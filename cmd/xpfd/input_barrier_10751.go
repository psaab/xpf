// #10751 early host-input barrier command, separate from the forward-only
// `transit-barrier` path. systemd-networkd requires the input barrier before
// addresses are brought up; the daemon's first host-inbound apply removes it.
package main

import (
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/psaab/xpf/pkg/daemon"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

var earlyInputBarrierInstall = func() error {
	return xnft.NewNetlinkInstaller().InstallEarlyInputBarrier()
}

var earlyInputBarrierRemove = func() error {
	return xnft.NewNetlinkInstaller().RemoveEarlyInputBarrier()
}

var earlyInputBarrierEnforcing = func() (bool, error) {
	return xnft.NewNetlinkInstaller().TableEnforcing(xnft.EarlyInputBarrierTableName)
}

var hostInboundDropsInput = func() (bool, error) {
	return xnft.NewNetlinkInstaller().TableDropsInput(xnft.HostInboundTableName)
}

// hostInboundFirstApplied reports whether a LIVE daemon process holds the
// first-apply marker (installed host-inbound enforcement and still owns
// it). Combined with DROP presence plus xpfd active below, it proves a
// live table is CURRENT daemon ownership — not a stale restore from
// before xpfd started, and not a prior process's marker surviving a
// failed cleanup (unlocked = stale = install, #10751 M2).
var hostInboundFirstApplied = func() bool {
	return daemon.HostInboundFirstApplyLive()
}

// xpfdUnitActive reports whether the xpfd systemd unit is active. A package
// var so service-order tests script cold-boot (inactive) vs live (active)
// without a systemd manager. Any error (no systemd, unit unknown/inactive)
// reads inactive — the fail-closed direction for ensure.
var xpfdUnitActive = func() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "xpfd").Run() == nil
}

// ensureRereadPause18746 runs between ensure's re-reads (AG on #18759).
// ensure runs outside the daemon, so nothing serializes it with an apply, and
// immediate re-reads could all land inside one multi-table apply. A package
// var so tests can count the pauses without sleeping.
var ensureRereadPause18746 = func() { time.Sleep(50 * time.Millisecond) }

// ensureProbe18746 runs one ensure probe. It re-reads, after a pause, while the
// probe reports a moved nf_tables generation (#18746). When it had to re-read
// it says so on stdout, which the boot unit sends to the journal
// (SyslogIdentifier=xpf-input-closed).
func ensureProbe18746(stdout io.Writer, name string, probe func() (bool, error)) (bool, error) {
	reads := 0
	v, err := xnft.RereadOnGenerationChangeAfter(xnft.GenerationChangeRereads, ensureRereadPause18746, func() (bool, error) {
		reads++
		return probe()
	})
	if reads > 1 {
		fmt.Fprintf(stdout, "input-barrier: %s probe re-read %d time(s) after concurrent nft commits (final error: %v)\n", name, reads-1, err)
	}
	return v, err
}

func parseInputBarrierArgs(args []string) error {
	if len(args) == 1 && (args[0] == "close" || args[0] == "remove" || args[0] == "ensure") {
		return nil
	}
	if len(args) == 2 && args[0] == "close" && args[1] == "--force" {
		return nil
	}
	return fmt.Errorf("usage: xpfd input-barrier {close [--force]|remove|ensure}")
}

func runInputBarrierSubcommand(args []string, stdout, stderr io.Writer) int {
	if err := parseInputBarrierArgs(args); err != nil {
		fmt.Fprintf(stderr, "input-barrier: %v\n", err)
		return 1
	}
	if args[0] == "remove" {
		if err := earlyInputBarrierRemove(); err != nil {
			fmt.Fprintf(stderr, "input-barrier: remove early input barrier: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "early input barrier removed")
		return 0
	}
	force := len(args) == 2
	if args[0] == "ensure" {
		return runInputBarrierEnsure(stdout, stderr)
	}
	if !force && daemon.EarlyInputHandoffLive() {
		fmt.Fprintf(stderr, "input-barrier: host input already handed off to the daemon; refusing reinstall (use --force to override)\n")
		return 1
	}
	if err := earlyInputBarrierInstall(); err != nil {
		fmt.Fprintf(stderr, "input-barrier: install early input barrier: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "early input barrier installed (inet input DROP with loopback, L3, DHCP-client admits)")
	return 0
}

// runInputBarrierEnsure implements `input-barrier ensure`, the boot unit's
// ExecStart AND ExecReload: it must never install global DROP into a live
// daemon, never clobber a standing lifeline guard with the global form,
// and never trust a stale table as live enforcement (#10751 R6-B/R7-A).
//
//   - marker HELD by a live process (handed off and the owner lives) →
//     verified no-op success. A merely PRESENT but unlocked marker (a
//     prior process's file surviving failed cleanup, or a planted one)
//     is stale ownership and falls through to install.
//   - handoff marker not live but host-inbound DROPS on its input hook
//     (not a flushed shell or admits-only zero-drop table), first-applied
//     by a LIVE daemon, with xpfd ACTIVE → no-op success: the live
//     daemon owns host input (marker write failed or marker cleared).
//     A stale restore reads inactive (cold boot), unapplied
//     (pre-first-apply, Type=simple is active-at-fork), or unlocked
//     (dead owner) and installs instead of trusting it.
//   - marker absent with an ENFORCING barrier already present (global or
//     a bootstrap lifeline guard) → no-op success: preserve, never
//     clobber.
//   - otherwise (nothing live, nothing standing) → install the global
//     barrier, fail-closed on error (pre-handoff boot path).
//
// A readback error falls through to the next probe (an unreadable readback
// cannot prove anything is live, so the fail-closed install still runs).
func runInputBarrierEnsure(stdout, stderr io.Writer) int {
	if daemon.EarlyInputHandoffLive() {
		fmt.Fprintln(stdout, "early input barrier already handed off to the daemon; nothing to do")
		return 0
	}
	// #18746: both predicates are generation-bracketed, so an nft commit
	// landing during the read (the live daemon's own apply, say) makes it
	// unreadable, and an unreadable probe falls through to the install below.
	// That would put global DROP into a live daemon or clobber a lifeline
	// guard. Re-read, with a pause, on that error only (ensureProbe18746); a
	// probe that stays unreadable still falls through, fail-closed as
	// documented above.
	if drops, err := ensureProbe18746(stdout, "host-inbound", hostInboundDropsInput); err == nil && drops && hostInboundFirstApplied() && xpfdUnitActive() {
		fmt.Fprintln(stdout, "host-inbound enforcement is live; nothing to do (if stale, the daemon's next pre-apply converges the guard)")
		return 0
	}
	if enforcing, err := ensureProbe18746(stdout, "early-barrier", earlyInputBarrierEnforcing); err == nil && enforcing {
		fmt.Fprintln(stdout, "early input barrier already present; nothing to do")
		return 0
	}
	if err := earlyInputBarrierInstall(); err != nil {
		fmt.Fprintf(stderr, "input-barrier: install early input barrier: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "early input barrier installed (inet input DROP with loopback, L3, DHCP-client admits)")
	return 0
}
