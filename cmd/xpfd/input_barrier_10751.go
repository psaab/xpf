// #10751 early host-input barrier command, separate from the forward-only
// `transit-barrier` path. systemd-networkd requires the input barrier before
// addresses are brought up; the daemon's first host-inbound apply removes it.
package main

import (
	"fmt"
	"io"
	"os/exec"

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

// hostInboundFirstApplied reports whether this boot's daemon installed
// host-inbound enforcement at least once. Combined with DROP presence
// plus xpfd active below, it proves a live table is CURRENT daemon
// ownership — not a stale restore from before xpfd started.
var hostInboundFirstApplied = func() bool {
	return daemon.HostInboundFirstApplyMarked()
}

// xpfdUnitActive reports whether the xpfd systemd unit is active. A package
// var so service-order tests script cold-boot (inactive) vs live (active)
// without a systemd manager. Any error (no systemd, unit unknown/inactive)
// reads inactive — the fail-closed direction for ensure.
var xpfdUnitActive = func() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "xpfd").Run() == nil
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
	if !force && daemon.EarlyInputHandoffMarked() {
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
//   - marker present (handed off this boot) → verified no-op success.
//   - marker absent but host-inbound DROPS on its input hook (not a
//     flushed shell or admits-only zero-drop table), first-applied by
//     this boot's daemon, with xpfd ACTIVE → no-op success: the live
//     daemon owns host input (marker write failed or marker cleared).
//     A stale restore reads inactive (cold boot) or unapplied
//     (pre-first-apply, Type=simple is active-at-fork) and installs
//     instead of trusting it.
//   - marker absent with an ENFORCING barrier already present (global or
//     a bootstrap lifeline guard) → no-op success: preserve, never
//     clobber.
//   - otherwise (nothing live, nothing standing) → install the global
//     barrier, fail-closed on error (pre-handoff boot path).
//
// A readback error falls through to the next probe (an unreadable readback
// cannot prove anything is live, so the fail-closed install still runs).
func runInputBarrierEnsure(stdout, stderr io.Writer) int {
	if daemon.EarlyInputHandoffMarked() {
		fmt.Fprintln(stdout, "early input barrier already handed off to the daemon; nothing to do")
		return 0
	}
	if drops, err := hostInboundDropsInput(); err == nil && drops && hostInboundFirstApplied() && xpfdUnitActive() {
		fmt.Fprintln(stdout, "host-inbound enforcement is live; nothing to do")
		return 0
	}
	if enforcing, err := earlyInputBarrierEnforcing(); err == nil && enforcing {
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
