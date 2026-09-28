// #10751 early host-input barrier command, separate from the forward-only
// `transit-barrier` path. systemd-networkd requires the input barrier before
// addresses are brought up; the daemon's first host-inbound apply removes it.
package main

import (
	"fmt"
	"io"

	"github.com/psaab/xpf/pkg/daemon"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

var earlyInputBarrierInstall = func() error {
	return xnft.NewNetlinkInstaller().InstallEarlyInputBarrier()
}

var earlyInputBarrierRemove = func() error {
	return xnft.NewNetlinkInstaller().RemoveEarlyInputBarrier()
}

var earlyInputBarrierPresent = func() (bool, error) {
	return xnft.NewNetlinkInstaller().EarlyInputBarrierPresent()
}

var hostInboundTablePresent = func() (bool, error) {
	return xnft.NewNetlinkInstaller().TablePresent(xnft.HostInboundTableName)
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
// daemon, and never clobber a standing lifeline guard with the global form
// (#10751 R5-C).
//
//   - marker present (handed off this boot) → verified no-op success.
//   - marker absent but host-inbound enforcement live (marker write failed
//     or marker cleared) → no-op success: the daemon owns host input.
//   - marker absent, no enforcement, barrier already present (global or a
//     bootstrap lifeline guard) → no-op success: preserve, never clobber.
//   - marker absent, nothing present → install the global barrier,
//     fail-closed on error (pre-handoff boot path).
//
// A readback error falls through to the next probe (an unreadable readback
// cannot prove anything is live, so the fail-closed install still runs).
func runInputBarrierEnsure(stdout, stderr io.Writer) int {
	if daemon.EarlyInputHandoffMarked() {
		fmt.Fprintln(stdout, "early input barrier already handed off to the daemon; nothing to do")
		return 0
	}
	if present, err := hostInboundTablePresent(); err == nil && present {
		fmt.Fprintln(stdout, "host-inbound enforcement is live; nothing to do")
		return 0
	}
	if present, err := earlyInputBarrierPresent(); err == nil && present {
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
