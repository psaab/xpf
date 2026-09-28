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
	if !force && daemon.EarlyInputHandoffMarked() {
		// #10751 R4-4: `ensure` is the unit's ExecStart. Post-handoff the
		// daemon owns enforcement (a restart converges it on first
		// apply), so starting the unit must SUCCEED without installing —
		// failing here would strand xpfd behind its own Requires edge.
		if args[0] == "ensure" {
			fmt.Fprintln(stdout, "early input barrier already handed off to the daemon; nothing to do")
			return 0
		}
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
