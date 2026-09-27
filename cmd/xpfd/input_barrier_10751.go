// #10751 early host-input barrier command, separate from the forward-only
// `transit-barrier` path. systemd-networkd requires the input barrier before
// addresses are brought up; the daemon's first host-inbound apply removes it.
package main

import (
	"fmt"
	"io"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

var earlyInputBarrierInstall = func() error {
	return xnft.NewNetlinkInstaller().InstallEarlyInputBarrier()
}

var earlyInputBarrierRemove = func() error {
	return xnft.NewNetlinkInstaller().RemoveEarlyInputBarrier()
}

func parseInputBarrierArgs(args []string) error {
	if len(args) != 1 || (args[0] != "close" && args[0] != "remove") {
		return fmt.Errorf("usage: xpfd input-barrier {close|remove}")
	}
	return nil
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
	if err := earlyInputBarrierInstall(); err != nil {
		fmt.Fprintf(stderr, "input-barrier: install early input barrier: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "early input barrier installed (inet input DROP with loopback, L3, FRR and HA admits)")
	return 0
}
