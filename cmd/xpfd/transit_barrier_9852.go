// Boot transit barrier (`xpfd transit-barrier close`, #9852).
//
// On every boot, systemd-networkd recreates the xpf bridge domains from the
// persisted 10-xpf-*.netdev files BEFORE xpfd starts, and bridged frames do
// not consult ip_forward. The #7191 barrier (inet + bridge xpf_transit_barrier)
// is an nftables table, so it does not survive a reboot: until xpfd's bring-up
// installs it, a bridge domain forwards between its ports with no policy.
//
// The boot unit xpf-transit-closed.service (scripts/image/, test/incus/,
// and the .deb; ordered Before=systemd-networkd.service and enabled with
// RequiredBy=systemd-networkd.service) runs this
// subcommand so the barrier is up before networkd can forward. xpfd's bring-up
// then re-installs the IDENTICAL objects idempotently (InstallTransitBarrier
// replaces an existing table per family) and takes ownership with no handoff;
// RemoveTransitBarrier deletes them when the #9725 gate legitimately opens.
//
// EARLY-BOOT SAFETY. main() dispatches here before parsing any daemon flag,
// loading any config, or taking any lock (classifyCommand is a pure argv map).
// The handler constructs a fresh netlink installer (socket-free constructor;
// one connection per family is opened for each transaction) and performs
// exactly one kernel transaction per family. It reads no config, writes no
// sysctl, and touches no filesystem path: the ONLY kernel mutation is the
// barrier itself.
//
// KNOB OWNERSHIP. This subcommand never writes the transit-forwarding sysctls.
// Those belong to the #9725 gate (daemon bring-up owns them from
// closeTransitUntilAttached on). The inet leg of the barrier still closes
// routed kernel transit as defence-in-depth (a forward-hook DROP holds
// regardless of ip_forward), but the sysctl values remain the gate's to drive.
//
// FAILURE DIRECTION. Usage errors, inet failures, real bridge failures, and
// mixed-family errors exit 1 with the kernel error on stderr. A sole bridge
// family-unsupported result (ENOENT, EOPNOTSUPP, or EAFNOSUPPORT) is the
// documented degraded-success exception: the inet barrier remains active and
// the command exits 0 with a warning naming the missing L2 coverage. The unit
// file carries NO `-` prefix, so every fatal error leaves networkd stopped
// rather than allowing a bridged-forwarding window. The normal success path
// does not affect management or loopback: this command writes no sysctls and
// its nftables table has only a forward hook.
package main

import (
	"fmt"
	"io"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// transitBarrierInstall performs the single kernel mutation of
// `xpfd transit-barrier close`. It is a package var (the runNetworkctl /
// vlanLinkAddSeam pattern) so tests inject install failures without a kernel.
var transitBarrierInstall = func() error {
	return xnft.NewNetlinkInstaller().InstallTransitBarrier()
}

// parseTransitBarrierArgs validates the operands of `xpfd transit-barrier`.
// The verb takes exactly one operand, `close`, and no flags; like #5322's
// `xpfd cleanup` guard, anything else is a hard usage error rather than a
// silently reinterpreted barrier operation. Extracted so the rejection is
// unit-testable without the os.Exit side effect of the dispatch.
func parseTransitBarrierArgs(args []string) error {
	if len(args) != 1 || args[0] != "close" {
		return fmt.Errorf("usage: xpfd transit-barrier close")
	}
	return nil
}

// runTransitBarrierSubcommand executes `xpfd transit-barrier close` and
// returns the process exit code: 0 when the inet barrier is installed, 1 on
// usage, inet, or real bridge-family failure. A kernel without bridge
// nf_tables support is a documented degraded-success case: the inet barrier
// remains active and the warning makes the missing L2 coverage explicit.
// The install is idempotent, so a re-run converges. Diagnostics go to stderr;
// success lines go to stdout (captured to the journal by the boot unit).
// Writers are parameters so tests capture both without redirecting
// os.Stdout/os.Stderr.
func runTransitBarrierSubcommand(args []string, stdout, stderr io.Writer) int {
	if err := parseTransitBarrierArgs(args); err != nil {
		fmt.Fprintf(stderr, "transit-barrier: %v\n", err)
		return 1
	}
	if err := transitBarrierInstall(); err != nil {
		if xnft.IsTransitBarrierBridgeUnsupportedOnly(err) {
			fmt.Fprintf(stderr, "transit-barrier: bridge family unavailable; "+
				"inet barrier installed (degraded bridge coverage): %v\n", err)
			fmt.Fprintln(stdout, "transit barrier installed (inet forward DROP; bridge family unavailable)")
			return 0
		}
		fmt.Fprintf(stderr, "transit-barrier: install transit barrier: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "transit barrier installed (inet + bridge forward DROP)")
	return 0
}
