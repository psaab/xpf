// `xpfd cleanup` (#16430): the one-shot teardown verb — closes kernel
// transit, unpins all dataplane state, deletes the fabric IPVLANs and
// clears the FRR managed section. It runs on uninstall / decommission,
// after the daemon has exited.
//
// LIVE-DAEMON INTERLOCK (#16430). Cleanup destroys state a running
// daemon believes it owns: beside a live daemon it withdrew FRR-managed
// routing (until the daemon's next commit), deleted the fabric overlay
// and unpinned dataplane state while the daemon kept reporting healthy.
// runCleanupSubcommand therefore ACQUIRES the #15085 daemon singleton
// (daemon.GuardDaemonLockForCleanup) before the first mutation and holds
// it for the whole teardown: a live daemon makes cleanup refuse with a
// non-zero exit naming `systemctl stop xpfd`, and a daemon cannot start
// mid-cleanup either. Acquiring — not merely probing
// daemonLockHeldByLiveProcess — closes the check-to-mutation TOCTOU.
package main

import (
	"fmt"
	"io"

	"github.com/psaab/xpf/pkg/daemon"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/frr"
)

// Cleanup steps as package vars so tests drive the guard and the step
// ordering without touching kernel transit, bpffs, netlink or FRR.
var (
	cleanupGuard = func() (func(), error) {
		lease, err := daemon.GuardDaemonLockForCleanup()
		if err != nil {
			return nil, err
		}
		return lease.Release, nil
	}
	cleanupCloseTransit = daemon.CloseKernelTransitForCleanup
	cleanupDataplane    = dataplane.Cleanup
	cleanupFabric       = daemon.CleanupFabricIPVLANs
	cleanupClearFRR     = func() error {
		fm := frr.New()
		fm.DisableDegradedRetry()
		err := fm.Clear()
		fm.Stop()
		return err
	}
)

// runCleanupSubcommand executes `xpfd cleanup` and returns a process
// exit code. Writers are parameters so tests capture diagnostics without
// redirecting os.Stdout/os.Stderr.
func runCleanupSubcommand(args []string, stdout, stderr io.Writer) int {
	// #5322: cleanup takes NO flags or positional arguments; like #4869's
	// `xpfd upgrade`, a stray operand (e.g. a typo'd path) is a hard usage
	// error, not silently ignored while cleanup still GCs all pinned
	// dataplane state and clears the FRR managed routes.
	if err := parseCleanupArgs(args); err != nil {
		fmt.Fprintf(stderr, "cleanup: %v\n", err)
		return 1
	}
	// #16430: refuse beside a live daemon BEFORE any transit/pin/fabric/
	// FRR mutation, and hold the singleton for the whole teardown so a
	// daemon cannot start into the state cleanup is destroying.
	release, err := cleanupGuard()
	if err != nil {
		fmt.Fprintf(stderr, "cleanup: %v\n", err)
		return 1
	}
	defer release()
	// #9725: cleanup destroys pinned XDP links and runs without the daemon's
	// periodic kernel-truth tick. Close and VERIFY transit BEFORE that
	// destructive operation; on uncertainty leave the pins for the daemon's
	// next start rather than knowingly opening a window.
	if err := cleanupCloseTransit(); err != nil {
		fmt.Fprintf(stderr, "cleanup transit: %v\n", err)
		return 1
	}
	if err := cleanupDataplane(); err != nil {
		fmt.Fprintf(stderr, "cleanup BPF: %v\n", err)
		return 1
	}
	// Remove fabric IPVLAN interfaces created by the daemon.
	cleanupFabric()
	// Also clear FRR managed routes so the kernel routing table is
	// clean. One-shot contract (#1880): no degraded-retry loop in
	// this short-lived process; a degraded/failed reload is logged
	// LOUDLY but keeps exit status 0 — deploy tooling wraps cleanup
	// in `|| true`, and the deploy flow itself bounds convergence
	// (the new daemon's first ApplyFull full-diffs any residue).
	// Critically, Clear() never runs `systemctl reload frr`: the
	// FRR 10.6 ExecReload bounces watchfrr (the unit MainPID) and
	// parks frr.service in a 2-minute stop-sigterm that queued
	// post-deploy reboots behind it (the #1880 failover-harness
	// budget misses) and ended in systemd SIGKILLing FRR.
	clearErr := cleanupClearFRR()
	// #10907: do not claim FRR managed routes were removed if Clear
	// failed. Keep the #1880 one-shot exit behavior; the next daemon
	// start reconciles any FRR residue.
	reportCleanupFRRResult(stdout, stderr, clearErr)
	return 0
}
