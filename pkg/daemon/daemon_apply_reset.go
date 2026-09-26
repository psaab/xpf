package daemon

import (
	"context"
	"errors"
)

// errDaemonResetting is returned by every config-write entry point once a
// factory reset (zeroize) has entered its terminal reset generation (#5281). It
// is not surfaced to an operator on the normal path — resetting is only ever
// set true by factoryReset while the daemon is being wiped and stopped — so its
// job is purely to make a racing commit / HA-sync / rollback / reconcile abort
// instead of re-creating the just-erased state.
var errDaemonResetting = errors.New("factory reset in progress: configuration writes are rejected")

// isResetting reports whether a factory reset has entered the terminal reset
// generation (#5281). Config writers check it under applySem to short-circuit.
func (d *Daemon) isResetting() bool { return d.resetting.Load() }

// enterResetGeneration marks the daemon as being factory-reset. Called by
// factoryReset while it holds applySem, BEFORE the wipe, so any writer that
// later acquires applySem re-renders nothing (#5281). It is left set for the
// daemon's remaining lifetime on a successful wipe (the daemon is stopped
// moments later) and cleared again only if the wipe FAILED (exitResetGeneration).
func (d *Daemon) enterResetGeneration() { d.resetting.Store(true) }

// exitResetGeneration leaves the reset generation. Called only on a FAILED wipe
// so the box stays recoverable and normal config work resumes (#5281).
func (d *Daemon) exitResetGeneration() { d.resetting.Store(false) }

// factoryReset runs a gRPC-initiated zeroize under the SAME global writer gate
// (d.applySem) that commit / apply / HA-sync serialize on, then enters the
// terminal reset generation so no concurrent or subsequent config writer can
// re-persist the erased .configdb SSOT or re-render the wiped secrets before the
// daemon is stopped (#5281). It is wired into the gRPC server as Config.ZeroizeFn
// and receives the pkg/grpcapi factory-reset primitive as wipe (kept there so
// the wipe stays testable via the performZeroizeWipe seam).
//
// Sequence (fail-CLOSED, wipe-then-stop):
//  1. Acquire applySem — this DRAINS any in-flight apply and BLOCKS a concurrent
//     one for the duration of the wipe. If ctx is cancelled before acquisition
//     (client disconnect), nothing has been erased yet, so aborting is safe.
//  2. Enter the terminal reset generation BEFORE the wipe, so a writer that
//     acquires applySem AFTER this returns (a periodic reconciler, a late
//     commit, a shutdown-time apply) short-circuits on errDaemonResetting.
//     2a. Quiesce config archival (#5869) and rescue.conf saves (#10769):
//     the reset generation gates daemon writers but not configstore-owned
//     writers that bypass applySem. Fence + JOIN them before the wipe so
//     neither the archive directory nor rescue.conf can be recreated after
//     it is erased.
//  3. Run the wipe while holding applySem.
//     - On FAILURE: exit the reset generation and release applySem (deferred)
//     so the half-reset box is recoverable and a retry can run, and return
//     the error. The caller must NOT stop the daemon — a stop here would
//     strand a box whose secrets are still on disk.
//     - On SUCCESS: stay in the reset generation (never cleared) and return nil;
//     the caller stops xpfd. applySem is released on return, but the resetting
//     flag keeps every later writer from re-rendering during the stop window.
func (d *Daemon) factoryReset(ctx context.Context, wipe func() error) error {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer d.applySem.Release(1)
	d.enterResetGeneration()
	// #5869: fence + drain the async config-archive writers BEFORE the wipe
	// erases /var/lib/xpf/archive. Auto-archive launches a fire-and-forget
	// configstore goroutine per commit that the #5281 reset generation does NOT
	// cover: a commit's writer that resumes after FactoryResetArchiveDir removed
	// the archive dir would MkdirAll it again and drop a config-<ts>.<seq>.conf
	// snapshot of the PRIOR tenant's full config text (cleartext IKE PSKs,
	// WireGuard keys, SNMP communities) — zeroize secret residue on a
	// re-tenanted device. QuiesceArchival sets the archive fence (new /
	// not-yet-written writers no-op) and JOINS any in-flight writer, so once it
	// returns no writer can recreate the archive the wipe is about to erase.
	// (Nil-store guard: unit tests drive factoryReset on a bare Daemon.)
	if d.store != nil {
		// #10769 d05-F8: rescueAction's SaveRescueConfig bypasses applySem,
		// so the daemon generation cannot fence it. Fence and join that
		// store-owned writer before the wipe erases rescue.conf.
		d.store.QuiesceRescueWrites()
		d.store.QuiesceArchival()
	}
	if err := wipe(); err != nil {
		// Fail-closed recoverable path: the daemon stays up and resumes normal
		// config work, so re-enable archival and rescue saves too (a SUCCESSFUL
		// wipe instead stops the daemon, leaving both fences latched). #5869,
		// #10769.
		if d.store != nil {
			d.store.ResumeArchival()
			d.store.ResumeRescueWrites()
		}
		d.exitResetGeneration()
		return err
	}
	return nil
}
