package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

// #15054 (A32-01). The #9811 config-apply retry owner bypassed
// beginBackgroundApply on three legs:
//
//  1. Bootstrap: reassertConfigApplyOnce acquires applySem itself and calls
//     applyConfigLocked(context.Background(), cfg) directly, so a debt latched
//     before enterBootstrapMode (which did not discharge it) is retried in
//     bootstrap mode — including the #9615 refused target that enterBootstrapMode
//     deliberately did NOT apply — reaching maybeExitBootstrapOnFirstConfig and
//     taking over interfaces/dataplane with no commit.
//  2. Shutdown fence: after fenceBackgroundApplies (#6788) the retry still
//     applies with a non-cancellable context that shutdown must join.
//  3. Rollback: executeConfirmedRollback acquired applySem with
//     context.Background() and applied with context.Background(), so a
//     shutdown-fenced daemon still runs an uncancellable full apply.
//
// Acceptance per the issue: both defect cells report applies=0, and the #9615
// cell shows no apply. The control (no bootstrap, no fence) must still apply.
//
// FAIL-ON-REVERT: reverting reassertConfigApplyOnce to its raw
// applySem.Acquire + applyConfigLocked(context.Background()) shape, or
// enterBootstrapMode to not discharge, or executeConfirmedRollback to
// context.Background(), lets the corresponding cell apply (applies>0).

// TestReassertRefusedInBootstrap15054 is defect cell 1: debt owed, daemon in
// bootstrap mode (as enterBootstrapMode leaves it after a first-commit or
// #9615 refused-target rollback). The retry must not apply at all. It also
// pins that enterBootstrapMode DISCHARGES/refuses pre-existing debt: debt
// latched by a failed rollback apply must not survive entry into the
// bootstrap safe state, or the (gated) retry would be pinned degraded with
// no owner able to converge it until an authorized commit.
func TestReassertRefusedInBootstrap15054(t *testing.T) {
	d, gen := newDebtDaemon9811(t)
	d.applyErrForTest = errors.New("transient rollback apply")
	applies := 0
	d.applyBodyForTest = func(_ *config.Config) { applies++ }

	// Latch debt via a failed confirmed-rollback apply (store now on A).
	d.executeConfirmedRollback(gen)
	if applies != 1 {
		t.Fatalf("fixture: rollback applied %d times, want 1", applies)
	}
	if owed, _, _ := d.ConfigApplyDebt(); !owed {
		t.Fatal("fixture: failed rollback apply must latch config-apply debt")
	}

	// Enter the bootstrap safe state (teardown stubbed by applyBodyForTest).
	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("enterBootstrapMode: %v", err)
	}
	if !d.inBootstrap() {
		t.Fatal("fixture: daemon must be in bootstrap mode")
	}
	if owed, _, _ := d.ConfigApplyDebt(); owed {
		t.Fatal("enterBootstrapMode left config-apply debt owed; the retry owner " +
			"would re-apply the refused/bootstrap target with no commit (#15054)")
	}

	// Even if debt were (re-)latched while in bootstrap, the retry must refuse.
	d.noteConfigApplyResult(errors.New("latched in bootstrap"))
	d.reassertConfigApplyOnce(context.Background())
	if applies != 1 {
		t.Fatalf("retry owner applied %d times total (want 1, the original rollback); "+
			"a bootstrap retry reaches maybeExitBootstrapOnFirstConfig and takes over "+
			"with no commit, including the #9615 refused target (#15054)", applies)
	}
	if !d.inBootstrap() {
		t.Fatal("bootstrap retry exited bootstrap mode without an authorized commit/sync/rollback")
	}
}

// TestReassertRefusedAfterShutdownFence15054 is defect cell 2: debt owed,
// shutdown fence latched (#6788). The retry must not apply, even though its
// loop context is still live (the loop is joined via wg, the fence is the
// gate beginBackgroundApply checks).
func TestReassertRefusedAfterShutdownFence15054(t *testing.T) {
	d, gen := newDebtDaemon9811(t)
	d.applyErrForTest = errors.New("transient rollback apply")
	applies := 0
	d.applyBodyForTest = func(_ *config.Config) { applies++ }

	d.executeConfirmedRollback(gen)
	if applies != 1 {
		t.Fatalf("fixture: rollback applied %d times, want 1", applies)
	}
	if owed, _, _ := d.ConfigApplyDebt(); !owed {
		t.Fatal("fixture: failed rollback apply must latch config-apply debt")
	}

	d.fenceBackgroundApplies()
	d.applyErrForTest = nil // fault clears; a post-fence apply would "succeed"
	d.reassertConfigApplyOnce(context.Background())
	if applies != 1 {
		t.Fatalf("retry owner applied %d times total (want 1); a post-fence retry runs "+
			"an uncancellable full apply that shutdown must join (#15054/#6788)", applies)
	}
}

// TestConfirmedRollbackRefusedAfterShutdownFence15054 pins the rollback leg:
// executeConfirmedRollback on a shutdown-fenced daemon must not run its
// unconditional apply. Before #15054 it acquired applySem with
// context.Background() and applied with context.Background(), escaping the
// #6788 fence entirely.
func TestConfirmedRollbackRefusedAfterShutdownFence15054(t *testing.T) {
	d, gen := newDebtDaemon9811(t)
	applies := 0
	d.applyBodyForTest = func(_ *config.Config) { applies++ }

	d.fenceBackgroundApplies()
	d.executeConfirmedRollback(gen)
	if applies != 0 {
		t.Fatalf("executeConfirmedRollback applied %d times on a shutdown-fenced daemon, "+
			"want 0; it bypassed the #6788 fence with context.Background() (#15054)", applies)
	}
}

// TestReassertAppliesWhenLive15054 is the named control: debt owed, daemon
// neither in bootstrap nor fenced. The retry must still apply and converge —
// a gate that refuses unconditionally would leave every genuine #9811 debt
// permanently degraded.
func TestReassertAppliesWhenLive15054(t *testing.T) {
	d, gen := newDebtDaemon9811(t)
	d.applyErrForTest = errors.New("transient rollback apply")
	applies := 0
	d.applyBodyForTest = func(_ *config.Config) { applies++ }

	d.executeConfirmedRollback(gen)
	if applies != 1 {
		t.Fatalf("fixture: rollback applied %d times, want 1", applies)
	}
	d.applyErrForTest = nil
	d.reassertConfigApplyOnce(context.Background())
	if applies != 2 {
		t.Fatalf("live retry applied %d times total, want 2; the #15054 gate must be "+
			"scoped to bootstrap/fence, not applied always", applies)
	}
	if owed, _, _ := d.ConfigApplyDebt(); owed {
		t.Fatal("live retry did not discharge the debt on success")
	}
}

// TestReassertUsesApplyCancelCtx15054 pins the context half of the fix: the
// retry's apply must be driven by applyCancelCtx() (the daemon-stop context),
// not context.Background(). It drives the REAL apply body (no
// applyBodyForTest seam, which returns before the #2926 boundaries): with
// the daemon-stop context already cancelled, a live (non-bootstrap,
// non-fenced) retry must abort at a boundary before the dataplane sync
// push, and must leave the debt owed. Before #15054
// configApplyReassertFn bound context.Background(), so the push ran.
func TestReassertUsesApplyCancelCtx15054(t *testing.T) {
	d, dp, _ := minimalApplyCtxDaemon(t)
	d.applySem = semaphore.NewWeighted(1)
	if _, err := d.store.SyncApply("system { host-name cancel-ctx-15054; }", nil); err != nil {
		t.Fatalf("SyncApply active config: %v", err)
	}
	d.noteConfigApplyResult(errors.New("latched debt"))
	if owed, _, _ := d.ConfigApplyDebt(); !owed {
		t.Fatal("fixture: debt must be owed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // daemon stop already signalled
	d.applyCancelContext, d.applyCancel = ctx, cancel
	d.reassertConfigApplyOnce(context.Background())
	if dp.applyCalls != 0 {
		t.Fatalf("retry ran the dataplane sync push %d times with the daemon-stop "+
			"context cancelled; the retry must drive its apply through "+
			"applyCancelCtx() (#15054)", dp.applyCalls)
	}
	if owed, _, _ := d.ConfigApplyDebt(); !owed {
		t.Fatal("a daemon-stop-aborted retry discharged the debt without applying; " +
			"the divergence would be reported converged")
	}
}
