package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// #9811. A commit-confirmed timeout promotes the STORE to the rollback target
// C1 and then applies it. When that apply failed, the failure was only logged —
// so under the #5679 contract the node kept ENFORCING the abandoned C2 while the
// store, `show configuration`, the peer resync and /health all reported C1, with
// nothing to retry it. This is a timer callback with no caller, unlike the
// commit path where the operator sees the error and re-commits.
//
// Each cell below names the specific way the fix could be wrong, because "the
// debt is owed" is true for a mechanism that latches and never converges, and
// "the debt is not owed" is true for one that never latches at all.

func newDebtDaemon9811(t *testing.T) (*Daemon, uint64) {
	t.Helper()
	s, gen := newRollbackTestStore(t) // active = B pending, rollback target = A
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}
	// PREMISE, asserted rather than assumed: nothing is owed before the
	// rollback runs, or every assertion below would be reading a pre-existing
	// state rather than this transaction's.
	if owed, failures, _ := d.ConfigApplyDebt(); owed || failures != 0 {
		t.Fatalf("fresh daemon already owes a config apply (owed=%v failures=%d); the cells below would be vacuous", owed, failures)
	}
	return d, gen
}

// TestConfirmedRollbackApplyFailureIsRetriedUntilItConverges9811 is the cell the
// issue asks for: the failure is retried, and it converges once the fault clears.
func TestConfirmedRollbackApplyFailureIsRetriedUntilItConverges9811(t *testing.T) {
	d, gen := newDebtDaemon9811(t)
	transient := errors.New("helper control socket: connection refused")
	d.applyErrForTest = transient
	// Count the applies, not just the debt. Asserting only that the debt clears
	// is satisfied by a retry owner that APPLIES NOTHING and reports success —
	// which discharges the debt and leaves the node diverged, the exact defect
	// wearing the fix's shape.
	applies := 0
	d.applyBodyForTest = func(_ *config.Config) { applies++ }

	d.executeConfirmedRollback(gen)
	if applies != 1 {
		t.Fatalf("the rollback itself applied %d times, want 1; the cells below would be reading the wrong transaction", applies)
	}

	owed, failures, lastErr := d.ConfigApplyDebt()
	if !owed {
		t.Fatal("a failed auto-rollback apply owes nothing; the node enforces the abandoned config with no retry owner and /health stays healthy (#9811)")
	}
	if failures != 1 {
		t.Errorf("failure count = %d after one failed apply, want 1", failures)
	}
	if !strings.Contains(lastErr, "connection refused") {
		t.Errorf("last error = %q, want the apply's own error", lastErr)
	}

	// The retry owner runs while the fault persists. The COUNT must climb: a
	// flat count with the debt still owed is exactly the signature of a debt
	// that is latched and not being retried, which is the pre-fix state wearing
	// a new field.
	d.reassertConfigApplyOnce(context.Background())
	if applies != 2 {
		t.Fatalf("the retry owner performed %d applies in total, want 2; a retry that does not actually re-apply converges nothing", applies)
	}
	if owed, failures, _ := d.ConfigApplyDebt(); !owed || failures != 2 {
		t.Fatalf("after one retry against a persisting fault: owed=%v failures=%d, want true/2 — a flat count with the debt owed means nothing is retrying it", owed, failures)
	}

	// Fault clears; the next tick must converge and discharge.
	d.applyErrForTest = nil
	d.reassertConfigApplyOnce(context.Background())
	if applies != 3 {
		t.Fatalf("the converging tick performed %d applies in total, want 3; the debt must be discharged by an APPLY, not by the absence of one", applies)
	}
	owed, _, lastErr = d.ConfigApplyDebt()
	if owed {
		t.Fatal("the debt is still owed after a successful re-apply; it never converges and /health would stay degraded forever")
	}
	if lastErr != "" {
		t.Errorf("last error = %q after convergence, want it cleared", lastErr)
	}
}

// TestSuccessfulConfirmedRollbackOwesNothing9811 is the control the issue asks
// for, and it is not optional: without it, a mechanism that latched the debt
// unconditionally would satisfy every assertion above.
func TestSuccessfulConfirmedRollbackOwesNothing9811(t *testing.T) {
	d, gen := newDebtDaemon9811(t)
	// applyErrForTest nil = clean apply.
	d.executeConfirmedRollback(gen)

	if owed, failures, _ := d.ConfigApplyDebt(); owed || failures != 0 {
		t.Fatalf("a SUCCESSFUL auto-rollback owes a config apply (owed=%v failures=%d); over-latching pins /health at 503 on a converged node", owed, failures)
	}
	if got := d.store.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("store did not roll back: host-name = %q, want A", got)
	}
}

// TestReassertDoesNothingWhenNothingIsOwed9811 is the narrowness control on the
// retry owner. It runs on every tick for the life of the daemon, so a version
// that re-applies unconditionally would re-publish the whole configuration every
// 30 seconds on a perfectly healthy node.
func TestReassertDoesNothingWhenNothingIsOwed9811(t *testing.T) {
	d, _ := newDebtDaemon9811(t)
	applies := 0
	d.applyBodyForTest = func(_ *config.Config) { applies++ }

	for i := 0; i < 3; i++ {
		d.reassertConfigApplyOnce(context.Background())
	}
	if applies != 0 {
		t.Fatalf("the retry owner applied %d times with nothing owed; it must cost one mutex read per tick on a healthy node", applies)
	}
}

// TestReassertAppliesTheACTIVEConfigNotTheFailedOne9811 pins the decision that
// makes this a convergence mechanism rather than a config regression.
//
// The retry re-reads the ACTIVE config instead of replaying the config whose
// apply failed. Replaying is the obvious implementation and it is wrong: an
// operator who commits a NEW configuration between the failure and the next tick
// would have that commit silently UNDONE by the retry owner. It is also what
// discharges the debt after an unrelated successful commit, which would
// otherwise leave a permanent false degraded on a converged node.
func TestReassertAppliesTheACTIVEConfigNotTheFailedOne9811(t *testing.T) {
	d, gen := newDebtDaemon9811(t)
	d.applyErrForTest = errors.New("transient")
	d.executeConfirmedRollback(gen) // store now on C1 (host-name A), debt owed

	// The operator commits a NEW configuration while the debt stands. The
	// harness leaves the store in configuration mode, so release it first —
	// otherwise this fails on the lock rather than on the behaviour under test.
	d.store.ExitConfigure()
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := d.store.SetFromInput("system host-name C"); err != nil {
		t.Fatalf("set host-name C: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("commit C: %v", err)
	}

	var applied string
	d.applyBodyForTest = func(cfg *config.Config) { applied = cfg.System.HostName }
	d.applyErrForTest = nil
	d.reassertConfigApplyOnce(context.Background())

	if applied != "C" {
		t.Fatalf("the retry owner applied host-name %q, want C — replaying the rollback target would UNDO the operator's newer commit", applied)
	}
	if owed, _, _ := d.ConfigApplyDebt(); owed {
		t.Fatal("the debt survived a successful apply of the active config; an unrelated commit must be able to discharge it or /health stays degraded forever")
	}
}
