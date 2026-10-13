package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #12780: one-level exact-undo rollback. C0 denies session 1's rule; C1
// removes it, and the failed candidate delete leaves session 1 owed. Rollback
// to C0 retains the denied tuple, but reject that publish, then supersede it
// with the same forbidding C1 policy. The candidate must remain owed even
// though the new target has no diff to rediscover it.
func TestPolicyInvalidationExactUndoRejectedPublishReowesCandidate12780(t *testing.T) {
	r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	// Session 1 is retained with its original rule provenance even though C0
	// denies it; exact undo must preserve that failed-delete obligation.
	c0, err := r.h.d.store.SyncApply(rulesConfigText12532("exact12780-c0", "",
		[]rule12532{
			{name: "p-first", app: "any"},
			{name: "a", app: "any", deny: true},
			{name: "b", app: "any"},
			{name: "web", app: "any"},
		}), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	ids := dpuserspace.PolicyIDsByStableKey(c0)
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		row.PolicyID = ids[r.dp.ruleBySession[row.ExpectedRTFlowSessionID]]
		row.IngressZoneID = config.StableZoneID("trust")
		row.EgressZoneID = config.StableZoneID("untrust")
	}
	r.h.d.store.MarkActiveApplied()

	r.dp.deleteErrOnce = true
	c1, gen, err := publishConfirmedRollbackText12072(t, r, c0,
		rulesConfigText12532("exact12780-c1", "", []rule12532{
			{name: "p-first", app: "any"}, {name: "b", app: "any"}, {name: "web", app: "any"},
		}))
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	if r.dp.applied != c1 || !heldCandidates12532(r.h.d.policyInvalidationDebt)[1] {
		t.Fatalf("premise: C1 did not land with session 1 owed: helper=%p C1=%p debt=%v",
			r.dp.applied, c1, heldCandidates12532(r.h.d.policyInvalidationDebt))
	}

	// Reject exact undo C0. Its target denies the retained tuple, so it must
	// remain owed even though the rollback itself never publishes.
	r.dp.script = make([]invalDebtOutcome12073, r.dp.applyCalls+1)
	r.dp.script[r.dp.applyCalls] = invalDebtOutcome12073{
		err: errors.New("rollback apply_snapshot rejected by helper (definite)"),
	}
	r.h.d.executeConfirmedRollback(gen)
	if r.dp.applied != c1 || r.h.d.store.ActiveConfig() != c0 {
		t.Fatalf("premise: rejected rollback moved authority: helper=%p (want C1 %p) store=%p (want C0 %p)",
			r.dp.applied, c1, r.h.d.store.ActiveConfig(), c0)
	}
	if r.hasDeletedSession(1) || !r.hasLiveSession(1) {
		t.Fatal("premise: rejected rollback deleted session 1")
	}

	// Fail the carried delete once so the debt ledger proves C2 re-owed the
	// candidate rather than deleting it via an unrelated fresh scan.
	r.dp.deleteErrOnce = true
	c2, err := publishLandedRollbackConfig12072(t, r, c0, "exact12780-c2",
		[]string{"p-first", "b", "web"})
	if r.dp.applied != c2 {
		t.Fatalf("premise: C2 did not land: %v", err)
	}
	if err == nil {
		t.Fatal("premise: C2's carried candidate delete did not fail")
	}
	if !heldCandidates12532(r.h.d.policyInvalidationDebt)[1] {
		t.Errorf("UNDER-RE-OWE #12780: denied candidate 1 vanished when rejected exact undo was superseded; debt=%v",
			heldCandidates12532(r.h.d.policyInvalidationDebt))
	}
	if r.hasDeletedSession(2) || !r.hasLiveSession(2) || r.hasDeletedSession(3) || !r.hasLiveSession(3) {
		t.Error("superseding target over-deleted a session still permitted by C1")
	}
}

// Positive control: accepted exact-undo still consumes candidate (existing
// TestPolicyInvalidationLandedDeleteDebtRollbackToPredecessor12323 covers it;
// this cell additionally checks the ledger so a re-owe-everywhere mutant fails).
func TestPolicyInvalidationExactUndoLandedRollbackDischarges12780(t *testing.T) {
	r, c0 := newLandedRollbackRun12072(t)
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackTarget12072(
		t, r, c0, "exactok12780-c1", []string{"p-first", "b", "web"})
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	r.h.d.executeConfirmedRollback(gen)
	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback did not land C0: store=%p helper=%p", r.h.d.store.ActiveConfig(), r.dp.applied)
	}
	if r.hasDeletedSession(1) || !r.hasLiveSession(1) {
		t.Fatal("OVER-DELETION: accepted rollback deleted session 1 which C0 permits")
	}
	if r.h.d.policyInvalidationDebt != nil {
		t.Fatalf("accepted rollback left debt: %+v", r.h.d.policyInvalidationDebt)
	}
}
