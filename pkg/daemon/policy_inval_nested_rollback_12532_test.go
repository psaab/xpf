package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #12532 P3: nested commit-confirmed C0->C1->C2, timer rollback to the
// original confirmed C0. C1 removes a (s1 debt), C2 removes b (s2 debt).
// C0 permits both, so neither session may be deleted by the rollback.
func TestPolicyInvalidationNestedConfirmedRollbackToRootDischargesPermitted12532(t *testing.T) {
	r, c0 := newLandedRollbackRun12072(t)

	r.dp.deleteErrOnce = true
	c1, _, applyErr := publishConfirmedRollbackTarget12072(
		t, r, c0, "nested12532-c1", []string{"p-first", "b", "web"})
	if applyErr == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	r.dp.deleteErrOnce = true
	_, gen, applyErr := publishConfirmedRollbackTarget12072(
		t, r, c1, "nested12532-c2", []string{"p-first", "web"})
	if applyErr == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.capture == nil ||
		debt.capture.candidateCount() == 0 {
		t.Fatalf("premise: nested debt missing: %+v", debt)
	}
	for _, id := range []uint64{1, 2, 3} {
		if !r.hasLiveSession(id) {
			t.Fatalf("premise: session %d not live before rollback", id)
		}
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION: rollback to C0 deleted permitted session %d: deleted=%v live=%v",
				id, r.hasDeletedSession(id), r.hasLiveSession(id))
		}
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("rollback to C0 did not discharge permitted debt: debt=%+v ActiveApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
}

// A candidate whose rule remains explicitly denied by the root policy must
// not be discharged while candidates from the same nested chain are filtered.
func TestPolicyInvalidationNestedRollbackKeepsRootDeniedCandidate12532(t *testing.T) {
	policies := []string{"p-first", "a", "b", "x", "web"}
	r, _ := newConvergenceRun12072(t, policies)
	c0, err := r.h.d.store.SyncApply(policySetConfigText12072("root-denies-x", policies), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	c0.Security.Policies[0].Policies[3].Action = config.PolicyDeny
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
	c1, _, err := publishConfirmedRollbackTarget12072(
		t, r, c0, "root-denies-x-c1", []string{"p-first", "b", "x", "web"})
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	xID := dpuserspace.PolicyIDsByStableKey(c1)["trust->untrust/x"]
	r.dp.rows = append(r.dp.rows, dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 1099, DstPort: 80,
		},
		PolicyID: xID, ExpectedRTFlowSessionID: 99,
		IngressZoneID: config.StableZoneID("trust"),
		EgressZoneID:  config.StableZoneID("untrust"),
	})
	r.dp.ruleBySession[99] = "trust->untrust/x"
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackTarget12072(
		t, r, c1, "root-denies-x-c2", []string{"p-first", "web"})
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	if !r.hasDeletedSession(99) || r.hasLiveSession(99) {
		t.Fatalf("UNDER-DELETION: root-denied x candidate survived nested rollback: deleted=%v live=%v",
			r.hasDeletedSession(99), r.hasLiveSession(99))
	}
	for _, id := range []uint64{1, 2, 4} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION: root-permitted session %d did not survive", id)
		}
	}
}

// #12532 depth-3: C0->C1->C2->C3 each forbidding one more rule, timer
// rollback to C0 must discharge every candidate C0 permits.
func TestPolicyInvalidationTripleNestedRollbackToRoot12532(t *testing.T) {
	r, c0 := newLandedRollbackRun12072(t)

	r.dp.deleteErrOnce = true
	c1, _, err1 := publishConfirmedRollbackTarget12072(
		t, r, c0, "nested12532c-c1", []string{"p-first", "b", "web"})
	r.dp.deleteErrOnce = true
	c2, _, err2 := publishConfirmedRollbackTarget12072(
		t, r, c1, "nested12532c-c2", []string{"p-first", "web"})
	r.dp.deleteErrOnce = true
	_, gen, err3 := publishConfirmedRollbackTarget12072(
		t, r, c2, "nested12532c-c3", []string{"p-first"})
	if err1 == nil || err2 == nil || err3 == nil {
		t.Fatalf("premise: failed deletes not surfaced: %v %v %v", err1, err2, err3)
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION at depth 3: session %d deleted by rollback to C0", id)
		}
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("depth-3 rollback did not converge: debt=%+v ActiveApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
}
