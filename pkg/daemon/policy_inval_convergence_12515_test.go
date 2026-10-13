package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func newLostAckRollbackRun12515(t *testing.T) (*convergenceRun12072, *config.Config) {
	t.Helper()
	r, _ := newConvergenceRun12072(t, []string{"p-first", "web"})
	c1, err := r.h.d.store.SyncApply(policySetConfigText12072(
		"rollback-c1-12515", []string{"p-first", "web"}), nil)
	if err != nil {
		t.Fatalf("promote C1: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c1, c1
	ids := dpuserspace.PolicyIDsByStableKey(c1)
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		row.PolicyID = ids[r.dp.ruleBySession[row.ExpectedRTFlowSessionID]]
	}
	r.h.d.store.MarkActiveApplied()
	return r, c1
}

// FAIL-ON-REVERT: removing the empty-diff authority check lets the timer apply
// C1 while the lost C2 outcome is still unknown, falsely stamp C1 applied, and
// leave session 1099 alive.
func TestPolicyInvalidationRollbackAfterLostAckRevokesC2OnlySession12515(t *testing.T) {
	r, c1 := newLostAckRollbackRun12515(t)
	r.dp.lostAckNext = true
	c2, gen, applyErr := publishConfirmedRollbackTarget12072(
		t, r, c1, "rollback-c2-12515", []string{"p-first", "web", "x"})
	if applyErr == nil {
		t.Fatal("lost C2 apply ACK was not surfaced")
	}
	if !r.dp.unknown || r.dp.helperCfg != c2 || r.dp.applied != c1 {
		t.Fatalf("lost-ACK authority state: unknown=%v helper=%p applied=%p, want unknown C2 over acknowledged C1 %p",
			r.dp.unknown, r.dp.helperCfg, r.dp.applied, c1)
	}

	// Session 1099 is admitted by x after the helper applied C2 but before
	// the confirm timer fires, so it was not in C2's prepublish capture.
	r.dp.rows = append(r.dp.rows, dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.109", DstIP: "10.0.0.2",
			SrcPort: 1099, DstPort: 80,
		},
		PolicyID:                dpuserspace.PolicyIDsByStableKey(c2)["trust->untrust/x"],
		ExpectedRTFlowSessionID: 1099,
	})
	r.dp.ruleBySession[1099] = "trust->untrust/x"
	if !r.hasLiveSession(1099) {
		t.Fatal("fixture failed to admit session 1099 under C2")
	}

	readsBeforeRollback := r.dp.reads
	attemptsBeforeRollback := r.dp.applyAttempts
	r.h.d.executeConfirmedRollback(gen)
	if r.h.d.store.ActiveConfig() != c1 {
		t.Fatalf("rollback active config=%p, want C1 %p", r.h.d.store.ActiveConfig(), c1)
	}
	if r.h.d.store.ActiveApplied() {
		t.Fatal("rollback falsely marked C1 applied while helper authority was unknown")
	}
	if r.dp.reads != readsBeforeRollback {
		t.Fatalf("empty-diff authority check issued %d helper reads, want 0",
			r.dp.reads-readsBeforeRollback)
	}
	if r.dp.applyAttempts != attemptsBeforeRollback {
		t.Fatalf("rollback published under unknown authority: ApplyConfig attempts +%d, want 0",
			r.dp.applyAttempts-attemptsBeforeRollback)
	}
	if !r.dp.unknown || !r.hasLiveSession(1099) || r.hasDeletedSession(1099) {
		t.Fatalf("unknown-authority rollback changed helper/session state: unknown=%v live1099=%v deleted1099=%v",
			r.dp.unknown, r.hasLiveSession(1099), r.hasDeletedSession(1099))
	}
	if debt := r.h.d.policyInvalidationDebt; debt == nil || debt.authorityRefusal == nil {
		t.Fatalf("rollback did not retain the authority refusal: debt=%+v", debt)
	}

	// Reconcile the lost C2 ACK as the userspace status retry would. The
	// rollback's retained plan must then re-anchor to C2, READ the session, and
	// revoke it before C1 can be stamped applied.
	if _, err := r.dp.ApplyConfig(context.Background(), c2); err != nil {
		t.Fatalf("reconcile helper authority to C2: %v", err)
	}
	if r.dp.unknown || r.dp.PolicyReadConfig() != c2 {
		t.Fatalf("helper authority did not reconcile: unknown=%v config=%p want C2 %p",
			r.dp.unknown, r.dp.PolicyReadConfig(), c2)
	}
	if r.h.d.store.ActiveApplied() {
		t.Fatal("C1 was marked applied before the reconciled rollback invalidation ran")
	}

	if err := r.h.d.applyActiveConfigResult(); err != nil {
		t.Fatalf("retry C1 apply after authority reconciliation: %v", err)
	}
	r.h.d.noteConfigApplyResult(nil)
	if r.dp.applied != c1 || r.dp.unknown {
		t.Fatalf("reconciled rollback authority: helper=%p unknown=%v, want C1 %p and known",
			r.dp.applied, r.dp.unknown, c1)
	}
	if r.hasLiveSession(1099) || !r.hasDeletedSession(1099) {
		t.Fatalf("C2-only session was not revoked: live1099=%v deleted1099=%v",
			r.hasLiveSession(1099), r.hasDeletedSession(1099))
	}
	if !r.hasLiveSession(1) || r.hasDeletedSession(1) {
		t.Fatalf("rollback over-deleted C1's surviving web session: live=%v deleted=%v",
			r.hasLiveSession(1), r.hasDeletedSession(1))
	}
	if r.h.d.policyInvalidationDebt != nil || r.h.d.policyInvalidationPlan != nil ||
		!r.h.d.store.ActiveApplied() {
		t.Fatalf("reconciled rollback did not converge: debt=%+v plan=%+v ActiveApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.policyInvalidationPlan,
			r.h.d.store.ActiveApplied())
	}
}
