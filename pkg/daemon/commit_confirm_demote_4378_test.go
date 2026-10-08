// #4378: commit-confirmed rollback timer must not fire on a node demoted from
// RG0 primary. The RG0 ownership transition (applyRG0OwnershipTransition, the
// StateSecondary/StateSecondaryHold branch) must confirm any in-flight
// `commit confirmed` window before going read-only, so the armed rollback
// timer does NOT revert the demoted (now standby) node to its pre-confirm
// tree while the new primary keeps the committed config — config divergence
// surfacing at the next failover.
//
// CONFIRM (keep the commit), not roll back, is correct: the committing node
// pushed the committed config to the peer via config-sync at commit-confirmed
// time, so the peer — now primary — already runs it; confirming keeps both
// nodes converged.
package daemon

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

// newDemoteTestStore builds a store with a CONFIRMED baseline "Base" and an
// armed (pending) `commit confirmed` promoting active to "Committed". The
// arm-time confirm generation is returned so a test can drive the real
// rollback-timer dispatch. Without a registered rollbackExecutor, the store's
// timer dispatch falls back to performAutoRollback (store-state only, no
// dataplane) — reverting active to "Base" — which is exactly the standby
// divergence #4378 must prevent.
func newDemoteTestStore(t *testing.T) (*configstore.Store, uint64) {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatalf("set host-name Base: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit Base: %v", err)
	}
	if err := s.SetFromInput("system host-name Committed"); err != nil {
		t.Fatalf("set host-name Committed: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("should have a pending confirm after CommitConfirmed")
	}
	return s, s.ConfirmGenForTesting()
}

// RG0 demotion during a commit-confirmed window confirms the window: the timer
// is cleared, the store goes read-only, and a subsequent arm-time timer fire
// is a no-op — the committed config survives on the demoted standby.
//
// RED-on-revert: drop the ConfirmPendingOnDemotion call from the StateSecondary
// branch and the window stays armed, so InvokeRollbackTimerForTesting reverts
// active to "Base" — the standby diverges from the primary that keeps
// "Committed".
func TestRG0DemotionConfirmsPendingCommitConfirmed_4378(t *testing.T) {
	s, armGen := newDemoteTestStore(t)
	d := &Daemon{store: s}

	// Node is demoted from RG0 primary (StateSecondary) mid-window.
	d.applyRG0OwnershipTransition(cluster.StateSecondary, true)

	if s.IsConfirmPending() {
		t.Error("RG0 demotion must clear the pending commit-confirmed timer")
	}
	if !s.ClusterReadOnly() {
		t.Error("RG0 demotion must leave the store cluster-read-only")
	}
	if got := s.ActiveConfig().System.HostName; got != "Committed" {
		t.Fatalf("active host-name after demotion = %q, want Committed", got)
	}

	// The armed timer fires with its arm-time generation. The confirmGen bump
	// from the demotion confirm must make it a no-op.
	s.InvokeRollbackTimerForTesting(armGen)

	if got := s.ActiveConfig().System.HostName; got != "Committed" {
		t.Fatalf("commit-confirmed timer fired on the demoted standby and reverted config: "+
			"active host-name = %q, want Committed (standby rolled back while the primary "+
			"keeps the commit — #4378 config divergence)", got)
	}
}

// StateSecondaryHold is the sync-hold flavor of demotion and must confirm the
// pending window identically.
func TestRG0DemotionSecondaryHoldConfirms_4378(t *testing.T) {
	s, armGen := newDemoteTestStore(t)
	d := &Daemon{store: s}

	d.applyRG0OwnershipTransition(cluster.StateSecondaryHold, true)
	if s.IsConfirmPending() {
		t.Error("RG0 demotion (SecondaryHold) must clear the pending commit-confirmed timer")
	}
	s.InvokeRollbackTimerForTesting(armGen)
	if got := s.ActiveConfig().System.HostName; got != "Committed" {
		t.Fatalf("SecondaryHold demotion did not confirm: active host-name = %q, want Committed", got)
	}
}

// Promotion to RG0 primary must NOT touch a pending commit-confirmed window
// (the promoting node is the one that OWNS the in-flight window); it only
// clears read-only. This guards against a future over-broad "confirm on any
// RG0 transition" regression.
func TestRG0PromotionLeavesPendingWindow_4378(t *testing.T) {
	s, _ := newDemoteTestStore(t)
	// Pretend the node was read-only (secondary) before promotion.
	s.SetClusterReadOnly(true)
	d := &Daemon{store: s}

	d.applyRG0OwnershipTransition(cluster.StatePrimary, false)
	if !s.IsConfirmPending() {
		t.Error("RG0 promotion must not clear a pending commit-confirmed window")
	}
	if s.ClusterReadOnly() {
		t.Error("RG0 promotion must clear cluster-read-only")
	}
}
