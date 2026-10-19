package eventengine

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Regression tests for #15022 (A14-03): a no-within policy on
// ping_test_completed whose change-configuration restores values that are
// already active (the ordinary restore-on-success shape) used to re-commit
// an unchanged candidate on EVERY event. RPM emits ping_test_completed
// roughly every probe cycle, and the engine's 30s cooldown only throttles
// the cadence — so the unchanged full commit+apply ran every 30s forever,
// pushing one identical history entry per commit and evicting the bounded
// rollback ladder (50 entries) in ~24 minutes.
//
// The fix short-circuits the commit in applyOnce when the post-batch
// candidate equals the active config: no history push, no global-budget
// spend, no commitFn invocation — but the action still counts as committed
// (runAction arms the cooldown on a nil error), so a repeated event is
// throttled exactly like a real commit.
//
// FAIL-ON-REVERT: without the short-circuit, the first event below performs
// a real store commit, so ListHistory grows and CommittedNoChange stays 0.

// TestNoopCommit_UnchangedBatchSkipsCommit_15022 is the RED core: the batch
// re-sets the host-name the active config already carries, so the post-batch
// candidate is identical to active and the commit must be skipped.
func TestNoopCommit_UnchangedBatchSkipsCommit_15022(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:   "restore-on-success",
		Events: []string{"ping_test_completed"},
		// No WithinClauses: evaluate.go returns true with no temporal filter,
		// so every ping_test_completed fires the policy.
		ThenCommands: []string{"set system host-name base"},
	}
	e := New(s, nil) // nil commitFn: standalone store.Commit path
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	historyBefore := len(s.ListHistory())

	e.HandleEvent(eventFor("ping_test_completed"))

	waitFor(t, "no-change action accounted", func() bool {
		return e.Stats().SkippedNoChange >= 1
	})

	if got := len(s.ListHistory()); got != historyBefore {
		t.Fatalf("history length = %d, want %d: an unchanged candidate must not push a rollback entry (#15022)", got, historyBefore)
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("host-name = %q, want %q (active config must be untouched)", got, "base")
	}
	// The action is a successful no-op, not a rejection or a stale drop.
	st := e.Stats()
	if st.Committed != 1 {
		t.Errorf("Committed = %d, want 1 (a skipped no-change commit still counts committed so the cooldown arms)", st.Committed)
	}
	if st.Rejected != 0 || st.DroppedStale != 0 {
		t.Errorf("Rejected=%d DroppedStale=%d, want 0/0 for a no-change skip", st.Rejected, st.DroppedStale)
	}
	// The global commit budget must not be spent on a no-op.
	e.budgetMu.Lock()
	budgetCount := e.budgetCount
	e.budgetMu.Unlock()
	if budgetCount != 0 {
		t.Errorf("global budget count = %d, want 0 (a skipped commit must not consume the rolling budget)", budgetCount)
	}
}

// The cooldown still arms for a skipped commit: a second event arriving
// inside the 30s window is suppressed at evaluate, so the perpetual
// 30s re-commit cadence the report describes cannot re-form through the
// skip path.
func TestNoopCommit_CooldownStillArms_15022(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "restore-on-success",
		Events:       []string{"ping_test_completed"},
		ThenCommands: []string{"set system host-name base"},
	}
	e := New(s, nil)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_completed"))
	waitFor(t, "no-change action accounted", func() bool {
		return e.Stats().SkippedNoChange >= 1
	})
	armWaitForCooldown(t, e, "restore-on-success")

	e.HandleEvent(eventFor("ping_test_completed"))
	time.Sleep(50 * time.Millisecond)
	if got := e.Stats().SkippedNoChange; got != 1 {
		t.Fatalf("SkippedNoChange = %d, want 1: the cooldown armed by the skipped commit must suppress the in-window repeat", got)
	}
	if got := len(s.ListHistory()); got != 1 {
		t.Fatalf("history length = %d, want 1 (seed commit only)", got)
	}
}

// Control: a batch that REALLY changes the candidate still commits, pushes
// history, and does not count as skipped. Guards the equality gate from
// becoming too aggressive (a gate that always skipped would pass the RED
// test above while silently breaking every real remediation).
func TestNoopCommit_ChangedBatchStillCommits_15022(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "real-change",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name remediated"},
	}
	e := New(s, nil)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	historyBefore := len(s.ListHistory())
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "real commit", func() bool { return e.Stats().Committed >= 1 })

	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Fatalf("host-name = %q, want %q (a changed batch must commit)", got, "remediated")
	}
	if got := len(s.ListHistory()); got != historyBefore+1 {
		t.Fatalf("history length = %d, want %d (a real commit pushes one entry)", got, historyBefore+1)
	}
	if got := e.Stats().SkippedNoChange; got != 0 {
		t.Fatalf("SkippedNoChange = %d, want 0 for a real change", got)
	}
}

// The daemon path (commitFn non-nil) must also skip: commitFn is never
// invoked for an unchanged candidate, so no full apply runs.
func TestNoopCommit_DaemonPathSkipsCommitFn_15022(t *testing.T) {
	s := newStore(t)
	commitCalls := 0
	commitFn := func(ctx context.Context, desc string) (*config.Config, error) {
		commitCalls++
		if _, err := s.CommitWithDescriptionAs("system:event-engine", desc); err != nil {
			return nil, err
		}
		return s.ActiveConfig(), nil
	}
	pol := &config.EventPolicy{
		Name:         "restore-on-success",
		Events:       []string{"ping_test_completed"},
		ThenCommands: []string{"set system host-name base"},
	}
	e := New(s, commitFn)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(rpm.Event{Name: "ping_test_completed", TestOwner: "owner", TestName: "tname"})
	waitFor(t, "no-change action accounted", func() bool {
		return e.Stats().SkippedNoChange >= 1
	})
	if commitCalls != 0 {
		t.Fatalf("commitFn invoked %d times, want 0 for an unchanged candidate", commitCalls)
	}
	if got := len(s.ListHistory()); got != 1 {
		t.Fatalf("history length = %d, want 1 (seed commit only)", got)
	}
}
