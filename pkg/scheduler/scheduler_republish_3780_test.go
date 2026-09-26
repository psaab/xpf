package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestScheduler_RepublishFailureRetriesUntilConverged is the #3780
// self-heal contract. A scheduler window transition republishes
// enforcement via updateFn. When that republish FAILS the transition has
// not converged — a scheduled permit whose window just closed would keep
// forwarding (fail-open). The scheduler must latch the failure and
// re-fire updateFn on the NEXT tick even though the active-state map did
// not change, retrying until it succeeds.
//
// RED-on-revert: reverting the `|| s.republishPending` re-fire (or
// recordRepublishResultLocked) makes the retry never happen — the second
// evaluate would not call updateFn (calls stays at 1) and the stale
// permit would persist silently.
func TestScheduler_RepublishFailureRetriesUntilConverged(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}

	var (
		calls     int
		lastState map[string]bool
		failing   = true
	)
	updateFn := func(_ context.Context, state map[string]bool) error {
		calls++
		lastState = state
		if failing {
			return errors.New("republish failed")
		}
		return nil
	}

	// Prime inside the window (active). NewPrimed must not fire updateFn.
	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, initial := NewPrimed(schedCfg, updateFn, now)
	if !initial["workhours"] {
		t.Fatalf("workhours should start active inside window, got %v", initial)
	}
	if calls != 0 {
		t.Fatalf("NewPrimed must not fire updateFn, got %d calls", calls)
	}
	if s.RepublishPending() {
		t.Fatal("fresh scheduler must not report a pending republish")
	}

	// Window closes at 17:00 → state flips to inactive. The first
	// evaluate fires updateFn, which FAILS. The transition must stay
	// pending for retry.
	closeT := time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC)
	s.evaluate(context.Background(), closeT, true)
	if calls != 1 {
		t.Fatalf("window close should fire updateFn once, got %d", calls)
	}
	if lastState["workhours"] {
		t.Fatal("workhours should be inactive after the window closed")
	}
	if !s.RepublishPending() {
		t.Fatal("a failed republish must leave the transition pending for retry (fail-open otherwise)")
	}
	pending, failures, since := s.RepublishFailureStatus()
	if !pending || failures != 1 || since.IsZero() {
		t.Fatalf("failure status = (pending=%v failures=%d since=%v), want (true, 1, non-zero)", pending, failures, since)
	}

	// Next tick: the active state did NOT change (still outside window),
	// but because the prior republish failed, evaluate MUST re-fire
	// updateFn. This is the self-heal that revert kills.
	nextT := closeT.Add(1 * time.Minute)
	s.evaluate(context.Background(), nextT, true)
	if calls != 2 {
		t.Fatalf("pending republish must be retried on the next tick even without a state change, got %d calls", calls)
	}
	if !s.RepublishPending() {
		t.Fatal("a still-failing retry must stay pending")
	}

	// The transient failure clears; the retry converges and clears the
	// pending flag.
	failing = false
	s.evaluate(context.Background(), nextT.Add(1*time.Minute), true)
	if calls != 3 {
		t.Fatalf("pending republish must fire again, got %d calls", calls)
	}
	if s.RepublishPending() {
		t.Fatal("a successful republish must clear the pending flag")
	}

	// Converged steady state: no change, not pending → no further fires.
	s.evaluate(context.Background(), nextT.Add(2*time.Minute), true)
	if calls != 3 {
		t.Fatalf("converged steady state must not re-fire updateFn, got %d calls", calls)
	}
}

// TestScheduler_SuccessfulRepublishNeverLatchesPending guards the happy
// path: a state change whose republish succeeds must not leave the
// scheduler in a pending/retry state (which would churn an identical
// snapshot every tick forever).
func TestScheduler_SuccessfulRepublishNeverLatchesPending(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}
	var calls int
	updateFn := func(context.Context, map[string]bool) error {
		calls++
		return nil
	}
	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, _ := NewPrimed(schedCfg, updateFn, now)

	// Close the window: one successful republish, no pending.
	s.evaluate(context.Background(), time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC), true)
	if calls != 1 {
		t.Fatalf("window close should fire once, got %d", calls)
	}
	if s.RepublishPending() {
		t.Fatal("a successful republish must not latch pending")
	}
	// A subsequent no-change tick must not re-fire.
	s.evaluate(context.Background(), time.Date(2026, 2, 12, 17, 31, 0, 0, time.UTC), true)
	if calls != 1 {
		t.Fatalf("no-change tick after a successful republish must not re-fire, got %d", calls)
	}
}

func TestScheduler_CarriesClockHoldAndRepublishFailureAcrossReplacement(t *testing.T) {
	oldCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}
	newCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", AllDay: true},
	}
	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)

	var oldCalls int
	old, initial := NewPrimed(oldCfg, func(context.Context, map[string]bool) error {
		oldCalls++
		return errors.New("republish unavailable")
	}, now)
	if !initial["workhours"] {
		t.Fatal("old scheduler should start with the permit active")
	}

	// Simulate a wall-clock step. The scheduler must hold scheduled permits
	// closed and the failed close must begin the bounded republish streak.
	old.mu.Lock()
	old.lastWallUnixNano = now.Add(time.Hour).UnixNano()
	old.mu.Unlock()
	stepAt := now.Add(time.Minute)
	old.evaluate(context.Background(), stepAt, true)
	if oldCalls != 1 || old.IsActive("workhours") {
		t.Fatalf("clock-step evaluation calls=%d active=%t, want one failed close and inactive state",
			oldCalls, old.IsActive("workhours"))
	}

	// A hash replacement during the recovery hold must not reset the hold or
	// prime a newly-active permit.
	holdReplacement, _ := NewPrimed(newCfg, func(context.Context, map[string]bool) error { return nil }, stepAt.Add(time.Minute))
	holdReplacement.CarryRecoveryStateFrom(old, stepAt.Add(time.Minute))
	if holdReplacement.ActiveState()["workhours"] {
		t.Fatal("replacement scheduler reopened the permit during the inherited clock recovery hold")
	}

	// Keep the old republish failing through its five-minute fail-closed bound.
	for minute := 2; minute <= 7; minute++ {
		old.evaluate(context.Background(), now.Add(time.Duration(minute)*time.Minute), true)
	}
	if !old.RepublishFailClosed() {
		t.Fatal("five-minute failed republish streak did not latch fail-closed")
	}
	if old.IsActive("workhours") {
		t.Fatal("old scheduler did not publish an inactive state after fail-closed latched")
	}
	_, failuresBeforeReplace, sinceBeforeReplace := old.RepublishFailureStatus()
	if failuresBeforeReplace < 6 || !sinceBeforeReplace.Equal(stepAt) {
		t.Fatalf("failure status before replacement = (%d, %v), want continued streak from %v",
			failuresBeforeReplace, sinceBeforeReplace, stepAt)
	}

	// Replacement config is active at this wall time. It must inherit the
	// retry/fail-closed latch and retry the denied state rather than silently
	// clearing the five-minute recovery bound.
	replacedAt := now.Add(8 * time.Minute)
	var (
		newCalls int
		newState map[string]bool
	)
	replacement, primed := NewPrimed(newCfg, func(_ context.Context, state map[string]bool) error {
		newCalls++
		newState = state
		return errors.New("republish unavailable")
	}, replacedAt)
	if !primed["workhours"] {
		t.Fatal("changed schedule should be active before inherited safety state")
	}
	replacement.CarryRecoveryStateFrom(old, replacedAt)
	if !replacement.RepublishPending() || !replacement.RepublishFailClosed() {
		t.Fatal("replacement scheduler lost the pending fail-closed recovery state")
	}
	if replacement.ActiveState()["workhours"] {
		t.Fatal("replacement scheduler exposed an active permit after fail-closed inheritance")
	}
	_, failuresAfterReplace, sinceAfterReplace := replacement.RepublishFailureStatus()
	if failuresAfterReplace != failuresBeforeReplace || !sinceAfterReplace.Equal(sinceBeforeReplace) {
		t.Fatalf("failure status after replacement = (%d, %v), want (%d, %v)",
			failuresAfterReplace, sinceAfterReplace, failuresBeforeReplace, sinceBeforeReplace)
	}

	replacement.evaluate(context.Background(), replacedAt.Add(time.Minute), true)
	if newCalls != 1 || newState == nil || newState["workhours"] {
		t.Fatalf("inherited pending retry calls=%d state=%v, want one inactive retry", newCalls, newState)
	}
}
