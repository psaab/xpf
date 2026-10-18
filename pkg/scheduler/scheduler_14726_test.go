package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #14726 leg 1: a successful latch republish clears republishFailClosed while
// s.active is still the forced all-false map from the latched evaluate. Until
// the next evaluate recomputes the window, consumers reading
// ActiveStateWithFailClosed see (inactive, failClosed=false) — the fail-open
// encoding for a scheduled deny/reject. The scheduler must not expose that
// pair: clearing the latch must recompute the authoritative map from the
// recorded time, so an in-window scheduler reads active, and the recovery
// follow-up is still owed exactly once.
func TestRepublishRecoveryClearsLatchWithRecomputedActive14726(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}
	var (
		s       *Scheduler
		failing = true
	)
	updateFn := func(_ context.Context, state map[string]bool) error {
		if failing {
			return errors.New("republish unavailable")
		}
		return nil
	}
	start := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC) // Thursday, in window
	s, initial := NewPrimed(schedCfg, updateFn, start)
	if !initial["workhours"] {
		t.Fatalf("precondition: workhours should start active, got %v", initial)
	}

	// Drive the republish failure streak past the bounded age while the
	// window closes, so republishFailClosed latches with a forced
	// all-false authoritative map.
	closeAt := time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC)
	s.evaluate(context.Background(), closeAt, true)
	tick := closeAt
	for tick.Sub(closeAt) < RepublishFailClosedAge {
		tick = tick.Add(time.Minute)
		s.evaluate(context.Background(), tick, true)
	}
	if !s.RepublishFailClosed() {
		t.Fatal("precondition: failure streak did not latch fail-closed")
	}

	// The window legitimately reopens the next day; the latched evaluate
	// still forces the map all-false and the republish still fails.
	reopen := time.Date(2026, 2, 13, 10, 0, 0, 0, time.UTC) // Friday, in window
	s.evaluate(context.Background(), reopen, true)
	if state, failClosed := s.ActiveStateWithFailClosed(); state["workhours"] || !failClosed {
		t.Fatalf("latched state = (%v, failClosed=%v), want (inactive, true)", state, failClosed)
	}

	// The latch snapshot now succeeds through the daemon's apply-transaction
	// path (RecordRepublishResult), which recomputes nothing. This is the
	// exact clearing call that used to expose (inactive, false).
	recoveryAt := reopen.Add(time.Minute)
	s.RecordRepublishResult(nil, recoveryAt)
	if s.RepublishFailClosed() {
		t.Fatal("successful latch republish must clear the fail-closed latch")
	}
	state, failClosed := s.ActiveStateWithFailClosed()
	if failClosed {
		t.Fatalf("after recovery failClosed = true, want false (state=%v)", state)
	}
	if !state["workhours"] {
		t.Fatalf("after recovery state = %v, want workhours active: latch cleared while the authoritative map was still forced all-false (fail-open pair for scheduled deny/reject)", state)
	}
	if !s.IsActive("workhours") {
		t.Fatal("after recovery IsActive = false, want true for the reopened window")
	}
	if !s.republishRecoveryPending {
		t.Fatal("recovery must still owe exactly one normal-disposition republish")
	}

	// The owed follow-up evaluate publishes the already-recomputed state and
	// clears the recovery flag without reopening anything spuriously.
	failing = false
	s.evaluate(context.Background(), recoveryAt.Add(time.Minute), true)
	if s.republishRecoveryPending {
		t.Fatal("follow-up evaluate must clear the recovery-pending flag")
	}
	if state, _ := s.ActiveStateWithFailClosed(); !state["workhours"] {
		t.Fatalf("after follow-up state = %v, want workhours active", state)
	}
}

// #14726 leg 1 (apply-path variant): a successful initial publish recorded
// via RecordRepublishResult while the scheduler is merely pending (not yet
// latched) must not clear recovery owed from an earlier latch, and an
// intervening successful RecordRepublishResult must not strand the map.
func TestRecordRepublishResultSuccessRecomputesForcedMap14726(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", AllDay: true},
	}
	noop := func(context.Context, map[string]bool) error { return nil }
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	s, initial := NewPrimed(schedCfg, noop, now)
	if !initial["workhours"] {
		t.Fatalf("precondition: all-day scheduler should start active, got %v", initial)
	}
	failErr := errors.New("stale republish")
	s.RecordRepublishResult(failErr, now.Add(-6*time.Minute))
	s.RecordRepublishResult(failErr, now)
	if !s.RepublishFailClosed() {
		t.Fatal("precondition: latch not set")
	}
	// Force the latched map through evaluate so s.active is all-false.
	s.evaluate(context.Background(), now.Add(time.Minute), false)
	if s.ActiveState()["workhours"] {
		t.Fatal("precondition: latched map must be inactive")
	}
	s.RecordRepublishResult(nil, now.Add(2*time.Minute))
	if state, failClosed := s.ActiveStateWithFailClosed(); failClosed || !state["workhours"] {
		t.Fatalf("after RecordRepublishResult(nil): state=%v failClosed=%v, want (active, false)", state, failClosed)
	}
}

// #14726 leg 3: an overnight per-day window belongs to the weekday it starts
// on. Friday 22:00-06:00 must be inactive Friday 00:30 (that tail belongs to
// Thursday, which has no arm) and active Saturday 00:30 (Friday's tail).
// A daily (every-day) overnight window is the control: its tail is active
// every morning because every day resolves to the same window.
func TestIsWithinWindow_OvernightPerDayWeekday14726(t *testing.T) {
	fridayOnly := &config.SchedulerConfig{
		Name: "fri-night",
		Days: map[string]*config.SchedulerDayWindow{
			"friday": {StartTime: "22:00:00", StopTime: "06:00:00"},
		},
	}
	// 2026-03-06 is a Friday; 2026-03-07 a Saturday.
	probes := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"friday evening inside", time.Date(2026, 3, 6, 23, 0, 0, 0, time.UTC), true},
		{"friday early tail inactive (belongs to thursday)", time.Date(2026, 3, 6, 0, 30, 0, 0, time.UTC), false},
		{"saturday early tail active (friday window)", time.Date(2026, 3, 7, 0, 30, 0, 0, time.UTC), true},
		{"saturday before stop active", time.Date(2026, 3, 7, 5, 59, 0, 0, time.UTC), true},
		{"saturday at stop inactive", time.Date(2026, 3, 7, 6, 0, 0, 0, time.UTC), false},
		{"saturday evening inactive (no saturday arm)", time.Date(2026, 3, 7, 23, 0, 0, 0, time.UTC), false},
		{"friday noon inactive", time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC), false},
		{"friday at start active", time.Date(2026, 3, 6, 22, 0, 0, 0, time.UTC), true},
		{"friday before start inactive", time.Date(2026, 3, 6, 21, 59, 0, 0, time.UTC), false},
	}
	for _, tc := range probes {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWithinWindow(tc.now, fridayOnly); got != tc.want {
				t.Errorf("isWithinWindow(%s, friday 22:00-06:00) = %v, want %v", tc.now, got, tc.want)
			}
		})
	}

	// Control: a uniform daily overnight window keeps its existing tail
	// behaviour on both mornings.
	daily := &config.SchedulerConfig{Name: "nightly", StartTime: "22:00:00", StopTime: "06:00:00"}
	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"daily friday early active", time.Date(2026, 3, 6, 0, 30, 0, 0, time.UTC), true},
		{"daily saturday early active", time.Date(2026, 3, 7, 0, 30, 0, 0, time.UTC), true},
		{"daily noon inactive", time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWithinWindow(tc.now, daily); got != tc.want {
				t.Errorf("isWithinWindow(%s, daily 22:00-06:00) = %v, want %v", tc.now, got, tc.want)
			}
		})
	}

	// Control: a per-day overnight window whose next day has its own arm —
	// the next day's own evening window still governs its evening, and an
	// explicit next-day exclude suppresses the inherited tail.
	satExcluded := &config.SchedulerConfig{
		Name: "fri-night-sat-excluded",
		Days: map[string]*config.SchedulerDayWindow{
			"friday":   {StartTime: "22:00:00", StopTime: "06:00:00"},
			"saturday": {Exclude: true},
		},
	}
	if isWithinWindow(time.Date(2026, 3, 7, 0, 30, 0, 0, time.UTC), satExcluded) {
		t.Error("saturday exclude must suppress friday's overnight tail on saturday morning")
	}
	if !isWithinWindow(time.Date(2026, 3, 6, 23, 0, 0, 0, time.UTC), satExcluded) {
		t.Error("friday evening must stay active when only saturday is excluded")
	}
}
