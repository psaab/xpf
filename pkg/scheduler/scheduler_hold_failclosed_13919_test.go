package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #13919: an in-window scheduled deny/reject must remain eligible when the
// scheduler's wall clock is held or its configured zone is unavailable. The
// published all-false active map also needs the action-aware fail-closed bit;
// without it the userspace builder marks the deny inactive and allows fallthrough.
func TestPolicyFailClosedCoversRecoveryHoldAndUnavailableZone13919(t *testing.T) {
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	defs := map[string]*config.SchedulerConfig{"workhours": {Name: "workhours", AllDay: true}}
	noop := func(context.Context, map[string]bool) error { return nil }

	trusted, active := NewPrimed(defs, noop, now)
	if !active["workhours"] || trusted.PolicyFailClosed(now) {
		t.Fatalf("trusted control: active=%v failClosed=%t, want active and normal disposition", active, trusted.PolicyFailClosed(now))
	}

	stepped, _ := NewPrimed(defs, noop, now.Add(time.Hour))
	held, _ := NewPrimed(defs, noop, now)
	held.CarryRecoveryStateFrom(stepped, now)
	if !held.InRecoveryHold(now) {
		t.Fatal("precondition: scheduler did not enter recovery hold")
	}
	if held.ActiveState()["workhours"] || !held.PolicyFailClosed(now) {
		t.Fatalf("recovery hold: active=%v failClosed=%t, want inactive plus deny-eligible disposition", held.ActiveState(), held.PolicyFailClosed(now))
	}
	if held.PolicyFailClosed(now.Add(3 * time.Minute)) {
		t.Fatal("recovery hold disposition persisted past hold expiration")
	}

	zoneUnavailable, zoneState := NewPrimedInLocation(defs, noop, now, nil)
	if zoneState["workhours"] || !zoneUnavailable.PolicyFailClosed(now) {
		t.Fatalf("unavailable zone: active=%v failClosed=%t, want inactive plus deny-eligible disposition", zoneState, zoneUnavailable.PolicyFailClosed(now))
	}
}

// A clock step must publish the disposition transition even when both the
// old (out-of-window) and new (held) active maps are all-false.
func TestClockStepPublishesDenyDispositionWithoutMapChange13919(t *testing.T) {
	now := time.Date(2026, 2, 12, 11, 59, 0, 0, time.UTC)
	defs := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "12:00", StopTime: "13:00"},
	}
	calls := 0
	s, active := NewPrimed(defs, func(context.Context, map[string]bool) error {
		calls++
		return nil
	}, now)
	if active["workhours"] {
		t.Fatal("control precondition: scheduler must be outside its window")
	}
	// Simulate the wall clock having advanced much farther than monotonic
	// elapsed time between evaluations.
	s.mu.Lock()
	s.lastWallUnixNano = now.Add(time.Hour).UnixNano()
	s.mu.Unlock()
	s.evaluate(context.Background(), now.Add(time.Minute), true)
	if calls != 1 {
		t.Fatalf("clock-step publication calls = %d, want 1 despite unchanged active map", calls)
	}
	if !s.PolicyFailClosed(now.Add(time.Minute)) {
		t.Fatal("clock-step publication lost its deny-first disposition")
	}
}
