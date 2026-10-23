package scheduler

// #16010: a scheduler marked Unresolvable by tolerant compile (all-day +
// complete-window conflict) must never be active, at any time of day, on
// any weekday — permits gated by it fail closed instead of resolving
// widest via the all-day arm. (Scheduled DENY/REJECT eligibility is a
// snapshot-lowering disposition, pinned in pkg/dataplane/userspace
// TestBuildPolicySnapshotsUnresolvableScheduler16010.)
//
// FAIL-ON-REVERT: removing the Unresolvable check in isWithinWindow makes
// the all-day cases below active and this test fails.

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestIsWithinWindowUnresolvable16010(t *testing.T) {
	// Monday 2026-02-09 12:00 UTC and Monday 03:00 (outside the window but
	// inside all-day) both must be inactive.
	for _, now := range []time.Time{
		time.Date(2026, 2, 9, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 9, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC),
	} {
		daily := &config.SchedulerConfig{
			Name: "S", AllDay: true, StartTime: "09:00:00", StopTime: "17:00:00",
			Unresolvable: true,
		}
		if isWithinWindow(now, daily) {
			t.Fatalf("unresolvable daily all-day+window scheduler active at %v, want fail-closed", now)
		}
		weekday := &config.SchedulerConfig{
			Name: "S", Unresolvable: true,
			Days: map[string]*config.SchedulerDayWindow{
				"monday": {AllDay: true, StartTime: "09:00:00", StopTime: "17:00:00"},
			},
		}
		if isWithinWindow(now, weekday) {
			t.Fatalf("unresolvable weekday all-day+window scheduler active at %v, want fail-closed", now)
		}
	}
	// Control: same windows without the mark behave as before (all-day wins).
	control := &config.SchedulerConfig{Name: "S", AllDay: true, StartTime: "09:00:00", StopTime: "17:00:00"}
	if !isWithinWindow(time.Date(2026, 2, 9, 3, 0, 0, 0, time.UTC), control) {
		t.Fatal("control all-day scheduler must remain active outside the window")
	}
	// A Scheduler built from the marked config reports inactive via the
	// public surface the dataplane consumes.
	s, _ := NewPrimed(map[string]*config.SchedulerConfig{
		"S": {Name: "S", AllDay: true, StartTime: "09:00:00", StopTime: "17:00:00", Unresolvable: true},
	}, nil, time.Date(2026, 2, 9, 12, 0, 0, 0, time.UTC))
	if s.IsActive("S") {
		t.Fatal("IsActive must be false for an unresolvable scheduler")
	}
	if state := s.ActiveState(); state["S"] {
		t.Fatalf("ActiveState must report unresolvable scheduler inactive, got %v", state)
	}
}
