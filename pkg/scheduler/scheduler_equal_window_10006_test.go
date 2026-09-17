package scheduler

// #10006: start==stop MEANS always-active. The runtime evaluator
// (withinTimeOfDay) takes the wraparound branch for equal bounds, which is
// true for every clock time. That is the preserved status quo per Hyrum's
// law — NOT a never-active or instantaneous window. These pins go RED if the
// branch is ever "fixed" to treat equality as closed.
//
// The commit-time warning that surfaces this convention to operators is
// pinned on the config side (pkg/config
// compiler_validate_scheduler_equal_window_10006_test.go).

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestIsWithinWindow_EqualStartStop_AlwaysActive pins a daily window with
// equal bounds active at every probe, including midnight, exactly at the
// bound, midday, and the last second of the day.
func TestIsWithinWindow_EqualStartStop_AlwaysActive(t *testing.T) {
	sched := &config.SchedulerConfig{Name: "eq", StartTime: "09:00:00", StopTime: "09:00:00"}
	probes := []time.Time{
		time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 12, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 12, 23, 59, 59, 0, time.UTC),
	}
	for _, now := range probes {
		if !isWithinWindow(now, sched) {
			t.Errorf("start==stop must be always-active, inactive at %s", now.Format("15:04:05"))
		}
	}
}

// TestIsWithinWindow_EqualStartStop_PerDay_AlwaysActive pins a per-day
// override with equal bounds always-active on that day — and only that day.
func TestIsWithinWindow_EqualStartStop_PerDay_AlwaysActive(t *testing.T) {
	thu := time.Date(2026, 2, 12, 3, 0, 0, 0, time.UTC)
	if thu.Weekday() != time.Thursday {
		t.Fatalf("fixture precondition: 2026-02-12 must be a Thursday, got %s", thu.Weekday())
	}
	sched := &config.SchedulerConfig{
		Name: "eqday",
		Days: map[string]*config.SchedulerDayWindow{
			"thursday": {StartTime: "14:00:00", StopTime: "14:00:00"},
		},
	}
	if !isWithinWindow(thu, sched) {
		t.Error("per-day start==stop must be always-active on that day")
	}
	fri := time.Date(2026, 2, 13, 3, 0, 0, 0, time.UTC)
	if isWithinWindow(fri, sched) {
		t.Error("per-day start==stop must not leak onto days without an override")
	}
}

// TestIsWithinWindow_EqualStartStop_ExplicitOverrides pins the precedence
// controls that keep an equality warning truthful: an explicit exclusion
// remains inactive, while an explicit all-day arm remains active.
func TestIsWithinWindow_EqualStartStop_ExplicitOverrides(t *testing.T) {
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC) // Thursday
	excluded := &config.SchedulerConfig{
		Name: "excluded-eq",
		Days: map[string]*config.SchedulerDayWindow{
			"thursday": {
				StartTime: "09:00:00",
				StopTime:  "09:00:00",
				Exclude:   true,
			},
		},
	}
	if isWithinWindow(now, excluded) {
		t.Error("explicit exclude must remain inactive despite equal bounds")
	}

	allDay := &config.SchedulerConfig{
		Name:      "allday-eq",
		StartTime: "09:00:00",
		StopTime:  "09:00:00",
		AllDay:    true,
	}
	if !isWithinWindow(now, allDay) {
		t.Error("explicit all-day must remain active alongside equal bounds")
	}
}
