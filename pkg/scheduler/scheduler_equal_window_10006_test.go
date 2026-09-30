package scheduler

// #10006/#11089: start==stop MEANS never-active. The runtime evaluator
// (withinTimeOfDay) short-circuits equal bounds to false (Junos parity: an
// empty [start, stop) range matches nothing). Pre-#11089 the evaluator took
// the wraparound branch for equal bounds, which was true for every clock
// time and permitted 24/7 — a fail-open time gate. These pins go RED if the
// branch ever regresses to always-active.
//
// The commit-time warning that surfaces this convention to operators is
// pinned on the config side (pkg/config
// compiler_validate_scheduler_equal_window_10006_test.go).

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestIsWithinWindow_EqualStartStop_NeverActive pins a daily window with
// equal bounds inactive at every probe, including midnight, exactly at the
// bound, midday, and the last second of the day.
func TestIsWithinWindow_EqualStartStop_NeverActive(t *testing.T) {
	sched := &config.SchedulerConfig{Name: "eq", StartTime: "09:00:00", StopTime: "09:00:00"}
	probes := []time.Time{
		time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 12, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 12, 23, 59, 59, 0, time.UTC),
	}
	for _, now := range probes {
		if isWithinWindow(now, sched) {
			t.Errorf("start==stop must be never-active, active at %s", now.Format("15:04:05"))
		}
	}
}

// TestIsWithinWindow_EqualStartStop_PerDay_NeverActive pins a per-day
// override with equal bounds inactive on that day.
func TestIsWithinWindow_EqualStartStop_PerDay_NeverActive(t *testing.T) {
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
	if isWithinWindow(thu, sched) {
		t.Error("per-day start==stop must be never-active on that day")
	}
}

// TestIsWithinWindow_EqualStartStop_ExplicitOverrides pins the precedence
// controls: an explicit exclusion remains inactive, while an explicit
// all-day arm remains active.
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
