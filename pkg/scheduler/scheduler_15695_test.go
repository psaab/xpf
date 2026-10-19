package scheduler

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #15695 limb 1: an overnight tail must not activate before start-date.
// The window opened yesterday at 22:00, before a start-date of today;
// pre-fix overnightTailActive ignored yesterday's date entirely.
// 2026-06-09 is a Tuesday, 2026-06-10 a Wednesday.
func TestIsWithinWindow_OvernightTailStartDate15695(t *testing.T) {
	dailyOnStart := &config.SchedulerConfig{
		Name:      "campaign",
		StartDate: "2026-06-10",
		StartTime: "22:00:00",
		StopTime:  "06:00:00",
	}
	if isWithinWindow(time.Date(2026, 6, 10, 2, 0, 0, 0, time.UTC), dailyOnStart) {
		t.Error("phantom tail: 02:00 on start-date must be inactive; window opened 2026-06-09 22:00 before start-date")
	}
	// Controls: evening of start-date and next morning's tail are live.
	if !isWithinWindow(time.Date(2026, 6, 10, 23, 0, 0, 0, time.UTC), dailyOnStart) {
		t.Error("start-date evening 23:00 must be active")
	}
	if !isWithinWindow(time.Date(2026, 6, 11, 2, 0, 0, 0, time.UTC), dailyOnStart) {
		t.Error("tail of window opened on start-date must be active next morning")
	}

	// Per-day variant: window opened Monday, start-date Tuesday.
	mondayOnly := &config.SchedulerConfig{
		Name:      "mon-night",
		StartDate: "2026-03-10", // Tuesday; 2026-03-09 is a Monday.
		Days: map[string]*config.SchedulerDayWindow{
			"monday": {StartTime: "22:00:00", StopTime: "06:00:00"},
		},
	}
	if isWithinWindow(time.Date(2026, 3, 10, 3, 0, 0, 0, time.UTC), mondayOnly) {
		t.Error("phantom tail: Monday window predates Tuesday start-date and must not activate Tuesday 03:00")
	}

	// Date-time start bound after yesterday's open: same phantom.
	dateTimeStart := &config.SchedulerConfig{
		Name:      "dt",
		StartDate: "2026-06-10.08:30",
		StartTime: "22:00:00",
		StopTime:  "06:00:00",
	}
	if isWithinWindow(time.Date(2026, 6, 10, 2, 0, 0, 0, time.UTC), dateTimeStart) {
		t.Error("phantom tail with date-time start-date must be inactive")
	}
}

// #15695 limb 2: date-only stop-date is inclusive through that date but
// must be inactive at exactly 00:00:00 of the following day. Pre-fix
// `now.After(stop.AddDate(0,0,1))` leaked that exact instant.
func TestWithinDateRange_StopDateMidnightBoundary15695(t *testing.T) {
	sched := &config.SchedulerConfig{Name: "dated", StopDate: "2026-03-10"}
	if !isWithinWindow(time.Date(2026, 3, 10, 23, 59, 59, 0, time.UTC), sched) {
		t.Error("stop-date must stay active through 23:59:59 of the stop date")
	}
	if isWithinWindow(time.Date(2026, 3, 11, 0, 0, 0, 0, time.UTC), sched) {
		t.Error("stop-date 2026-03-10 must be inactive at exactly 2026-03-11T00:00:00")
	}
	if isWithinWindow(time.Date(2026, 3, 11, 0, 0, 30, 0, time.UTC), sched) {
		t.Error("stop-date 2026-03-10 must be inactive after midnight")
	}
}
