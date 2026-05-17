package scheduler

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestIsWithinWindow_NoTimes(t *testing.T) {
	sched := &config.SchedulerConfig{Name: "always"}
	now := time.Date(2026, 2, 12, 14, 30, 0, 0, time.UTC)
	if !isWithinWindow(now, sched) {
		t.Error("no times configured should always be active")
	}
}

func TestIsWithinWindow_NormalRange_Inside(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "business-hours",
		StartTime: "08:00:00",
		StopTime:  "17:00:00",
	}
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC) // noon
	if !isWithinWindow(now, sched) {
		t.Error("noon should be within 08:00-17:00")
	}
}

func TestIsWithinWindow_NormalRange_Outside(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "business-hours",
		StartTime: "08:00:00",
		StopTime:  "17:00:00",
	}
	now := time.Date(2026, 2, 12, 20, 0, 0, 0, time.UTC) // 8pm
	if isWithinWindow(now, sched) {
		t.Error("8pm should be outside 08:00-17:00")
	}
}

func TestIsWithinWindow_NormalRange_AtStart(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "business-hours",
		StartTime: "08:00:00",
		StopTime:  "17:00:00",
	}
	now := time.Date(2026, 2, 12, 8, 0, 0, 0, time.UTC) // exactly 08:00
	if !isWithinWindow(now, sched) {
		t.Error("exactly at start time should be within window")
	}
}

func TestIsWithinWindow_NormalRange_AtStop(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "business-hours",
		StartTime: "08:00:00",
		StopTime:  "17:00:00",
	}
	now := time.Date(2026, 2, 12, 17, 0, 0, 0, time.UTC) // exactly 17:00
	if isWithinWindow(now, sched) {
		t.Error("exactly at stop time should be outside window (exclusive)")
	}
}

func TestIsWithinWindow_Overnight_Inside(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "overnight",
		StartTime: "22:00:00",
		StopTime:  "06:00:00",
	}
	now := time.Date(2026, 2, 12, 23, 0, 0, 0, time.UTC) // 11pm
	if !isWithinWindow(now, sched) {
		t.Error("11pm should be within 22:00-06:00 overnight window")
	}
}

func TestIsWithinWindow_Overnight_InsideNextMorning(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "overnight",
		StartTime: "22:00:00",
		StopTime:  "06:00:00",
	}
	now := time.Date(2026, 2, 13, 3, 0, 0, 0, time.UTC) // 3am
	if !isWithinWindow(now, sched) {
		t.Error("3am should be within 22:00-06:00 overnight window")
	}
}

func TestIsWithinWindow_Overnight_Outside(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "overnight",
		StartTime: "22:00:00",
		StopTime:  "06:00:00",
	}
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC) // noon
	if isWithinWindow(now, sched) {
		t.Error("noon should be outside 22:00-06:00 overnight window")
	}
}

func TestIsWithinWindow_DateRange_Before(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "campaign",
		StartDate: "2026-03-01",
		StopDate:  "2026-03-31",
		StartTime: "00:00:00",
		StopTime:  "23:59:59",
	}
	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	if isWithinWindow(now, sched) {
		t.Error("February date should be before March date range")
	}
}

func TestIsWithinWindow_DateRange_Inside(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "campaign",
		StartDate: "2026-03-01",
		StopDate:  "2026-03-31",
		StartTime: "00:00:00",
		StopTime:  "23:59:59",
	}
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	if !isWithinWindow(now, sched) {
		t.Error("mid-March should be within March date range")
	}
}

func TestIsWithinWindow_DateRange_After(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "campaign",
		StartDate: "2026-03-01",
		StopDate:  "2026-03-31",
		StartTime: "00:00:00",
		StopTime:  "23:59:59",
	}
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	if isWithinWindow(now, sched) {
		t.Error("April should be after March date range")
	}
}

func TestIsWithinWindow_DateRangeOnly(t *testing.T) {
	sched := &config.SchedulerConfig{
		Name:      "campaign",
		StartDate: "2026-03-01",
		StopDate:  "2026-03-31",
	}
	// Within date range, no time restriction
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	if !isWithinWindow(now, sched) {
		t.Error("within date range with no time should be active")
	}
}

func TestScheduler_InitialState(t *testing.T) {
	var called bool
	var state map[string]bool

	schedCfg := map[string]*config.SchedulerConfig{
		"always-on": {Name: "always-on"}, // no times = always active
	}

	s := New(schedCfg, func(activeState map[string]bool) {
		called = true
		state = activeState
	})

	if !called {
		t.Error("callback should be called on initial evaluation")
	}
	if !state["always-on"] {
		t.Error("always-on should be active")
	}
	if !s.IsActive("always-on") {
		t.Error("IsActive should return true for always-on")
	}
}

func TestScheduler_NewPrimedDoesNotNotifyInitialState(t *testing.T) {
	var called bool
	schedCfg := map[string]*config.SchedulerConfig{
		"always-on": {Name: "always-on"},
	}

	s, state := NewPrimed(schedCfg, func(activeState map[string]bool) {
		called = true
	}, time.Date(2026, 2, 12, 14, 30, 0, 0, time.UTC))

	if called {
		t.Fatal("NewPrimed fired callback during constructor")
	}
	if !state["always-on"] {
		t.Fatal("initial state missing always-on=true")
	}
	if !s.IsActive("always-on") {
		t.Fatal("IsActive should return true for always-on")
	}
}

func TestScheduler_WallClockBackwardStepFailsClosed(t *testing.T) {
	var lastState map[string]bool
	schedCfg := map[string]*config.SchedulerConfig{
		"business-hours": {
			Name:      "business-hours",
			StartTime: "08:00:00",
			StopTime:  "17:00:00",
		},
	}
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	s, state := NewPrimed(schedCfg, func(activeState map[string]bool) {
		lastState = activeState
	}, now)
	if !state["business-hours"] {
		t.Fatal("initial state should be active")
	}

	s.evaluate(now.Add(-1*time.Hour), true)
	if lastState == nil {
		t.Fatal("expected callback after fail-closed state change")
	}
	if lastState["business-hours"] {
		t.Fatalf("wall-clock backward step should fail closed, got state %+v", lastState)
	}
	if s.IsActive("business-hours") {
		t.Fatal("scheduler should remain inactive after backward wall-clock step")
	}
}

func TestScheduler_WallClockBackwardStepStaysFailClosedUntilClockRecovers(t *testing.T) {
	var lastState map[string]bool
	schedCfg := map[string]*config.SchedulerConfig{
		"business-hours": {
			Name:      "business-hours",
			StartTime: "08:00:00",
			StopTime:  "17:00:00",
		},
	}
	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	s, state := NewPrimed(schedCfg, func(activeState map[string]bool) {
		lastState = activeState
	}, now)
	if !state["business-hours"] {
		t.Fatal("initial state should be active")
	}

	// Simulate the real NTP rollback shape: monotonic time advances while
	// wall time appears to move backward relative to the previous wall sample.
	s.mu.Lock()
	s.lastEval = now
	s.lastWallUnixNano = now.Add(time.Hour).UnixNano()
	s.mu.Unlock()

	s.evaluate(now.Add(time.Second), true)
	if lastState == nil || lastState["business-hours"] {
		t.Fatalf("first backward-step evaluation should fail closed, got state %+v", lastState)
	}
	lastState = nil

	// The recovery hold keeps the scheduler closed for more than one tick,
	// even after the new wall/monotonic samples are internally consistent.
	s.evaluate(now.Add(time.Minute), true)
	if lastState != nil {
		t.Fatalf("second rollback evaluation should not notify without state change, got %+v", lastState)
	}
	if s.IsActive("business-hours") {
		t.Fatal("scheduler should stay inactive during wall-clock recovery hold")
	}

	s.evaluate(now.Add(3*time.Minute), true)
	if lastState == nil || !lastState["business-hours"] {
		t.Fatalf("scheduler should recover after hold window, got state %+v", lastState)
	}
}

func TestScheduler_ActiveState(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"always-on": {Name: "always-on"},
	}
	s := New(schedCfg, func(activeState map[string]bool) {})

	state := s.ActiveState()
	if !state["always-on"] {
		t.Error("ActiveState should contain always-on = true")
	}

	// Verify it's a copy
	state["always-on"] = false
	if !s.IsActive("always-on") {
		t.Error("ActiveState should return a copy, not a reference")
	}
}

func TestScheduler_Update(t *testing.T) {
	var lastState map[string]bool
	schedCfg := map[string]*config.SchedulerConfig{
		"always-on": {Name: "always-on"},
	}
	s := New(schedCfg, func(activeState map[string]bool) {
		lastState = activeState
	})

	// Update with new schedulers (removes always-on, adds another)
	s.Update(map[string]*config.SchedulerConfig{
		"new-sched": {Name: "new-sched"},
	})

	if !lastState["new-sched"] {
		t.Error("new-sched should be active")
	}
	if _, exists := lastState["always-on"]; exists {
		t.Error("always-on should be removed after Update")
	}
}

func TestTod_Before(t *testing.T) {
	tests := []struct {
		a, b tod
		want bool
	}{
		{tod{8, 0, 0}, tod{9, 0, 0}, true},
		{tod{9, 0, 0}, tod{8, 0, 0}, false},
		{tod{8, 0, 0}, tod{8, 0, 0}, false},
		{tod{8, 30, 0}, tod{8, 31, 0}, true},
		{tod{8, 30, 59}, tod{8, 31, 0}, true},
		{tod{8, 30, 0}, tod{8, 30, 1}, true},
	}
	for _, tt := range tests {
		if got := tt.a.before(tt.b); got != tt.want {
			t.Errorf("%v.before(%v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestParseTimeOfDay(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		want    tod
	}{
		{"08:00:00", false, tod{8, 0, 0}},
		{"23:59:59", false, tod{23, 59, 59}},
		{"00:00:00", false, tod{0, 0, 0}},
		{"invalid", true, tod{}},
		{"8:00", true, tod{}},
	}
	for _, tt := range tests {
		got, err := parseTimeOfDay(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseTimeOfDay(%q) err = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseTimeOfDay(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
