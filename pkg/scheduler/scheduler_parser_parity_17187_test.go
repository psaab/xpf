package scheduler

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestSchedulerValidatorRuntimeParity17187 (#17187 acceptance) drives ONE
// table through the commit-time validators (config.ValidateTimeOfDay /
// config.ValidateDate) and the runtime evaluator (isWithinWindow) and
// asserts accept <=> evaluable for the same raw bound, including the
// padded rows. Before the fix the copies had diverged: Validate* trimmed
// and accepted " 09:00", while the runtime parsed raw, failed, and left
// the scheduler inactive all day (a scheduled deny never engaged).
func TestSchedulerValidatorRuntimeParity17187(t *testing.T) {
	loc := time.FixedZone("Parity17187", -7*60*60)
	// Inside every accepted window below.
	inside := time.Date(2026, time.October, 1, 12, 0, 0, 0, loc)

	timeRows := []struct {
		name  string
		start string
		stop  string
	}{
		{"bare HH:MM", "09:00", "17:00"},
		{"HH:MM:SS", "09:00:00", "17:00:00"},
		{"leading-padded start", " 09:00", "17:00"},
		{"trailing-padded start", "09:00 ", "17:00"},
		{"leading-padded stop", "09:00", " 17:00"},
		{"trailing-padded stop", "09:00", "17:00 "},
		{"both padded", " 09:00 ", " 17:00 "},
		{"malformed", "9am", "17:00"},
		{"one-digit hour", "9:00", "17:00"},
		{"empty start", "", "17:00"},
	}
	for _, row := range timeRows {
		t.Run("time/"+row.name, func(t *testing.T) {
			accepted := config.ValidateTimeOfDay(row.start) == nil &&
				config.ValidateTimeOfDay(row.stop) == nil
			sched := &config.SchedulerConfig{
				Name:      "parity17187",
				Daily:     true,
				StartTime: row.start,
				StopTime:  row.stop,
			}
			evaluable := isWithinWindow(inside, sched)
			if accepted != evaluable {
				t.Errorf("start=%q stop=%q: validator accepted=%v but runtime evaluable(active inside)=%v; accept must <=> evaluable",
					row.start, row.stop, accepted, evaluable)
			}
			if row.name == "bare HH:MM" && !evaluable {
				t.Errorf("control: bare window must be active inside")
			}
		})
	}

	dateRows := []struct {
		name  string
		start string
		stop  string
	}{
		{"bare date", "2026-03-01", "2026-12-31"},
		{"date-time", "2026-03-01.08:30", "2026-12-31.17:00"},
		{"leading-padded start", " 2026-03-01", "2026-12-31"},
		{"trailing-padded start", "2026-03-01 ", "2026-12-31"},
		{"trailing-padded stop", "2026-03-01", "2026-12-31 "},
		{"padded date-time", " 2026-03-01.08:30", "2026-12-31.17:00"},
		{"malformed", "2026/03/01", "2026-12-31"},
	}
	for _, row := range dateRows {
		t.Run("date/"+row.name, func(t *testing.T) {
			accepted := config.ValidateDate(row.start) == nil &&
				config.ValidateDate(row.stop) == nil
			sched := &config.SchedulerConfig{
				Name:      "parity17187-date",
				StartDate: row.start,
				StopDate:  row.stop,
			}
			// A date-range-only scheduler is evaluable iff isWithinWindow
			// can decide it: an unparseable bound fails closed (inactive).
			evaluable := isWithinWindow(inside, sched)
			if accepted != evaluable {
				t.Errorf("start=%q stop=%q: validator accepted=%v but runtime evaluable=%v; accept must <=> evaluable",
					row.start, row.stop, accepted, evaluable)
			}
		})
	}

	// Location parity for date-time bounds: the shared parser must
	// interpret the bound in the caller's location, as the deleted
	// pkg/scheduler copy did with time.ParseInLocation. A UTC-parsing
	// mutant shifts the instant and flips this cell.
	t.Run("date-time bound uses caller location", func(t *testing.T) {
		sched := &config.SchedulerConfig{
			Name:      "parity17187-loc",
			StartDate: "2026-10-01.08:30",
			StopDate:  "2026-10-01.09:00",
		}
		// 08:45 in loc (UTC-7) is inside; the same wall clock read as UTC
		// would place `inside` at 01:45 local, before the window.
		if !isWithinWindow(time.Date(2026, time.October, 1, 8, 45, 0, 0, loc), sched) {
			t.Errorf("date-time bound not evaluated in caller location")
		}
	})
}
