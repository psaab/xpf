package scheduler

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestJunosNativeDailyTimeBoundary11305(t *testing.T) {
	local := time.FixedZone("JunosLocal", -7*60*60)
	sched := &config.SchedulerConfig{
		Name:      "daily-window",
		Daily:     true,
		StartTime: "08:30",
		StopTime:  "09:00",
	}
	for _, tc := range []struct {
		name   string
		hour   int
		minute int
		second int
		want   bool
	}{
		{"before start", 8, 29, 59, false},
		{"at start", 8, 30, 0, true},
		{"before stop", 8, 59, 59, true},
		{"at exclusive stop", 9, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 10, 1, tc.hour, tc.minute, tc.second, 0, local)
			if got := isWithinWindow(now, sched); got != tc.want {
				t.Errorf("isWithinWindow(%s) = %v, want %v",
					now.Format(time.RFC3339), got, tc.want)
			}
		})
	}
}

func TestJunosNativeDateTimeBoundary11305(t *testing.T) {
	local := time.FixedZone("JunosLocal", -7*60*60)
	sched := &config.SchedulerConfig{
		Name:      "one-time-window",
		StartDate: "2026-10-01.08:30",
		StopDate:  "2026-10-01.09:00",
	}
	for _, tc := range []struct {
		name   string
		year   int
		month  time.Month
		day    int
		hour   int
		minute int
		second int
		want   bool
	}{
		{"before start", 2026, time.October, 1, 8, 29, 59, false},
		{"at start", 2026, time.October, 1, 8, 30, 0, true},
		{"before stop", 2026, time.October, 1, 8, 59, 59, true},
		{"at exclusive stop", 2026, time.October, 1, 9, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(tc.year, tc.month, tc.day, tc.hour, tc.minute, tc.second, 0, local)
			if got := isWithinWindow(now, sched); got != tc.want {
				t.Errorf("isWithinWindow(%s) = %v, want %v",
					now.Format(time.RFC3339), got, tc.want)
			}
		})
	}
}
