package scheduler

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestIsWithinWindow_DailyExclude12822(t *testing.T) {
	probes := []struct {
		name  string
		now   time.Time
		sched *config.SchedulerConfig
		want  bool
	}{
		{
			name:  "excludes ordinary daily window",
			now:   time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
			sched: &config.SchedulerConfig{Name: "excluded", StartTime: "09:00:00", StopTime: "17:00:00", DailyExclude: true},
			want:  false,
		},
		{
			name:  "bare daily exclude remains inactive",
			now:   time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
			sched: &config.SchedulerConfig{Name: "bare-exclude", DailyExclude: true},
			want:  false,
		},
		{
			name:  "excludes at normal window start",
			now:   time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC),
			sched: &config.SchedulerConfig{Name: "excluded", StartTime: "09:00:00", StopTime: "17:00:00", DailyExclude: true},
			want:  false,
		},
		{
			name:  "excludes overnight window",
			now:   time.Date(2026, 3, 2, 23, 0, 0, 0, time.UTC),
			sched: &config.SchedulerConfig{Name: "excluded-overnight", StartTime: "22:00:00", StopTime: "06:00:00", DailyExclude: true},
			want:  false,
		},
		{
			name:  "excludes overnight tail",
			now:   time.Date(2026, 3, 3, 3, 0, 0, 0, time.UTC),
			sched: &config.SchedulerConfig{Name: "excluded-overnight", StartTime: "22:00:00", StopTime: "06:00:00", DailyExclude: true},
			want:  false,
		},
		{
			name:  "excludes daily all-day window",
			now:   time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
			sched: &config.SchedulerConfig{Name: "excluded-all-day", AllDay: true, DailyExclude: true},
			want:  false,
		},
		{
			name:  "daily window remains active when not excluded",
			now:   time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
			sched: &config.SchedulerConfig{Name: "ordinary", StartTime: "09:00:00", StopTime: "17:00:00"},
			want:  true,
		},
		{
			name: "daily exclude overrides weekday fallback window",
			now:  time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
			sched: &config.SchedulerConfig{
				Name:         "excluded",
				StartTime:    "09:00:00",
				StopTime:     "17:00:00",
				DailyExclude: true,
				Days: map[string]*config.SchedulerDayWindow{
					"tuesday": {StartTime: "09:00:00", StopTime: "17:00:00"},
				},
			},
			want: false,
		},
	}
	for _, tc := range probes {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWithinWindow(tc.now, tc.sched); got != tc.want {
				t.Errorf("isWithinWindow() = %v, want %v", got, tc.want)
			}
		})
	}
}
