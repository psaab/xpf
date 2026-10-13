package config_test

// #12822: schedulerWindowFromNode parses a daily `exclude` into
// SchedulerDayWindow.Exclude, but compileSchedulers' daily arm copied only
// StartTime, StopTime, and AllDay into SchedulerConfig, which has no daily
// exclude carrier. Runtime checks Exclude on the effective daily window to
// suppress it, so `daily { exclude; start-time ...; stop-time ...; }`
// (and every other daily exclude spelling) silently compiled into an
// ACTIVE daily window: the excluded window was inverted into an active
// window. Weekday arms already preserved Exclude; daily must too.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func dailyExcludeSched12822(t *testing.T, cfg *config.Config) *config.SchedulerConfig {
	t.Helper()
	s := cfg.Schedulers["S"]
	if s == nil {
		t.Fatalf("scheduler S missing: %+v", cfg.Schedulers)
	}
	return s
}

func TestSchedulerDailyExcludeCompiled12822(t *testing.T) {
	t.Run("hierarchical exclude with window", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S {
        daily {
            exclude;
            start-time 09:00:00;
            stop-time 17:00:00;
        }
    }
}`)
		s := dailyExcludeSched12822(t, cfg)
		if !s.DailyExclude {
			t.Fatalf("daily exclude dropped at compile: %+v", s)
		}
		if s.StartTime != "09:00:00" || s.StopTime != "17:00:00" || s.AllDay {
			t.Fatalf("daily exclude window bounds changed: %+v", s)
		}
	})

	t.Run("hierarchical exclude only", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { daily { exclude; } }
}`)
		s := dailyExcludeSched12822(t, cfg)
		if !s.DailyExclude {
			t.Fatalf("bare daily exclude dropped at compile: %+v", s)
		}
	})

	t.Run("hierarchical packed daily exclude", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { daily exclude; }
}`)
		s := dailyExcludeSched12822(t, cfg)
		if !s.DailyExclude {
			t.Fatalf("packed daily exclude dropped at compile: %+v", s)
		}
	})

	t.Run("flat set exclude with window", func(t *testing.T) {
		cfg := compileFlat(t,
			"set schedulers scheduler S daily exclude",
			"set schedulers scheduler S daily start-time 09:00:00",
			"set schedulers scheduler S daily stop-time 17:00:00",
		)
		s := dailyExcludeSched12822(t, cfg)
		if !s.DailyExclude {
			t.Fatalf("flat-set daily exclude dropped at compile: %+v", s)
		}
		if s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
			t.Fatalf("flat-set daily window bounds changed: %+v", s)
		}
	})

	t.Run("non-excluded daily window untouched", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } }
}`)
		s := dailyExcludeSched12822(t, cfg)
		if s.DailyExclude {
			t.Fatalf("window-only daily must not gain an exclude: %+v", s)
		}
	})

	t.Run("daily all-day untouched", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { daily all-day; }
}`)
		s := dailyExcludeSched12822(t, cfg)
		if s.DailyExclude || !s.AllDay {
			t.Fatalf("daily all-day changed: %+v", s)
		}
	})
}
