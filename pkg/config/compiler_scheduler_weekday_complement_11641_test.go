package config_test

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSchedulerWeekdayComplementaryFragments11641(t *testing.T) {
	const firstStart = `schedulers {
    scheduler S {
        sunday { start-time 09:00:00; }
    }
    scheduler S {
        sunday { stop-time 17:00:00; }
    }
}`
	const firstStop = `schedulers {
    scheduler S {
        sunday { stop-time 17:00:00; }
    }
    scheduler S {
        sunday { start-time 09:00:00; }
    }
}`
	const combined = `schedulers {
    scheduler S {
        sunday { start-time 09:00:00; stop-time 17:00:00; }
    }
}`

	assertWindow := func(t *testing.T, cfg *config.Config, wantStart, wantStop string) {
		t.Helper()
		sched := cfg.Schedulers["S"]
		if sched == nil || sched.Days["sunday"] == nil {
			t.Fatalf("compiled schedule has no Sunday window: %+v", sched)
		}
		window := sched.Days["sunday"]
		if window.StartTime != wantStart || window.StopTime != wantStop {
			t.Fatalf("Sunday window = %q..%q, want %q..%q", window.StartTime, window.StopTime, wantStart, wantStop)
		}
	}

	for _, tc := range []struct {
		name string
		text string
	}{
		{name: "start then stop", text: firstStart},
		{name: "stop then start", text: firstStop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertWindow(t, compileHier(t, tc.text), "09:00:00", "17:00:00")
		})
	}
	t.Run("combined weekday control", func(t *testing.T) {
		assertWindow(t, compileHier(t, combined), "09:00:00", "17:00:00")
	})
	t.Run("flat-set control", func(t *testing.T) {
		assertWindow(t, compileFlat(t,
			"set schedulers scheduler S sunday start-time 09:00:00",
			"set schedulers scheduler S sunday stop-time 17:00:00",
		), "09:00:00", "17:00:00")
	})
	t.Run("daily control", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { daily { start-time 09:00:00; } }
    scheduler S { daily { stop-time 17:00:00; } }
}`)
		sched := cfg.Schedulers["S"]
		if sched == nil || !sched.Daily || sched.StartTime != "09:00:00" || sched.StopTime != "17:00:00" {
			t.Fatalf("daily control = %+v, want daily 09:00:00..17:00:00", sched)
		}
	})
	t.Run("weekday flags survive complementary fragments", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { sunday { all-day; exclude; } }
    scheduler S { sunday { start-time 09:00:00; } }
}`)
		window := cfg.Schedulers["S"].Days["sunday"]
		if window == nil || !window.AllDay || !window.Exclude || window.StartTime != "09:00:00" {
			t.Fatalf("weekday flags or boundary were lost across fragments: %+v", window)
		}
	})
}
