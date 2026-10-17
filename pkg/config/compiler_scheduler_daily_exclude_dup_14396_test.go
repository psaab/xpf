package config_test

// #14396: a duplicate `daily` stanza ASSIGNED (not OR'd) DailyExclude, so
// `daily { exclude; }` followed by `daily { start-time ...; stop-time ...; }`
// (or the reverse, or duplicate scheduler instances, or a group-provided
// exclude plus a local window) compiled to DailyExclude=false: a scheduler
// Junos says is never active became active in its window. The weekday arm
// in the same function already ORs Exclude; AllDay in the daily arm already
// ORs too. Only the DailyExclude assignment broke the pattern.
//
// FAIL-ON-REVERT: restoring `sched.DailyExclude = win.Exclude` drops the
// exclude whenever a window-only daily stanza is seen after the exclude
// stanza and every case below goes RED (except the reverse-order control,
// which pins that ordering alone does not manufacture an exclude).

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func dailyDupSched14396(t *testing.T, cfg *config.Config) *config.SchedulerConfig {
	t.Helper()
	s := cfg.Schedulers["S"]
	if s == nil {
		t.Fatalf("scheduler S missing: %+v", cfg.Schedulers)
	}
	return s
}

func checkDailyExclude14396(t *testing.T, cfg *config.Config) {
	t.Helper()
	s := dailyDupSched14396(t, cfg)
	if !s.DailyExclude {
		t.Fatalf("duplicate daily dropped exclude (never-active became active): %+v", s)
	}
	if s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
		t.Fatalf("duplicate daily window bounds not preserved: %+v", s)
	}
	if !s.Daily {
		t.Fatalf("duplicate daily lost recurrence flag: %+v", s)
	}
}

func TestSchedulerDailyExcludeDuplicateStanza14396(t *testing.T) {
	t.Run("exclude then window same scheduler block", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S {
        daily { exclude; }
        daily { start-time 09:00:00; stop-time 17:00:00; }
    }
}`)
		checkDailyExclude14396(t, cfg)
	})

	t.Run("window then exclude same scheduler block", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S {
        daily { start-time 09:00:00; stop-time 17:00:00; }
        daily { exclude; }
    }
}`)
		checkDailyExclude14396(t, cfg)
	})

	t.Run("duplicate scheduler instances exclude first", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { daily { exclude; } }
    scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } }
}`)
		checkDailyExclude14396(t, cfg)
	})

	t.Run("duplicate scheduler instances window first", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } }
    scheduler S { daily { exclude; } }
}`)
		checkDailyExclude14396(t, cfg)
	})

	t.Run("hierarchical group exclude plus local window", func(t *testing.T) {
		cfg := compileHier(t, `groups {
    G { schedulers { scheduler S { daily { exclude; } } } }
}
schedulers {
    scheduler S {
        apply-groups G;
        daily { start-time 09:00:00; stop-time 17:00:00; }
    }
}`)
		checkDailyExclude14396(t, cfg)
	})

	t.Run("group exclude plus local window", func(t *testing.T) {
		cfg := compileFlat(t,
			"set groups G schedulers scheduler S daily exclude",
			"set schedulers scheduler S apply-groups G",
			"set schedulers scheduler S daily start-time 09:00:00",
			"set schedulers scheduler S daily stop-time 17:00:00",
		)
		checkDailyExclude14396(t, cfg)
	})

	t.Run("group window plus local exclude", func(t *testing.T) {
		cfg := compileFlat(t,
			"set groups G schedulers scheduler S daily start-time 09:00:00",
			"set groups G schedulers scheduler S daily stop-time 17:00:00",
			"set schedulers scheduler S apply-groups G",
			"set schedulers scheduler S daily exclude",
		)
		checkDailyExclude14396(t, cfg)
	})

	// Controls: a window-only duplicate must not manufacture an exclude,
	// and a single exclude-only daily still excludes (existing #12822).
	t.Run("window-only duplicates gain no exclude", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S {
        daily { start-time 09:00:00; }
        daily { stop-time 17:00:00; }
    }
}`)
		s := dailyDupSched14396(t, cfg)
		if s.DailyExclude {
			t.Fatalf("window-only daily gained an exclude: %+v", s)
		}
		if s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
			t.Fatalf("window-only daily bounds changed: %+v", s)
		}
	})
}
