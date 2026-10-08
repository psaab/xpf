package config_test

// #12238: weekday scheduler merge was sticky-OR for AllDay/Exclude
// (compiler_system.go: `w.AllDay = w.AllDay || win.AllDay`). A repeated
// Monday all-day block followed by a specific Monday 09:00-17:00 window
// stayed all-day — and AllDay is checked first at runtime
// (pkg/scheduler isWithinWindow) — widening a time-limited permit. An
// earlier exclude likewise could never be superseded.
//
// The fix: a later weekday block stating a COMPLETE window (both
// start-time and stop-time) supersedes prior AllDay/Exclude flags, and a
// later explicit flag supersedes its contradiction. Partial time fragments
// still merge without disturbing flags (#11641): a lone start/stop boundary
// cannot express a contradictory window.
//
// FAIL-ON-REVERT: restoring the sticky-OR makes the all-day cell below
// stay all-day (AllDay=true with 09:00-17:00 bounds) and the exclude
// cell stay excluded — both go RED.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func weekdayWindow12238(t *testing.T, cfg *config.Config, day string) *config.SchedulerDayWindow {
	t.Helper()
	sched := cfg.Schedulers["S"]
	if sched == nil {
		t.Fatalf("scheduler S missing: %+v", cfg.Schedulers)
	}
	w := sched.Days[day]
	if w == nil {
		t.Fatalf("scheduler S has no %s window: %+v", day, sched.Days)
	}
	return w
}

// Regression cell: Monday all-day + Monday 09:00-17:00 is 09:00-17:00 only.
func TestSchedulerWeekdayCompleteWindowSupersedesAllDay_12238(t *testing.T) {
	cfg := compileHier(t, `schedulers {
    scheduler S {
        monday { all-day; }
    }
    scheduler S {
        monday { start-time 09:00:00; stop-time 17:00:00; }
    }
}`)
	w := weekdayWindow12238(t, cfg, "monday")
	if w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
		t.Fatalf("monday bounds = %q..%q, want 09:00:00..17:00:00 (%+v)", w.StartTime, w.StopTime, w)
	}
	if w.AllDay {
		t.Fatalf("later complete window must supersede prior all-day, got %+v", w)
	}
	if w.Exclude {
		t.Fatalf("exclude must stay clear, got %+v", w)
	}
}

// Exclude analog: Monday exclude + Monday 09:00-17:00 is 09:00-17:00 only.
func TestSchedulerWeekdayCompleteWindowSupersedesExclude_12238(t *testing.T) {
	cfg := compileHier(t, `schedulers {
    scheduler S {
        monday { exclude; }
    }
    scheduler S {
        monday { start-time 09:00:00; stop-time 17:00:00; }
    }
}`)
	w := weekdayWindow12238(t, cfg, "monday")
	if w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
		t.Fatalf("monday bounds = %q..%q, want 09:00:00..17:00:00 (%+v)", w.StartTime, w.StopTime, w)
	}
	if w.Exclude {
		t.Fatalf("later complete window must supersede prior exclude, got %+v", w)
	}
	if w.AllDay {
		t.Fatalf("all-day must stay clear, got %+v", w)
	}
}

// Bare contradictory flags supersede across blocks (last-wins), in both
// directions; a fragment stating BOTH flags keeps both (#8939 coexistence).
func TestSchedulerWeekdayLaterFlagSupersedesContradiction_12238(t *testing.T) {
	t.Run("all-day then exclude", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { monday { all-day; } }
    scheduler S { monday { exclude; } }
}`)
		w := weekdayWindow12238(t, cfg, "monday")
		if !w.Exclude || w.AllDay {
			t.Fatalf("later exclude must supersede prior all-day, got %+v", w)
		}
	})
	t.Run("exclude then all-day", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { monday { exclude; } }
    scheduler S { monday { all-day; } }
}`)
		w := weekdayWindow12238(t, cfg, "monday")
		if !w.AllDay || w.Exclude {
			t.Fatalf("later all-day must supersede prior exclude, got %+v", w)
		}
	})
	t.Run("both flags stated together keep both", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { monday { all-day; } }
    scheduler S { monday { all-day; exclude; } }
}`)
		w := weekdayWindow12238(t, cfg, "monday")
		if !w.AllDay || !w.Exclude {
			t.Fatalf("fragment stating both flags must keep both, got %+v", w)
		}
	})
}

// Reverse order: a later bare flag wins over an earlier bounded window
// (bounds are preserved like the daily arm, but AllDay/Exclude govern).
func TestSchedulerWeekdayLaterFlagWinsOverWindow_12238(t *testing.T) {
	t.Run("window then all-day", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } }
    scheduler S { monday { all-day; } }
}`)
		w := weekdayWindow12238(t, cfg, "monday")
		if !w.AllDay || w.Exclude {
			t.Fatalf("later all-day must win over earlier window, got %+v", w)
		}
	})
	t.Run("window then exclude", func(t *testing.T) {
		cfg := compileHier(t, `schedulers {
    scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } }
    scheduler S { monday { exclude; } }
}`)
		w := weekdayWindow12238(t, cfg, "monday")
		if !w.Exclude || w.AllDay {
			t.Fatalf("later exclude must win over earlier window, got %+v", w)
		}
	})
}

// Boundary guard: a PARTIAL fragment (one boundary, no flags) still merges
// without disturbing prior flags — pure overwrite (daily-arm style) would
// clear them and go RED here. Mirrors #11641.
func TestSchedulerWeekdayPartialFragmentPreservesFlags_12238(t *testing.T) {
	cfg := compileHier(t, `schedulers {
    scheduler S { monday { all-day; exclude; } }
    scheduler S { monday { start-time 09:00:00; } }
}`)
	w := weekdayWindow12238(t, cfg, "monday")
	if !w.AllDay || !w.Exclude || w.StartTime != "09:00:00" {
		t.Fatalf("partial fragment must preserve flags and add its boundary, got %+v", w)
	}
}

// Distinct-weekday control: the supersede touches only the repeated day.
func TestSchedulerWeekdaySupersedeLeavesOtherDays_12238(t *testing.T) {
	cfg := compileHier(t, `schedulers {
    scheduler S {
        monday { all-day; }
        tuesday { start-time 09:00:00; stop-time 17:00:00; }
    }
    scheduler S {
        monday { start-time 10:00:00; stop-time 12:00:00; }
    }
}`)
	m := weekdayWindow12238(t, cfg, "monday")
	if m.AllDay || m.StartTime != "10:00:00" || m.StopTime != "12:00:00" {
		t.Fatalf("monday must be the later window only, got %+v", m)
	}
	tu := weekdayWindow12238(t, cfg, "tuesday")
	if tu.AllDay || tu.Exclude || tu.StartTime != "09:00:00" || tu.StopTime != "17:00:00" {
		t.Fatalf("tuesday must be untouched, got %+v", tu)
	}
}
