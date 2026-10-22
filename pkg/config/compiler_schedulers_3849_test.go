package config_test

// #3849: compileSchedulers must descend into the Junos `daily { start-time;
// stop-time; }` container and the per-day (monday..sunday) containers.
// Before the fix the `daily` arm only set the recurrence flag, leaving
// StartTime/StopTime empty, and the runtime evaluator then fell open to
// always-active. These tests pin the compile-side descend for both AST
// shapes; the runtime fail-closed half is pinned in pkg/scheduler.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileHier(t *testing.T, input string) *config.Config {
	t.Helper()
	p := config.NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func compileFlat(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestCompileSchedulerDailyBlockHierarchical is the core RED-on-revert: a
// `daily { start-time 09:00:00; stop-time 17:00:00; }` block must populate
// StartTime/StopTime. Reverting the daily descend leaves them empty and this
// goes RED.
func TestCompileSchedulerDailyBlockHierarchical(t *testing.T) {
	cfg := compileHier(t, `schedulers {
    scheduler biz {
        daily {
            start-time 09:00:00;
            stop-time 17:00:00;
        }
    }
}`)
	s := cfg.Schedulers["biz"]
	if s == nil {
		t.Fatal("scheduler biz not compiled")
	}
	if s.StartTime != "09:00:00" {
		t.Errorf("StartTime = %q, want 09:00:00 (daily block not descended)", s.StartTime)
	}
	if s.StopTime != "17:00:00" {
		t.Errorf("StopTime = %q, want 17:00:00 (daily block not descended)", s.StopTime)
	}
	if !s.Daily {
		t.Error("Daily flag not set for a daily{} block")
	}
}

// TestCompileSchedulerDailyBlockFlatSet pins the flat-set shape. Before
// #3849/F-013 (schedulers absent from setSchema) SetPath packed the whole
// `set` line onto one leaf and the compiler dropped it entirely.
func TestCompileSchedulerDailyBlockFlatSet(t *testing.T) {
	cfg := compileFlat(t,
		"set schedulers scheduler biz daily start-time 09:00:00",
		"set schedulers scheduler biz daily stop-time 17:00:00",
	)
	s := cfg.Schedulers["biz"]
	if s == nil {
		t.Fatal("scheduler biz not compiled from flat-set")
	}
	if s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
		t.Errorf("flat-set daily window = %q..%q, want 09:00:00..17:00:00", s.StartTime, s.StopTime)
	}
}

// TestCompileSchedulerDayOfWeek pins per-day (monday..sunday) descend in both
// shapes.
func TestCompileSchedulerDayOfWeek(t *testing.T) {
	hier := compileHier(t, `schedulers {
    scheduler week {
        monday {
            start-time 08:00:00;
            stop-time 12:00:00;
        }
        friday {
            exclude;
        }
    }
}`)
	s := hier.Schedulers["week"]
	if s == nil {
		t.Fatal("scheduler week not compiled")
	}
	mon := s.Days["monday"]
	if mon == nil {
		t.Fatal("monday window not compiled")
	}
	if mon.StartTime != "08:00:00" || mon.StopTime != "12:00:00" {
		t.Errorf("monday window = %q..%q, want 08:00:00..12:00:00", mon.StartTime, mon.StopTime)
	}
	fri := s.Days["friday"]
	if fri == nil || !fri.Exclude {
		t.Errorf("friday exclude not compiled: %+v", fri)
	}

	flat := compileFlat(t,
		"set schedulers scheduler week monday start-time 08:00:00",
		"set schedulers scheduler week monday stop-time 12:00:00",
	)
	fs := flat.Schedulers["week"]
	if fs == nil || fs.Days["monday"] == nil {
		t.Fatalf("flat-set day-of-week not compiled: %+v", fs)
	}
	if fs.Days["monday"].StartTime != "08:00:00" {
		t.Errorf("flat-set monday start = %q, want 08:00:00", fs.Days["monday"].StartTime)
	}
}

// TestCompileSchedulerDailyAllDay pins `daily all-day` in both shapes.
func TestCompileSchedulerDailyAllDay(t *testing.T) {
	hier := compileHier(t, `schedulers {
    scheduler always {
        daily all-day;
    }
}`)
	if s := hier.Schedulers["always"]; s == nil || !s.AllDay {
		t.Fatalf("hierarchical daily all-day not compiled: %+v", s)
	}

	flat := compileFlat(t, "set schedulers scheduler always daily all-day")
	if s := flat.Schedulers["always"]; s == nil || !s.AllDay {
		t.Fatalf("flat-set daily all-day not compiled: %+v", s)
	}
}

// TestCompileSchedulerLegacyDirectChildren pins backward compatibility with
// the pre-#3849 simplified shape where start-time/stop-time are direct
// children of the scheduler (no daily block).
func TestCompileSchedulerLegacyDirectChildren(t *testing.T) {
	cfg := compileHier(t, `schedulers {
    scheduler legacy {
        start-time 09:00:00;
        stop-time 17:00:00;
        daily;
    }
}`)
	s := cfg.Schedulers["legacy"]
	if s == nil {
		t.Fatal("scheduler legacy not compiled")
	}
	if s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
		t.Errorf("legacy direct-child window = %q..%q, want 09:00:00..17:00:00", s.StartTime, s.StopTime)
	}
}

// TestSchemaRejectsBadSchedulerTime is the commit-time fail-closed half: a
// malformed start-time is rejected at commit (SchemaValidate) instead of
// silently zeroing the window.
func TestSchemaRejectsBadSchedulerTime(t *testing.T) {
	p := config.NewParser(`schedulers {
    scheduler biz {
        daily {
            start-time 9am;
            stop-time 17:00:00;
        }
    }
}`)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if err := config.SchemaValidate(tree); err == nil {
		t.Fatal("SchemaValidate accepted an invalid start-time (9am); expected commit rejection")
	}
}

// TestSchemaAcceptsValidScheduler ensures a well-formed scheduler passes the
// commit gate.
func TestSchemaAcceptsValidScheduler(t *testing.T) {
	p := config.NewParser(`schedulers {
    scheduler biz {
        daily {
            start-time 09:00:00;
            stop-time 17:00:00;
        }
    }
}`)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if err := config.SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected a valid scheduler: %v", err)
	}
}
