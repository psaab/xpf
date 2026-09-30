package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func repeatedSchedulerWindowConfig11358(t *testing.T, day string) *config.ConfigTree {
	t.Helper()
	text := "schedulers { scheduler S { " + day + " { " +
		"start-time 09:00:00; stop-time 12:00:00; " +
		"start-time 16:00:00; stop-time 17:00:00; " +
		"} } }"
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func TestSchedulerRepeatedWindowPairRejectedOrWarned11358(t *testing.T) {
	for _, day := range []string{"daily", "sunday"} {
		t.Run(day, func(t *testing.T) {
			tree := repeatedSchedulerWindowConfig11358(t, day)
			if _, err := config.CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "#11358") || !strings.Contains(err.Error(), day) {
				t.Fatalf("strict compile error = %v, want a #11358 repeated-window diagnostic naming %s", err, day)
			}

			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile should preserve bootability: %v", err)
			}
			found := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#11358") && strings.Contains(warning, day) &&
					strings.Contains(warning, "last value for each boundary") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient warnings = %v, want a #11358 repeated-window warning naming %s", cfg.Warnings, day)
			}
		})
	}
}

func TestSchedulerLegacyDailyRepeatedBoundariesRejected11358(t *testing.T) {
	const text = `schedulers {
    scheduler S {
        start-time 09:00:00;
        stop-time 12:00:00;
        start-time 16:00:00;
        stop-time 17:00:00;
    }
}`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "#11358") || !strings.Contains(err.Error(), "daily") {
		t.Fatalf("strict compile error = %v, want a #11358 daily-window diagnostic", err)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile should preserve bootability: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#11358") && strings.Contains(warning, "daily") {
			return
		}
	}
	t.Fatalf("lenient warnings = %v, want a #11358 daily-window warning", cfg.Warnings)
}

func TestSchedulerRepeatedIdenticalBoundariesRemainValid11358(t *testing.T) {
	const text = `schedulers {
    scheduler S {
        sunday {
            start-time 09:00:00;
            start-time 09:00:00;
            stop-time 17:00:00;
            stop-time 17:00:00;
        }
    }
}`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("identical repeated boundaries do not lose a distinct value: %v", err)
	}
	sched := cfg.Schedulers["S"]
	if sched == nil || sched.Days["sunday"] == nil {
		t.Fatalf("scheduler window was not compiled: %+v", sched)
	}
	window := sched.Days["sunday"]
	if window.StartTime != "09:00:00" || window.StopTime != "17:00:00" {
		t.Fatalf("identical repeated boundaries changed the window: %+v", window)
	}
}

func TestSchedulerDistinctWeekdayWindowsRemainValid11358(t *testing.T) {
	const text = `schedulers {
    scheduler S {
        sunday { start-time 09:00:00; stop-time 12:00:00; }
        monday { start-time 16:00:00; stop-time 17:00:00; }
    }
}`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("distinct weekday windows must remain valid: %v", err)
	}
	sched := cfg.Schedulers["S"]
	if sched == nil || sched.Days["sunday"] == nil || sched.Days["monday"] == nil {
		t.Fatalf("compiled scheduler lost a distinct weekday window: %+v", sched)
	}
	if got := sched.Days["sunday"].StartTime + ".." + sched.Days["sunday"].StopTime; got != "09:00:00..12:00:00" {
		t.Errorf("Sunday window = %q, want 09:00:00..12:00:00", got)
	}
	if got := sched.Days["monday"].StartTime + ".." + sched.Days["monday"].StopTime; got != "16:00:00..17:00:00" {
		t.Errorf("Monday window = %q, want 16:00:00..17:00:00", got)
	}
}

func TestSchedulerRepeatedWindowPairInheritedFromGroupRejected11358(t *testing.T) {
	const text = `groups {
    G {
        schedulers {
            scheduler S {
                sunday {
                    start-time 09:00:00;
                    stop-time 12:00:00;
                    start-time 16:00:00;
                    stop-time 17:00:00;
                }
            }
        }
    }
}
apply-groups G;
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "#11358") || !strings.Contains(err.Error(), "sunday") {
		t.Fatalf("strict compile error = %v, want a #11358 inherited Sunday-window diagnostic", err)
	}
}
