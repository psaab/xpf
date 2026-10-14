package config_test

// #12942: a day container's inline stop-time modifier (`start-time X {
// stop-time Y; }`, the braced twin of the #8939 flat run `day start-time X
// stop-time Y`) must stay inside the day window. The scheduler-level run
// expansion hoisted it out as if it were a scheduler statement, so
// `tuesday { start-time 09:00:00 { stop-time 17:00:00; } }` compiled a scalar
// StopTime=17:00:00 with no scalar StartTime: every non-Tuesday tick hit the
// incomplete-window fail-closed warn, a daily window beside it was corrupted
// on the tolerant path (stop rewritten to the weekday's), and the legitimate
// daily+weekday pair strict-rejected as an #11358 daily repeat nobody wrote.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// assertScalar12942 pins the scheduler-level scalar window: it must carry
// only what a scheduler-level or daily statement put there.
func assertScalar12942(t *testing.T, sched *config.SchedulerConfig, wantStart, wantStop string) {
	t.Helper()
	if sched == nil {
		t.Fatal("scheduler S missing (#12942)")
	}
	if sched.StartTime != wantStart || sched.StopTime != wantStop {
		t.Fatalf("scheduler scalar window = (%q, %q), want (%q, %q) — a weekday inline stop-time leaked into the scheduler scalar (#12942)",
			sched.StartTime, sched.StopTime, wantStart, wantStop)
	}
}

func compileStrict12942(t *testing.T, text string) *config.Config {
	t.Helper()
	tree := parseWeekdayConfig12238(t, text)
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func compileFlat12942(t *testing.T, commands ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// The issue repro, across every weekday container (they share one schema).
func TestSchedulerWeekdayInlineStopStaysInDay12942(t *testing.T) {
	for _, day := range []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"} {
		t.Run(day, func(t *testing.T) {
			cfg := compileStrict12942(t, "schedulers {\n    scheduler S { "+day+
				" { start-time 09:00:00 { stop-time 17:00:00; } } }\n}")
			assertScalar12942(t, cfg.Schedulers["S"], "", "")
			w := cfg.Schedulers["S"].Days[day]
			if w == nil || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" || w.AllDay || w.Exclude {
				t.Fatalf("%s window = %+v, want the complete 09:00:00-17:00:00 pair (#12942)", day, w)
			}
		})
	}
}

// The same chain in flat-set spelling: SetPath nests stop-time under the
// day's start-time identically, so the leak must be absent there too.
func TestSchedulerWeekdayInlineStopFlatSetStaysInDay12942(t *testing.T) {
	cfg := compileFlat12942(t,
		"set schedulers scheduler S tuesday start-time 09:00:00 stop-time 17:00:00")
	assertScalar12942(t, cfg.Schedulers["S"], "", "")
	w := cfg.Schedulers["S"].Days["tuesday"]
	if w == nil || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
		t.Fatalf("tuesday window = %+v, want the complete pair from the flat chain (#12942)", w)
	}
}

// A weekday inline stop-time must not rewrite the daily window the operator
// authored beside it, and the pair must not strict-reject as an #11358 daily
// repeat. On the tolerant path (boot load, HA sync) the rewritten daily stop
// was the fail-open half: every day but Tuesday stayed active until 17:00.
func TestSchedulerWeekdayInlineStopDoesNotCorruptDaily12942(t *testing.T) {
	text := `schedulers {
    scheduler S {
        daily { start-time 08:00:00; stop-time 16:00:00; }
        tuesday { start-time 09:00:00 { stop-time 17:00:00; } }
    }
}`
	cfg := compileStrict12942(t, text)
	assertScalar12942(t, cfg.Schedulers["S"], "08:00:00", "16:00:00")
	w := cfg.Schedulers["S"].Days["tuesday"]
	if w == nil || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
		t.Fatalf("tuesday window = %+v, want the weekday's own 09:00:00-17:00:00 pair (#12942)", w)
	}

	compiled, err := config.CompileConfigLenient(parseWeekdayConfig12238(t, text))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	for _, warning := range compiled.Warnings {
		if strings.Contains(warning, "#11358") {
			t.Fatalf("tolerant compile raised a phantom #11358 repeat: %q (#12942)", warning)
		}
	}
	assertScalar12942(t, compiled.Schedulers["S"], "08:00:00", "16:00:00")
}

// A scheduler-level start-time alone is an incomplete daily scalar that fails
// closed at runtime; the weekday's stop-time must not silently complete it
// into an 08:00-17:00 daily window (fail open on every non-Tuesday).
func TestSchedulerWeekdayInlineStopDoesNotCompleteScalarStart12942(t *testing.T) {
	cfg := compileStrict12942(t, `schedulers {
    scheduler S {
        start-time 08:00:00;
        tuesday { start-time 09:00:00 { stop-time 17:00:00; } }
    }
}`)
	assertScalar12942(t, cfg.Schedulers["S"], "08:00:00", "")
}
