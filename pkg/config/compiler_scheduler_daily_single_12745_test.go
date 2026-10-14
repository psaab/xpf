package config_test

// #12745: a daily window may not combine all-day with a complete
// start-time/stop-time window. #12643 rejected that contradiction for
// weekday overrides, but the daily window shares the same runtime path
// (scheduler checks AllDay before time bounds), so `daily { all-day;
// start-time ...; stop-time ...; }` committed and silently enforced the
// policy all day. Strict compilation rejects; tolerant compilation warns
// and keeps the union window, exactly as for #12643 weekdays.
//
// Scope mirrors #12643: all-day with only a partial pair stays valid
// (#11641 complementary fragments), as do all-day alone, a window alone,
// exclude with a window, and repeated daily statements whose scalar
// last-wins composition resolves to a single meaning (#12238).

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const flagWindow12745 = "combines all-day with a complete start-time/stop-time window"

func assertDiagnostic12745(t *testing.T, label, message string) {
	t.Helper()
	if !strings.Contains(message, `scheduler "S"`) || !strings.Contains(message, "daily") ||
		!strings.Contains(message, "#12745") || !strings.Contains(message, flagWindow12745) {
		t.Fatalf("%s = %q, want a #12745 diagnostic naming scheduler S, daily, and the flag/window contradiction", label, message)
	}
}

func rejectAndWarnUnion12745(t *testing.T, tree *config.ConfigTree) *config.SchedulerConfig {
	t.Helper()
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted a daily flag/window contradiction, want a #12745 rejection")
	} else {
		assertDiagnostic12745(t, "strict error", err.Error())
	}
	compiled, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	var warning string
	for _, candidate := range compiled.Warnings {
		if strings.Contains(candidate, "#12745") {
			warning = candidate
			break
		}
	}
	assertDiagnostic12745(t, "tolerant warning", warning)
	sched := compiled.Schedulers["S"]
	if sched == nil {
		t.Fatalf("scheduler S missing: %+v", compiled.Schedulers)
	}
	return sched
}

func TestSchedulerDailySingleStatementContradictionReject12745(t *testing.T) {
	groupMerged := parseWeekdayConfig12238(t, `groups { g1 {
    schedulers { scheduler S { daily all-day; } }
} }
apply-groups g1;
schedulers { scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } } }
`)

	peerOnlyGroup := parseWeekdayConfig12238(t, `groups {
    node0 {
        schedulers { scheduler S { daily all-day; } }
    }
    node1 { system { host-name node1; } }
}
apply-groups "${node}";
schedulers { scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } } }
`)

	loadMergedIntoContainer := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { all-day; } }
}`)
	for _, command := range []string{
		"set schedulers scheduler S daily start-time 09:00:00",
		"set schedulers scheduler S daily stop-time 17:00:00",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("parse load-merge command %q: %v", command, err)
		}
		if err := loadMergedIntoContainer.SetPath(path); err != nil {
			t.Fatalf("apply load-merge command %q: %v", command, err)
		}
	}

	rows := []struct {
		name string
		tree *config.ConfigTree
	}{
		{"authored one statement all-day", parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { all-day; start-time 09:00:00; stop-time 17:00:00; } }
}`)},
		{"authored one statement all-day and exclude", parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { all-day; exclude; start-time 09:00:00; stop-time 17:00:00; } }
}`)},
		{"W5 group-inherited all-day plus inline window", groupMerged},
		{"load merge into an all-day container", loadMergedIntoContainer},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			sched := rejectAndWarnUnion12745(t, row.tree)
			if !sched.AllDay || sched.StartTime != "09:00:00" || sched.StopTime != "17:00:00" {
				t.Fatalf("tolerant compile must keep the union window, got %+v", sched)
			}
		})
	}

	t.Run("W3 flat set", func(t *testing.T) {
		tree := &config.ConfigTree{}
		for _, command := range []string{
			"set schedulers scheduler S daily all-day",
			"set schedulers scheduler S daily start-time 09:00:00",
			"set schedulers scheduler S daily stop-time 17:00:00",
		} {
			path, err := config.ParseSetCommand(command)
			if err != nil {
				t.Fatalf("parse flat command %q: %v", command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("apply flat command %q: %v", command, err)
			}
		}
		sched := rejectAndWarnUnion12745(t, tree)
		if !sched.AllDay || sched.StartTime != "09:00:00" || sched.StopTime != "17:00:00" {
			t.Fatalf("tolerant compile must keep the union window, got %+v", sched)
		}
	})

	t.Run("GR6 node entry points", func(t *testing.T) {
		for _, nodeID := range []int{0, 1} {
			_, err := config.CompileConfigForNode(peerOnlyGroup, nodeID)
			if err == nil {
				t.Fatalf("node%d strict compile accepted a peer-only daily contradiction", nodeID)
			}
			assertDiagnostic12745(t, "node strict error", err.Error())
		}
		compiled, err := config.CompileConfigForNodeLenient(peerOnlyGroup, 0)
		if err != nil {
			t.Fatalf("node0 tolerant compile: %v", err)
		}
		var warning string
		for _, candidate := range compiled.Warnings {
			if strings.Contains(candidate, "#12745") {
				warning = candidate
				break
			}
		}
		assertDiagnostic12745(t, "node0 tolerant warning", warning)
		sched := compiled.Schedulers["S"]
		if sched == nil || !sched.AllDay || sched.StartTime != "09:00:00" || sched.StopTime != "17:00:00" {
			t.Fatalf("node0 tolerant compile must keep union window, got %+v", sched)
		}
	})

	// Legacy direct scheduler leaves compose the same daily scalars, so a
	// direct complete window plus a daily all-day statement is the same
	// contradiction.
	t.Run("daily all-day plus legacy direct window", func(t *testing.T) {
		sched := rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; start-time 09:00:00; stop-time 17:00:00; }
}`))
		if !sched.AllDay || sched.StartTime != "09:00:00" || sched.StopTime != "17:00:00" {
			t.Fatalf("tolerant compile must keep the union window, got %+v", sched)
		}
	})
}

func TestSchedulerDailySingleStatementControls12745(t *testing.T) {
	accept := func(t *testing.T, tree *config.ConfigTree) *config.Config {
		t.Helper()
		compiled, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("control must compile strictly: %v", err)
		}
		for _, warning := range compiled.Warnings {
			if strings.Contains(warning, "#12745") {
				t.Fatalf("control must not raise a #12745 warning: %q", warning)
			}
		}
		return compiled
	}

	t.Run("all-day only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers { scheduler S { daily all-day; } }`))
		if s := cfg.Schedulers["S"]; s == nil || !s.AllDay || s.StartTime != "" || s.StopTime != "" {
			t.Fatalf("all-day-only daily window changed: %+v", s)
		}
	})
	t.Run("window only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } }
}`))
		if s := cfg.Schedulers["S"]; s == nil || s.AllDay || s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
			t.Fatalf("window-only daily window changed: %+v", s)
		}
	})
	t.Run("flag with partial start only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { all-day; start-time 09:00:00; } }
}`))
		if s := cfg.Schedulers["S"]; s == nil || !s.AllDay || s.StartTime != "09:00:00" || s.StopTime != "" {
			t.Fatalf("partial daily window changed: %+v", s)
		}
	})
	t.Run("flag with partial stop only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { all-day; stop-time 17:00:00; } }
}`))
		if s := cfg.Schedulers["S"]; s == nil || !s.AllDay || s.StartTime != "" || s.StopTime != "17:00:00" {
			t.Fatalf("partial daily window changed: %+v", s)
		}
	})
	t.Run("exclude with complete window", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { exclude; start-time 09:00:00; stop-time 17:00:00; } }
}`))
		if s := cfg.Schedulers["S"]; s == nil || s.AllDay {
			t.Fatalf("exclude daily window changed: %+v", s)
		}
	})
	t.Run("daily all-day with weekday window distinct", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; monday { start-time 09:00:00; stop-time 17:00:00; } }
}`))
		if s := cfg.Schedulers["S"]; s == nil || !s.AllDay || s.StartTime != "" || s.StopTime != "" {
			t.Fatalf("daily all-day changed: %+v", s)
		}
		if w := cfg.Schedulers["S"].Days["monday"]; w == nil || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("weekday window changed: %+v", w)
		}
	})
	t.Run("legacy direct window only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { start-time 09:00:00; stop-time 17:00:00; }
}`))
		if s := cfg.Schedulers["S"]; s == nil || s.AllDay || s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
			t.Fatalf("legacy direct window changed: %+v", s)
		}
	})
	t.Run("later daily window retains prior all-day and rejects", func(t *testing.T) {
		sched := rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; daily { start-time 09:00:00; stop-time 17:00:00; } }
}`))
		if !sched.AllDay || sched.StartTime != "09:00:00" || sched.StopTime != "17:00:00" {
			t.Fatalf("tolerant compile must keep the union window, got %+v", sched)
		}
	})
}
