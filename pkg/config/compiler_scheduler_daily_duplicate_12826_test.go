package config_test

// #12826: duplicate `daily` stanzas dropped an earlier all-day flag in
// both the compiler and the #11358/#12745 collector, so `daily all-day;
// daily { start-time ...; stop-time ...; }` silently committed as a plain
// timed window instead of raising the #12745 contradiction already raised
// for one stanza. The weekday compiler arm has always accumulated all-day
// flags with sticky OR; daily did not.

// The collector also inspects a `stop-time` modifier nested under (or
// packed onto) a `start-time` statement in its root, daily, and weekday
// scans. The compiler extracts that modifier for root legacy leaves
// (#12637), so validation must account for it wherever encountered.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func dailyUnion12826(t *testing.T, sched *config.SchedulerConfig) {
	t.Helper()
	if sched == nil || !sched.AllDay || sched.StartTime != "09:00:00" || sched.StopTime != "17:00:00" {
		t.Fatalf("tolerant compile must keep the union daily window, got %+v", sched)
	}
}

func TestSchedulerDailyDuplicateAllDayReject12826(t *testing.T) {
	t.Run("same block all-day then window", func(t *testing.T) {
		dailyUnion12826(t, rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; daily { start-time 09:00:00; stop-time 17:00:00; } }
}`)))
	})
	t.Run("same block window then all-day", func(t *testing.T) {
		dailyUnion12826(t, rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } daily all-day; }
}`)))
	})
	t.Run("duplicate scheduler instances", func(t *testing.T) {
		dailyUnion12826(t, rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; }
    scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } }
}`)))
	})
	t.Run("split boundaries complete the window", func(t *testing.T) {
		dailyUnion12826(t, rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; daily { start-time 09:00:00; } daily { stop-time 17:00:00; } }
}`)))
	})
	t.Run("group merged all-day plus inline window", func(t *testing.T) {
		dailyUnion12826(t, rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `groups { g1 {
    schedulers { scheduler S { daily all-day; } }
} }
apply-groups g1;
schedulers { scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } } }
`)))
	})
	t.Run("flat set window then all-day", func(t *testing.T) {
		tree := &config.ConfigTree{}
		for _, command := range []string{
			"set schedulers scheduler S daily start-time 09:00:00",
			"set schedulers scheduler S daily stop-time 17:00:00",
			"set schedulers scheduler S daily all-day",
		} {
			path, err := config.ParseSetCommand(command)
			if err != nil {
				t.Fatalf("parse flat command %q: %v", command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("apply flat command %q: %v", command, err)
			}
		}
		dailyUnion12826(t, rejectAndWarnUnion12745(t, tree))
	})
}

func TestSchedulerDailyDuplicateControls12826(t *testing.T) {
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

	t.Run("all-day twice hierarchical", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; daily all-day; }
}`))
		if s := cfg.Schedulers["S"]; s == nil || !s.AllDay || s.StartTime != "" || s.StopTime != "" {
			t.Fatalf("repeated all-day changed: %+v", s)
		}
	})
	t.Run("all-day twice flat", func(t *testing.T) {
		tree := &config.ConfigTree{}
		for _, command := range []string{
			"set schedulers scheduler S daily all-day",
			"set schedulers scheduler S daily all-day",
		} {
			path, err := config.ParseSetCommand(command)
			if err != nil {
				t.Fatalf("parse flat command %q: %v", command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("apply flat command %q: %v", command, err)
			}
		}
		cfg := accept(t, tree)
		if s := cfg.Schedulers["S"]; s == nil || !s.AllDay || s.StartTime != "" || s.StopTime != "" {
			t.Fatalf("repeated flat all-day changed: %+v", s)
		}
	})
	t.Run("identical window twice", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } daily { start-time 09:00:00; stop-time 17:00:00; } }
}`))
		if s := cfg.Schedulers["S"]; s == nil || s.AllDay || s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
			t.Fatalf("repeated identical window changed: %+v", s)
		}
	})
}

func TestSchedulerNestedStopTimeModifier12826(t *testing.T) {
	t.Run("root start-time child stop-time completes daily contradiction", func(t *testing.T) {
		dailyUnion12826(t, rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; start-time 09:00:00 { stop-time 17:00:00; } }
}`)))
	})
	t.Run("root packed stop-time completes daily contradiction", func(t *testing.T) {
		dailyUnion12826(t, rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily all-day; start-time 09:00:00 stop-time 17:00:00; }
}`)))
	})
	t.Run("daily start-time child stop-time completes contradiction", func(t *testing.T) {
		dailyUnion12826(t, rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { all-day; start-time 09:00:00 { stop-time 17:00:00; } } }
}`)))
	})
	t.Run("weekday start-time child stop-time completes contradiction", func(t *testing.T) {
		tree := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday all-day; monday { start-time 09:00:00 { stop-time 17:00:00; } } }
}`)
		if _, err := config.CompileConfig(tree); err == nil {
			t.Fatal("strict compile accepted a weekday flag/window contradiction hidden by a nested stop-time, want a #12238/#12643 rejection")
		} else if !strings.Contains(err.Error(), "#12238") && !strings.Contains(err.Error(), "#12643") {
			t.Fatalf("strict error = %q, want a #12238 or #12643 diagnostic", err.Error())
		}
		compiled, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant compile: %v", err)
		}
		found := false
		for _, warning := range compiled.Warnings {
			if strings.Contains(warning, "#12238") || strings.Contains(warning, "#12643") {
				found = true
			}
		}
		if !found {
			t.Fatalf("tolerant warnings = %v, want a #12238 or #12643 diagnostic", compiled.Warnings)
		}
		w := compiled.Schedulers["S"].Days["monday"]
		if w == nil || !w.AllDay || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("tolerant compile must keep the union weekday window, got %+v", w)
		}
	})
	t.Run("weekday nested stop-time alone compiles complete window", func(t *testing.T) {
		cfg, err := config.CompileConfig(parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { start-time 09:00:00 { stop-time 17:00:00; } } }
}`))
		if err != nil {
			t.Fatalf("nested stop-time window must compile strictly: %v", err)
		}
		w := cfg.Schedulers["S"].Days["monday"]
		if w == nil || w.AllDay || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("nested stop-time window changed: %+v", w)
		}
	})
	t.Run("daily nested stop-time alone compiles complete window", func(t *testing.T) {
		cfg, err := config.CompileConfig(parseWeekdayConfig12238(t, `schedulers {
    scheduler S { daily { start-time 09:00:00 { stop-time 17:00:00; } } }
}`))
		if err != nil {
			t.Fatalf("nested stop-time daily window must compile strictly: %v", err)
		}
		s := cfg.Schedulers["S"]
		if s == nil || s.AllDay || s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
			t.Fatalf("nested stop-time daily window changed: %+v", s)
		}
	})
}
func TestSchedulerNestedStopTimeRepeatReject12826(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{
			name: "root",
			text: `schedulers {
    scheduler S { start-time 09:00:00 { stop-time 17:00:00; } stop-time 18:00:00; }
}`,
		},
		{
			name: "daily",
			text: `schedulers {
    scheduler S { daily { start-time 09:00:00 { stop-time 17:00:00; } stop-time 18:00:00; } }
}`,
		},
		{
			name: "weekday",
			text: `schedulers {
    scheduler S { monday { start-time 09:00:00 { stop-time 17:00:00; } stop-time 18:00:00; } }
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseWeekdayConfig12238(t, tc.text)
			if _, err := config.CompileConfig(tree); err == nil {
				t.Fatal("strict compile accepted conflicting nested and direct stop-time values, want #11358 rejection")
			} else if !strings.Contains(err.Error(), "#11358") {
				t.Fatalf("strict error = %q, want a #11358 diagnostic", err.Error())
			}
			compiled, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, "#11358") {
					return
				}
			}
			t.Fatalf("tolerant warnings = %v, want #11358 diagnostic", compiled.Warnings)
		})
	}
}
