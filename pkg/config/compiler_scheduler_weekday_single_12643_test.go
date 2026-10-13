package config_test

// #12643: a weekday's effective window may not combine all-day or exclude
// with a complete start/stop pair, no matter how the contributions were
// authored. #12238 rejected that combination only when the flag and the
// window sat in separate weekday statements; shapes that compose into one
// statement (a single authored block, flat `set`, `load merge`, or group
// inheritance merged into an inline window) still committed and, because
// runtime checks Exclude then AllDay before the time bounds, silently
// enforced the policy all day.
//
// Decision (this issue): REJECT, extending #12238. Strict compilation
// rejects; tolerant compilation warns and keeps the union window, exactly
// as for the split shapes. This flips the #10006/#11641-era acceptance of
// `monday { all-day; start-time ...; stop-time ...; }` (a flag next to only
// a PARTIAL pair keeps the #11641 complementary-fragment behavior).

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const flagWindow12643 = "combines all-day with a complete start-time/stop-time window"

func assertDiagnostic12643(t *testing.T, label, message string) {
	t.Helper()
	if !strings.Contains(message, `scheduler "S"`) || !strings.Contains(message, "monday") ||
		!strings.Contains(message, "#12643") || !strings.Contains(message, flagWindow12643) {
		t.Fatalf("%s = %q, want a #12643 diagnostic naming scheduler S, monday, and the flag/window contradiction", label, message)
	}
}

func rejectAndWarnUnion12643(t *testing.T, tree *config.ConfigTree) *config.SchedulerDayWindow {
	t.Helper()
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted a single-statement flag/window contradiction, want a #12643 rejection")
	} else {
		assertDiagnostic12643(t, "strict error", err.Error())
	}
	compiled, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	var warning string
	for _, candidate := range compiled.Warnings {
		if strings.Contains(candidate, "#12643") {
			warning = candidate
			break
		}
	}
	assertDiagnostic12643(t, "tolerant warning", warning)
	return weekdayWindow12238(t, compiled, "monday")
}

// W3/W5/GR6 plus the authored single-statement shape: every authoring path
// that composes the contradiction into one weekday statement must reject
// strictly and warn tolerantly while keeping the union window.
func TestSchedulerWeekdaySingleStatementContradictionReject12643(t *testing.T) {
	groupMerged := parseWeekdayConfig12238(t, `groups { g1 {
    schedulers { scheduler S { monday all-day; } }
} }
apply-groups g1;
schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }
`)

	peerOnlyGroup := parseWeekdayConfig12238(t, `groups {
    node0 {
        schedulers { scheduler S { monday all-day; } }
    }
    node1 { system { host-name node1; } }
}
apply-groups "${node}";
schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }
`)

	loadMergedIntoContainer := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { all-day; } }
}`)
	for _, command := range []string{
		"set schedulers scheduler S monday start-time 09:00:00",
		"set schedulers scheduler S monday stop-time 17:00:00",
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
    scheduler S { monday { all-day; start-time 09:00:00; stop-time 17:00:00; } }
}`)},
		{"authored one statement all-day and exclude", parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { all-day; exclude; start-time 09:00:00; stop-time 17:00:00; } }
}`)},
		{"W5 group-inherited all-day plus inline window", groupMerged},
		{"load merge into an all-day container", loadMergedIntoContainer},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			w := rejectAndWarnUnion12643(t, row.tree)
			if !w.AllDay && !w.Exclude || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
				t.Fatalf("tolerant compile must keep the union window, got %+v", w)
			}
		})
	}

	t.Run("W3 flat set", func(t *testing.T) {
		tree := &config.ConfigTree{}
		for _, command := range []string{
			"set schedulers scheduler S monday all-day",
			"set schedulers scheduler S monday start-time 09:00:00",
			"set schedulers scheduler S monday stop-time 17:00:00",
		} {
			path, err := config.ParseSetCommand(command)
			if err != nil {
				t.Fatalf("parse flat command %q: %v", command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("apply flat command %q: %v", command, err)
			}
		}
		w := rejectAndWarnUnion12643(t, tree)
		if !w.AllDay || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("tolerant compile must keep the union window, got %+v", w)
		}
	})

	// The node-specific entry points share the verdict: a contradiction only
	// node0's group supplies is rejected on node1 too.
	t.Run("GR6 node entry points", func(t *testing.T) {
		for _, nodeID := range []int{0, 1} {
			_, err := config.CompileConfigForNode(peerOnlyGroup, nodeID)
			if err == nil {
				t.Fatalf("node%d strict compile accepted a peer-only single-statement contradiction", nodeID)
			}
			assertDiagnostic12643(t, "node strict error", err.Error())
		}
		compiled, err := config.CompileConfigForNodeLenient(peerOnlyGroup, 0)
		if err != nil {
			t.Fatalf("node0 tolerant compile: %v", err)
		}
		var warning string
		for _, candidate := range compiled.Warnings {
			if strings.Contains(candidate, "#12643") {
				warning = candidate
				break
			}
		}
		assertDiagnostic12643(t, "node0 tolerant warning", warning)
		w := weekdayWindow12238(t, compiled, "monday")
		if !w.AllDay || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("node0 tolerant compile must keep union window, got %+v", w)
		}
	})
}

// Controls that must stay valid: a flag alone, a window alone, a flag with
// only a partial pair (#11641 complementary fragments), the same flag/window
// meanings on distinct weekdays, and node-identical group content.
func TestSchedulerWeekdaySingleStatementControls12643(t *testing.T) {
	accept := func(t *testing.T, tree *config.ConfigTree) *config.Config {
		t.Helper()
		compiled, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("control must compile strictly: %v", err)
		}
		for _, warning := range compiled.Warnings {
			if strings.Contains(warning, "#12643") {
				t.Fatalf("control must not raise a #12643 warning: %q", warning)
			}
		}
		return compiled
	}

	t.Run("all-day only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers { scheduler S { monday all-day; } }`))
		if w := weekdayWindow12238(t, cfg, "monday"); !w.AllDay || w.StartTime != "" || w.StopTime != "" {
			t.Fatalf("all-day-only window changed: %+v", w)
		}
	})
	t.Run("window only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } }
}`))
		if w := weekdayWindow12238(t, cfg, "monday"); w.AllDay || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("window-only window changed: %+v", w)
		}
	})
	t.Run("flag with partial start only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { all-day; start-time 09:00:00; } }
}`))
		if w := weekdayWindow12238(t, cfg, "monday"); !w.AllDay || w.StartTime != "09:00:00" || w.StopTime != "" {
			t.Fatalf("partial window changed: %+v", w)
		}
	})
	t.Run("flag with partial stop only", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { exclude; stop-time 17:00:00; } }
}`))
		if w := weekdayWindow12238(t, cfg, "monday"); !w.Exclude || w.StartTime != "" || w.StopTime != "17:00:00" {
			t.Fatalf("partial window changed: %+v", w)
		}
	})
	t.Run("distinct weekdays", func(t *testing.T) {
		cfg := accept(t, parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday all-day; tuesday { start-time 09:00:00; stop-time 17:00:00; } }
}`))
		if w := weekdayWindow12238(t, cfg, "monday"); !w.AllDay {
			t.Fatalf("distinct Monday all-day window changed: %+v", w)
		}
		if w := weekdayWindow12238(t, cfg, "tuesday"); w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("distinct Tuesday window changed: %+v", w)
		}
	})
	t.Run("peer-identical groups", func(t *testing.T) {
		tree := parseWeekdayConfig12238(t, `groups {
    node0 { schedulers { scheduler S { monday all-day; } } }
    node1 { schedulers { scheduler S { monday all-day; } } }
}
apply-groups "${node}";
schedulers { scheduler S { tuesday { start-time 09:00:00; stop-time 17:00:00; } } }
`)
		for _, nodeID := range []int{0, 1} {
			cfg, err := config.CompileConfigForNode(tree, nodeID)
			if err != nil {
				t.Fatalf("node%d peer-identical control must compile: %v", nodeID, err)
			}
			if w := weekdayWindow12238(t, cfg, "monday"); !w.AllDay {
				t.Fatalf("node%d peer-identical Monday window changed: %+v", nodeID, w)
			}
		}
	})
}
