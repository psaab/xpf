package config_test

// #16010: on the tolerant path a scheduler all-day+window conflict used to
// keep the union window, and the runtime evaluates all-day before time
// bounds, so the conflict resolved widest (permit all day). The fix marks
// the scheduler Unresolvable on tolerant compile; strict compile still
// rejects. Exclude-only and repeated-boundary arms were killed /
// direction-neutral in the research ledger and are not the decisive arm
// here, but every scheduler-window-pair finding marks its scheduler
// unresolvable on the tolerant path.
//
// FAIL-ON-REVERT: dropping markSchedulersUnresolvable16010 (or the
// validator's name return) leaves Unresolvable=false and this test fails;
// dropping the scheduler runtime check is pinned by
// pkg/scheduler TestIsWithinWindowUnresolvable16010.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSchedulerAllDayWindowTolerantMarksUnresolvable16010(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "daily all-day plus window",
			text: `schedulers { scheduler S { daily { all-day; start-time 09:00:00; stop-time 17:00:00; } } }`,
		},
		{
			name: "weekday all-day plus window split statements",
			text: `schedulers { scheduler S { monday all-day; } scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }`,
		},
		{
			name: "weekday single statement all-day plus window",
			text: `schedulers { scheduler S { monday { all-day; start-time 09:00:00; stop-time 17:00:00; } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseWeekdayConfig12238(t, tc.text)
			if _, err := config.CompileConfig(tree); err == nil {
				t.Fatal("strict compile must reject all-day+window conflict")
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile must not brick: %v", err)
			}
			sched := cfg.Schedulers["S"]
			if sched == nil {
				t.Fatalf("scheduler S missing: %+v", cfg.Schedulers)
			}
			if !sched.Unresolvable {
				t.Fatalf("tolerant all-day+window scheduler must be marked Unresolvable, got %+v", sched)
			}
			// The union window is retained for display/diagnosis; only the
			// runtime activation is suppressed.
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "scheduler \"S\"") {
				t.Fatalf("tolerant compile must warn naming scheduler S, got %v", cfg.Warnings)
			}
		})
	}
}

func TestSchedulerCleanTolerantNotUnresolvable16010(t *testing.T) {
	for _, text := range []string{
		`schedulers { scheduler S { daily all-day; } }`,
		`schedulers { scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } } }`,
		`schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }`,
		`schedulers { scheduler S { monday all-day; tuesday { start-time 09:00:00; stop-time 17:00:00; } } }`,
	} {
		tree := parseWeekdayConfig12238(t, text)
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant compile %q: %v", text, err)
		}
		if sched := cfg.Schedulers["S"]; sched == nil || sched.Unresolvable {
			t.Fatalf("clean scheduler must not be Unresolvable for %q: %+v", text, sched)
		}
		// Strict compile of a clean scheduler must also stay clean.
		strictCfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile %q: %v", text, err)
		}
		if sched := strictCfg.Schedulers["S"]; sched == nil || sched.Unresolvable {
			t.Fatalf("strict clean scheduler must not be Unresolvable for %q: %+v", text, sched)
		}
	}
}

func TestSchedulerPeerOnlyGroupConflictMarksUnresolvable16010(t *testing.T) {
	// The conflicting scheduler exists only inside a node1 group; the
	// validator unions node0/node1 views, so the tolerant compile must
	// still mark it (here via the node0-fallback compile it may not
	// materialise — assert only that any compiled S is marked).
	text := `groups { node1 { schedulers { scheduler S { daily { all-day; start-time 09:00:00; stop-time 17:00:00; } } } } }
apply-groups node1;`
	tree := parseWeekdayConfig12238(t, text)
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if sched := cfg.Schedulers["S"]; sched != nil && !sched.Unresolvable {
		t.Fatalf("peer-only conflicting scheduler compiled unmarked: %+v", sched)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#12745") {
		t.Fatalf("expected #12745 tolerant warning for peer-only conflict, got %v", cfg.Warnings)
	}
}
