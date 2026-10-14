package config_test

// #12238: separate weekday statements may not split an all-day/exclude flag
// from a complete time window, or split all-day from exclude. Strict
// compilation rejects those contradictions whether the statements sit in one
// scheduler block or in repeated blocks; tolerant compilation warns and
// preserves the existing union semantics. Partial boundary fragments and
// values authored within one weekday statement keep their existing behavior,
// except that a complete all-day/time-window combination is now diagnosed by
// #12643 regardless of whether those meanings compose into one statement.
//
// Runtime evaluates flags before time bounds (Exclude, then AllDay), so the
// union fallback must produce the same compiled scheduler window across paths.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// The two #12238 diagnostics name different contradictions: an all-day versus
// exclude split has no time window to report.
const (
	flagWindow12238    = "start-time/stop-time bounds from a separate weekday statement"
	allDayExclude12238 = "combines all-day and exclude from separate weekday statements"
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

func parseWeekdayConfig12238(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func compileFlat12238(t *testing.T, commands ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("parse flat command %q: %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("apply flat command %q: %v", command, err)
		}
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile flat commands: %v", err)
	}
	return compiled
}

// rejectAndWarnUnion12238 asserts that the strict (commit-check) compile
// rejects text with exactly the given #12238 diagnostics, and that the
// tolerant compile warns with the same diagnostics and keeps the union window.
func rejectAndWarnUnion12238(t *testing.T, text string, kinds ...string) *config.SchedulerDayWindow {
	t.Helper()
	tree := parseWeekdayConfig12238(t, text)
	_, err := config.CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict compile accepted %s, want a #12238 rejection", text)
	}
	assertDiagnostic12238(t, "strict error", err.Error(), kinds)
	compiled, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	var warning string
	for _, candidate := range compiled.Warnings {
		if strings.Contains(candidate, "#12238") || strings.Contains(candidate, "#12643") {
			warning = candidate
			break
		}
	}
	assertDiagnostic12238(t, "tolerant warning", warning, kinds)
	return weekdayWindow12238(t, compiled, "monday")
}

func assertDiagnostic12238(t *testing.T, label, message string, kinds []string) {
	t.Helper()
	if !strings.Contains(message, `scheduler "S"`) || !strings.Contains(message, "monday") ||
		(!strings.Contains(message, "#12238") && !strings.Contains(message, "#12643")) {
		t.Fatalf("%s = %q, want a scheduler S weekday contradiction diagnostic", label, message)
	}
	for _, kind := range kinds {
		got := strings.Contains(message, kind)
		if kind == flagWindow12238 {
			got = got || strings.Contains(message, "complete start-time/stop-time window")
		}
		if !got {
			t.Fatalf("%s = %q: missing expected diagnostic component %q", label, message, kind)
		}
	}
}

func TestSchedulerWeekdayAllDayAndCompleteWindowReject_12238(t *testing.T) {
	for _, text := range []string{
		`schedulers { scheduler S { monday all-day; } scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }`,
		`schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } scheduler S { monday all-day; } }`,
	} {
		w := rejectAndWarnUnion12238(t, text, flagWindow12238)
		if !w.AllDay || w.Exclude || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("tolerant compile must keep the union window, got %+v", w)
		}
	}
}

func TestSchedulerWeekdayExcludeAndCompleteWindowReject_12238(t *testing.T) {
	for _, text := range []string{
		`schedulers { scheduler S { monday { exclude; } } scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }`,
		`schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } scheduler S { monday { exclude; } } }`,
	} {
		w := rejectAndWarnUnion12238(t, text, flagWindow12238)
		if !w.Exclude || w.AllDay || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
			t.Fatalf("tolerant compile must keep the union window, got %+v", w)
		}
	}
}

func TestSchedulerWeekdayContradictoryFlagsReject_12238(t *testing.T) {
	for _, text := range []string{
		`schedulers { scheduler S { monday { all-day; } } scheduler S { monday { exclude; } } }`,
		`schedulers { scheduler S { monday { exclude; } } scheduler S { monday { all-day; } } }`,
	} {
		w := rejectAndWarnUnion12238(t, text, allDayExclude12238)
		if !w.AllDay || !w.Exclude {
			t.Fatalf("tolerant compile must preserve both unioned flags, got %+v", w)
		}
	}
}

func TestSchedulerWeekdayCombinedFlagWindowRejectsAcrossInstances_12238(t *testing.T) {
	// The later statement carries all-day and the complete window itself, so
	// only the earlier exclude statement is split from them: both diagnostics
	// fire, independent of which flag was authored first.
	w := rejectAndWarnUnion12238(t, `schedulers {
    scheduler S { monday { exclude; } }
    scheduler S { monday { all-day; start-time 09:00:00; stop-time 17:00:00; } }
}`, flagWindow12238, allDayExclude12238)
	if !w.AllDay || !w.Exclude || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
		t.Fatalf("tolerant compile must retain the combined union, got %+v", w)
	}
}

// Separate weekday statements inside ONE scheduler block are split exactly
// like repeated blocks. The first rows are the shapes a `set` or `load merge`
// produces on top of a committed `monday all-day;` leaf.
func TestSchedulerWeekdaySplitStatementsInOneBlockReject_12238(t *testing.T) {
	window := config.SchedulerDayWindow{StartTime: "09:00:00", StopTime: "17:00:00"}
	allDayWindow, excludeWindow := window, window
	allDayWindow.AllDay = true
	excludeWindow.Exclude = true
	for _, tc := range []struct {
		name  string
		text  string
		kinds []string
		want  config.SchedulerDayWindow
	}{
		{
			name:  "all-day leaf then window",
			text:  `schedulers { scheduler S { monday all-day; monday { start-time 09:00:00; stop-time 17:00:00; } } }`,
			kinds: []string{flagWindow12238},
			want:  allDayWindow,
		},
		{
			name:  "window then all-day leaf",
			text:  `schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } monday all-day; } }`,
			kinds: []string{flagWindow12238},
			want:  allDayWindow,
		},
		{
			name:  "exclude then window",
			text:  `schedulers { scheduler S { monday { exclude; } monday { start-time 09:00:00; stop-time 17:00:00; } } }`,
			kinds: []string{flagWindow12238},
			want:  excludeWindow,
		},
		{
			name:  "all-day then exclude",
			text:  `schedulers { scheduler S { monday all-day; monday exclude; } }`,
			kinds: []string{allDayExclude12238},
			want:  config.SchedulerDayWindow{AllDay: true, Exclude: true},
		},
		{
			name:  "all-day then split window",
			text:  `schedulers { scheduler S { monday { all-day; } monday { start-time 09:00:00; } monday { stop-time 17:00:00; } } }`,
			kinds: []string{flagWindow12238},
			want:  allDayWindow,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := *rejectAndWarnUnion12238(t, tc.text, tc.kinds...); got != tc.want {
				t.Fatalf("tolerant union = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Both node views are checked, so separate statements that only node1's group
// supplies are rejected on node0 too, and node0's tolerant compile warns.
func TestSchedulerWeekdayPeerOnlySplitStatementsReject_12238(t *testing.T) {
	const text = `groups {
    node0 { system { host-name node0; } }
    node1 {
        schedulers {
            scheduler S { monday all-day; monday { start-time 09:00:00; stop-time 17:00:00; } }
        }
    }
}
apply-groups "${node}";
`
	for _, nodeID := range []int{0, 1} {
		_, err := config.CompileConfigForNode(parseWeekdayConfig12238(t, text), nodeID)
		if err == nil {
			t.Fatalf("node%d strict compile accepted peer-only split statements", nodeID)
		}
		assertDiagnostic12238(t, fmt.Sprintf("node%d strict error", nodeID), err.Error(), []string{flagWindow12238})
	}
	compiled, err := config.CompileConfigForNodeLenient(parseWeekdayConfig12238(t, text), 0)
	if err != nil {
		t.Fatalf("tolerant node0 compile: %v", err)
	}
	var warning string
	for _, candidate := range compiled.Warnings {
		if strings.Contains(candidate, "#12238") || strings.Contains(candidate, "#12643") {
			warning = candidate
			break
		}
	}
	assertDiagnostic12238(t, "tolerant node0 warning", warning, []string{flagWindow12238})
}

// A flag statement that carries only one bound still contradicts a window
// once another statement supplies the missing bound: the flag's statement no
// longer carries the whole window, so this is not a complementary fragment.
func TestSchedulerWeekdayFlagHalfWindowCompletedElsewhereRejects_12238(t *testing.T) {
	w := rejectAndWarnUnion12238(t, `schedulers {
    scheduler S { monday { all-day; start-time 09:00:00; } }
    scheduler S { monday { stop-time 17:00:00; } }
}`, flagWindow12238)
	if !w.AllDay || w.Exclude || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
		t.Fatalf("tolerant compile must keep the union window, got %+v", w)
	}
}

// Daily all-day plus a complete window is a #12745 contradiction, even when
// duplicate daily statements compose the two meanings.
func TestSchedulerDailyRepeatsReject12745_12238(t *testing.T) {
	for _, text := range []string{
		`schedulers { scheduler S { daily all-day; } scheduler S { daily { start-time 09:00:00; stop-time 17:00:00; } } }`,
		`schedulers { scheduler S { daily all-day; daily { start-time 09:00:00; stop-time 17:00:00; } } }`,
	} {
		sched := rejectAndWarnUnion12745(t, parseWeekdayConfig12238(t, text))
		if !sched.AllDay || sched.StartTime != "09:00:00" || sched.StopTime != "17:00:00" {
			t.Fatalf("tolerant compile must keep the daily union window, got %+v", sched)
		}
	}
}

func TestSchedulerWeekdayPartialAndSingleStatementControls_12238(t *testing.T) {
	partial := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { all-day; exclude; } }
    scheduler S { monday { start-time 09:00:00; } }
}`)
	compiled, err := config.CompileConfig(partial)
	if err != nil {
		t.Fatalf("partial boundary must not be rejected: %v", err)
	}
	w := weekdayWindow12238(t, compiled, "monday")
	if !w.AllDay || !w.Exclude || w.StartTime != "09:00:00" || w.StopTime != "" {
		t.Fatalf("partial fragment must preserve flags and add its boundary, got %+v", w)
	}

	inBlockPartial := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday all-day; monday { start-time 09:00:00; } }
}`)
	compiled, err = config.CompileConfig(inBlockPartial)
	if err != nil {
		t.Fatalf("partial boundary statement in one block must not be rejected: %v", err)
	}
	w = weekdayWindow12238(t, compiled, "monday")
	if !w.AllDay || w.Exclude || w.StartTime != "09:00:00" || w.StopTime != "" {
		t.Fatalf("in-block partial fragment must preserve the flag and add its boundary, got %+v", w)
	}

	single := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { exclude; start-time 09:00:00; stop-time 17:00:00; } }
}`)
	compiled, err = config.CompileConfig(single)
	if err != nil {
		t.Fatalf("single-statement exclude/window remains valid because exclude already makes the day closed: %v", err)
	}
	w = weekdayWindow12238(t, compiled, "monday")
	if !w.Exclude || w.AllDay || w.StartTime != "09:00:00" || w.StopTime != "17:00:00" {
		t.Fatalf("single-statement exclude/window changed: %+v", w)
	}
}

func TestSchedulerWeekdayDistinctDayAndFlatSetParity_12238(t *testing.T) {
	distinctDays := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday all-day; }
    scheduler S { tuesday { start-time 09:00:00; stop-time 17:00:00; } }
}`)
	distinctCfg, err := config.CompileConfig(distinctDays)
	if err != nil {
		t.Fatalf("distinct weekdays across scheduler instances must remain valid: %v", err)
	}
	if got := weekdayWindow12238(t, distinctCfg, "monday"); !got.AllDay {
		t.Fatalf("distinct Monday all-day window changed: %+v", got)
	}
	if got := weekdayWindow12238(t, distinctCfg, "tuesday"); got.StartTime != "09:00:00" || got.StopTime != "17:00:00" {
		t.Fatalf("distinct Tuesday window changed: %+v", got)
	}

	hierarchical := `schedulers {
    scheduler S { monday { all-day; } tuesday { start-time 09:00:00; stop-time 17:00:00; } }
    scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } }
}`
	// The contradictory Monday is rejected strictly and retains union semantics
	// on tolerant paths; Tuesday remains an unrelated valid weekday.
	monday := rejectAndWarnUnion12238(t, hierarchical, flagWindow12238)
	if !monday.AllDay || monday.StartTime != "09:00:00" || monday.StopTime != "17:00:00" {
		t.Fatalf("Monday union changed: %+v", monday)
	}
	parsed := parseWeekdayConfig12238(t, hierarchical)
	tolerantCfg, err := config.CompileConfigLenient(parsed)
	if err != nil {
		t.Fatalf("tolerant compile for distinct-day parity: %v", err)
	}
	if got := weekdayWindow12238(t, tolerantCfg, "tuesday"); got.StartTime != "09:00:00" || got.StopTime != "17:00:00" {
		t.Fatalf("tolerant compile changed distinct Tuesday window: %+v", got)
	}

	// Flat `set` and FormatSet replay compose Monday into ONE weekday
	// statement, which #12643 now rejects because it combines all-day with
	// a complete window; the union remains unchanged on tolerant paths.
	setTree := &config.ConfigTree{}
	for _, command := range []string{
		"set schedulers scheduler S monday all-day",
		"set schedulers scheduler S monday start-time 09:00:00",
		"set schedulers scheduler S monday stop-time 17:00:00",
		"set schedulers scheduler S tuesday start-time 09:00:00",
		"set schedulers scheduler S tuesday stop-time 17:00:00",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("parse flat command %q: %v", command, err)
		}
		if err := setTree.SetPath(path); err != nil {
			t.Fatalf("apply flat command %q: %v", command, err)
		}
	}
	setCfg, err := config.CompileConfigLenient(setTree)
	if err != nil {
		t.Fatalf("compile flat commands tolerantly: %v", err)
	}
	setMonday := weekdayWindow12238(t, setCfg, "monday")
	if *setMonday != *monday {
		t.Fatalf("hierarchical tolerant window %+v diverges from flat-set window %+v", *monday, *setMonday)
	}

	flat := &config.ConfigTree{}
	for _, line := range strings.Split(parsed.FormatSet(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse FormatSet line %q: %v", line, err)
		}
		if err := flat.SetPath(path); err != nil {
			t.Fatalf("replay FormatSet line %q: %v", line, err)
		}
	}
	flatCfg, err := config.CompileConfigLenient(flat)
	if err != nil {
		t.Fatalf("FormatSet replay tolerantly compiled: %v", err)
	}
	flatMonday := weekdayWindow12238(t, flatCfg, "monday")
	if *flatMonday != *monday {
		t.Fatalf("hierarchical tolerant window %+v diverges from FormatSet replay %+v", *monday, *flatMonday)
	}
	if got := weekdayWindow12238(t, flatCfg, "tuesday"); got.StartTime != "09:00:00" || got.StopTime != "17:00:00" {
		t.Fatalf("FormatSet replay lost distinct Tuesday window: %+v", got)
	}
}

func TestSchedulerWeekdayAuthoringShapeParity_12238(t *testing.T) {
	const repeatedBlocks = `schedulers {
    scheduler S { monday { all-day; } }
    scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } }
}`
	baseTree := parseWeekdayConfig12238(t, repeatedBlocks)
	replaySet := func(text string) *config.ConfigTree {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			path, err := config.ParseSetCommand(line)
			if err != nil {
				t.Fatalf("parse set replay line %q: %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("replay set line %q: %v", line, err)
			}
		}
		return tree
	}

	p2Flat := &config.ConfigTree{}
	for _, command := range []string{
		"set schedulers scheduler S monday all-day",
		"set schedulers scheduler S monday start-time 09:00:00",
		"set schedulers scheduler S monday stop-time 17:00:00",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("parse flat control %q: %v", command, err)
		}
		if err := p2Flat.SetPath(path); err != nil {
			t.Fatalf("apply flat control %q: %v", command, err)
		}
	}
	p3bFormat, errs := config.NewParser(baseTree.Format()).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse Format replay: %v", errs)
	}
	p4Single := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { all-day; start-time 09:00:00; stop-time 17:00:00; } }
}`)
	p5Split := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { all-day; } }
    scheduler S { monday { start-time 09:00:00; } }
    scheduler S { monday { stop-time 17:00:00; } }
}`)
	p6Roots := parseWeekdayConfig12238(t, `schedulers { scheduler S { monday { all-day; } } }
schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }`)
	p8InBlock := parseWeekdayConfig12238(t, `schedulers {
    scheduler S { monday { all-day; } monday { start-time 09:00:00; stop-time 17:00:00; } }
}`)
	// P9 is `set` on top of a stored `monday all-day;` leaf: SetPath cannot
	// extend the two-key leaf, so the window lands in a second statement.
	p9SetOntoLeaf := parseWeekdayConfig12238(t, `schedulers { scheduler S { monday all-day; } }`)
	for _, command := range []string{
		"set schedulers scheduler S monday start-time 09:00:00",
		"set schedulers scheduler S monday stop-time 17:00:00",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("parse P9 command %q: %v", command, err)
		}
		if err := p9SetOntoLeaf.SetPath(path); err != nil {
			t.Fatalf("apply P9 command %q: %v", command, err)
		}
	}

	rows := []struct {
		name   string
		tree   *config.ConfigTree
		reject bool
		warn   bool
	}{
		{name: "P1 hierarchical blocks", tree: baseTree, reject: true, warn: true},
		// P2, P3, and P3c compose Monday into one statement (#12643), so each
		// now rejects strictly and warns tolerantly.
		{name: "P2 flat set", tree: p2Flat, reject: true, warn: true},
		{name: "P3 FormatSet replay", tree: replaySet(baseTree.FormatSet()), reject: true, warn: true},
		{name: "P3b Format replay", tree: p3bFormat, reject: true, warn: true},
		{name: "P3c load-merge FormatSet replay", tree: replaySet(baseTree.FormatSetForLoadMerge()), reject: true, warn: true},
		{name: "P4 one statement", tree: p4Single, reject: true, warn: true},
		{name: "P5 split start/stop blocks", tree: p5Split, reject: true, warn: true},
		{name: "P6 separate roots", tree: p6Roots, reject: true, warn: true},
		{name: "P8 one block, separate statements", tree: p8InBlock, reject: true, warn: true},
		{name: "P9 set onto an all-day leaf", tree: p9SetOntoLeaf, reject: true, warn: true},
	}
	want := config.SchedulerDayWindow{StartTime: "09:00:00", StopTime: "17:00:00", AllDay: true}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, strictErr := config.CompileConfig(row.tree)
			if row.reject {
				if strictErr == nil ||
					(!strings.Contains(strictErr.Error(), "#12238") && !strings.Contains(strictErr.Error(), "#12643")) ||
					!strings.Contains(strictErr.Error(), `scheduler "S"`) ||
					!strings.Contains(strictErr.Error(), "monday") {
					t.Fatalf("strict error = %v, want a scheduler weekday contradiction diagnostic", strictErr)
				}
			} else if strictErr != nil {
				t.Fatalf("strict compile: %v", strictErr)
			}

			compiled, err := config.CompileConfigLenient(row.tree)
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			foundWarning := false
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, "#12238") || strings.Contains(warning, "#12643") {
					foundWarning = true
					break
				}
			}
			if foundWarning != row.warn {
				t.Fatalf("warning presence = %v, warnings %v; want %v", foundWarning, compiled.Warnings, row.warn)
			}
			got := *weekdayWindow12238(t, compiled, "monday")
			if got != want {
				t.Fatalf("compiled window %+v differs from expected union %+v", got, want)
			}
		})
	}
}
