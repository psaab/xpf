package config

import (
	"strings"
	"testing"
)

// Tests for #15205 (residual of #6771, A14-05): the #3751 strict
// within/trigger validator read only the FIRST `trigger` sibling
// (w.FindChild("trigger")) while compileEventOptions applies EVERY
// sibling last-wins (FindChildren("trigger")). A hierarchical clause such as
//
//	within 60 {
//	    trigger on 3;
//	    trigger on typo;
//	}
//
// therefore committed clean: the validator saw only the valid first sibling,
// and the compiler silently dropped the bad later value (Atoi error ignored,
// earlier value kept) or filled a contradictory field from it. The validator
// now aggregates every trigger sibling and applies the same checks to the
// aggregate, so an invalid or contradictory later sibling is rejected
// strictly exactly as if it had been packed into the first sibling.
//
// Hierarchical syntax MUST be built with NewParser (flat `set` lines merge
// repeated trigger values under ONE trigger node as children, which the old
// validator already saw whole — that shape does not exercise this defect).

func buildEventWithinHier15205(t *testing.T, body string) *ConfigTree {
	t.Helper()
	p := NewParser(body)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func hierWithin15205(triggerStmts string) string {
	return "event-options {\n    policy P {\n        events ping_test_failed;\n        within 60 {\n" +
		triggerStmts +
		"\n        }\n    }\n}"
}

// TestEventWithinSecondTriggerSiblingRejected15205 is the RED-on-revert core:
// hard error. On origin/master the validator reads only the first sibling, so
// every subtest is accepted and goes RED.
func TestEventWithinSecondTriggerSiblingRejected15205(t *testing.T) {
	cases := []struct {
		name string
		trig string
		want []string
	}{
		{
			name: "second sibling non-numeric count",
			trig: "            trigger on 3;\n            trigger on typo;",
			want: []string{"P", "typo", "on"},
		},
		{
			name: "second sibling out-of-range count",
			trig: "            trigger on 3;\n            trigger on 0;",
			want: []string{"P", "on", "range"},
		},
		{
			name: "second sibling contradictory until",
			trig: "            trigger on 3;\n            trigger until 5;",
			want: []string{"P", "on", "until"},
		},
		{
			name: "second sibling contradictory on after until",
			trig: "            trigger until 5;\n            trigger on 3;",
			want: []string{"P", "on", "until"},
		},
		{
			name: "second sibling unknown keyword",
			trig: "            trigger on 3;\n            trigger after 3;",
			want: []string{"P", "after"},
		},
		{
			name: "second sibling missing count",
			trig: "            trigger on 3;\n            trigger on;",
			want: []string{"P", "on", "count"},
		},
		{
			name: "second sibling empty trigger",
			trig: "            trigger on 3;\n            trigger;",
			want: []string{"P", "trigger"},
		},
		{
			// Block form: the second trigger sibling carries its spec as a
			// child node rather than packed keys.
			name: "second sibling block-form contradictory",
			trig: "            trigger on 3;\n            trigger {\n                until 5;\n            }",
			want: []string{"P", "on", "until"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildEventWithinHier15205(t, hierWithin15205(tc.trig))
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a malformed second trigger sibling (%q); want a strict reject", tc.trig)
			}
			for _, sub := range tc.want {
				if !strings.Contains(err.Error(), sub) {
					t.Fatalf("reject error %q missing expected substring %q", err.Error(), sub)
				}
			}
		})
	}
}

// TestEventWithinDuplicateTriggerLastWinsControl15205 is the adjacent
// legitimate-behaviour control: repeated trigger siblings carrying the SAME
// keyword with valid counts are ordinary Junos re-sets — the compiler takes
// the last value (#6771) and the widened validator must not reject them.
func TestEventWithinDuplicateTriggerLastWinsControl15205(t *testing.T) {
	tree := buildEventWithinHier15205(t, hierWithin15205(
		"            trigger on 3;\n            trigger on 9;"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid duplicate trigger on re-set: %v", err)
	}
	if len(cfg.EventOptions) != 1 || len(cfg.EventOptions[0].WithinClauses) != 1 {
		t.Fatalf("compiled policies=%v, want one policy with one within clause", cfg.EventOptions)
	}
	w := cfg.EventOptions[0].WithinClauses[0]
	if w.Seconds != 60 || w.TriggerOn != 9 || w.TriggerUntil != 0 {
		t.Errorf("duplicate trigger on compiled as seconds=%d on=%d until=%d, want 60/9/0 (last sibling wins)",
			w.Seconds, w.TriggerOn, w.TriggerUntil)
	}

	tree = buildEventWithinHier15205(t, hierWithin15205(
		"            trigger until 4;\n            trigger until 11;"))
	cfg, err = CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid duplicate trigger until re-set: %v", err)
	}
	w = cfg.EventOptions[0].WithinClauses[0]
	if w.TriggerUntil != 11 || w.TriggerOn != 0 {
		t.Errorf("duplicate trigger until compiled as on=%d until=%d, want 0/11 (last sibling wins)",
			w.TriggerOn, w.TriggerUntil)
	}
}

// TestEventWithinSecondTriggerSiblingLenient15205 pins the tolerant load /
// peer-sync split for the widened gate: a malformed second sibling downgrades
// to a warning, not a hard error, exactly like a malformed first sibling.
func TestEventWithinSecondTriggerSiblingLenient15205(t *testing.T) {
	tree := buildEventWithinHier15205(t, hierWithin15205(
		"            trigger on 3;\n            trigger on typo;"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a malformed second trigger sibling on the tolerant path: %v", err)
	}
	found := false
	for _, warn := range cfg.Warnings {
		if strings.Contains(warn, "within") && strings.Contains(warn, "typo") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path did not emit a warning for the second trigger sibling; warnings=%v", cfg.Warnings)
	}
}
