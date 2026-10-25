package config

import (
	"fmt"
	"strings"
	"testing"
)

// Tests for #16654 (residual of #14660/#15134): the closed-world gate
// did not descend into `within`, so Junos correlation children —
// `events X`, `not events X` (the "fire only if X did NOT happen"
// negative gate), or any bogus token — committed clean and were dropped
// by compileEventOptions (which reads only FindChildren("trigger")
// inside a within clause). A policy whose negative prerequisite was
// removed then fired unconditionally — the fail-open direction.
//
// validateEventWithinClause (the #3751 walk, same strict/lenient split)
// now rejects (strict) / warns (lenient) any within child other than
// `trigger`, naming the policy and the token. The control
// `within 60 { trigger on 3; }` stays clean.
//
// RED-on-revert: removing the withinChildTokens16654 check from
// validateEventWithinClause makes every Reject/Warn cell below accept
// silently (the hier braced cells were probe-verified err=<nil> on
// origin/master).

func TestEventWithinCorrelationChildren16654StrictRejects(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
		want []string // substrings: policy + offending token + #16654
	}{
		{
			name: "hier braced events",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { events ping_test_completed; trigger on 1; } then { change-configuration { commands "set system host-name x"; } } } }`),
			want: []string{"p", "events", "#16654"},
		},
		{
			name: "hier braced not events",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { not events ping_test_completed; trigger on 1; } then { change-configuration { commands "set system host-name x"; } } } }`),
			want: []string{"p", "not", "#16654"},
		},
		{
			name: "hier braced not block events",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { not { events ping_test_completed; } trigger on 1; } } }`),
			want: []string{"p", "not", "#16654"},
		},
		{
			name: "hier braced bogus token",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { bogus-token foo; trigger on 1; } } }`),
			want: []string{"p", "bogus-token", "#16654"},
		},
		{
			name: "hier packed events tail fused sibling (strict-rejected pre-gate)",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 events ping_test_completed; } }`),
			want: []string{"p", "events"},
		},
		{
			name: "hier packed not events tail (direct #16654 gate)",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 not events ping_test_completed; } }`),
			want: []string{"p", "not", "#16654"},
		},
		{
			name: "flat events",
			tree: setTree6659(t,
				`set event-options policy p events ping_test_failed`,
				`set event-options policy p within 60 events ping_test_completed`,
				`set event-options policy p within 60 trigger on 1`,
				`set event-options policy p then change-configuration commands "set system host-name x"`),
			want: []string{"p", "events", "#16654"},
		},
		{
			name: "flat not events",
			tree: setTree6659(t,
				`set event-options policy p events ping_test_failed`,
				`set event-options policy p within 60 not events ping_test_completed`,
				`set event-options policy p within 60 trigger on 1`,
				`set event-options policy p then change-configuration commands "set system host-name x"`),
			want: []string{"p", "not", "#16654"},
		},
		{
			name: "flat bogus token",
			tree: setTree6659(t,
				`set event-options policy p events ping_test_failed`,
				`set event-options policy p within 60 bogus-token foo`,
				`set event-options policy p within 60 trigger on 1`),
			want: []string{"p", "bogus-token", "#16654"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted inert within correlation child; want reject containing %v", tc.want)
			}
			for _, sub := range tc.want {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q missing %q", err.Error(), sub)
				}
			}
		})
	}
}

// TestEventWithinCorrelationChildren16654LenientWarns pins the tolerant
// split for the non-fused shapes (packed tails are strict-only fused
// siblings, see StrictRejects): braced and flat spellings warn naming
// policy + token + #16654 and still compile (#1960).
func TestEventWithinCorrelationChildren16654LenientWarns(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{
			name: "hier braced events",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { events ping_test_completed; trigger on 1; } } }`),
			want: []string{"p", "events", "#16654"},
		},
		{
			name: "hier braced not events",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { not events ping_test_completed; trigger on 1; } } }`),
			want: []string{"p", "not", "#16654"},
		},
		{
			name: "hier braced bogus token",
			tree: parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { bogus-token foo; trigger on 1; } } }`),
			want: []string{"p", "bogus-token", "#16654"},
		},
		{
			name: "flat not events",
			tree: setTree6659(t,
				`set event-options policy p events ping_test_failed`,
				`set event-options policy p within 60 not events ping_test_completed`,
				`set event-options policy p within 60 trigger on 1`),
			want: []string{"p", "not", "#16654"},
		},
		{
			name: "flat events",
			tree: setTree6659(t,
				`set event-options policy p events ping_test_failed`,
				`set event-options policy p within 60 events ping_test_completed`,
				`set event-options policy p within 60 trigger on 1`),
			want: []string{"p", "events", "#16654"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected within correlation child: %v", err)
			}
			if cfg == nil {
				t.Fatal("lenient compile returned nil config")
			}
			if !hasWarningContaining14660(cfg, tc.want...) {
				t.Fatalf("lenient warnings %v contain no warning with %v", cfg.Warnings, tc.want)
			}
		})
	}
}

// TestEventWithinCorrelationControl16654 proves the fix does not
// over-reject: `within 60 { trigger on 3; }` (and the flat / packed
// trigger spellings) stay clean strict and lenient, with the compiled
// WithinClauses preserved.
func TestEventWithinCorrelationControl16654(t *testing.T) {
	trees := map[string]*ConfigTree{
		"hier trigger on":    parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { trigger on 3; } then { change-configuration { commands "set system host-name x"; } } } }`),
		"hier trigger until": parseHierText(t, `event-options { policy p { events ping_test_failed; within 60 { trigger until 3; } } }`),
		"flat trigger on": setTree6659(t,
			`set event-options policy p events ping_test_failed`,
			`set event-options policy p within 60 trigger on 3`),
	}
	for name, tree := range trees {
		t.Run(name+"/strict", func(t *testing.T) {
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected within trigger control: %v", err)
			}
			if hasWarningContaining14660(cfg, "#16654") {
				t.Fatalf("strict control carried #16654 warning: %v", cfg.Warnings)
			}
			if len(cfg.EventOptions) != 1 || len(cfg.EventOptions[0].WithinClauses) != 1 {
				t.Fatalf("compiled EventOptions = %+v, want 1 policy with 1 within clause", cfg.EventOptions)
			}
			w := cfg.EventOptions[0].WithinClauses[0]
			if w.Seconds != 60 || (w.TriggerOn != 3 && w.TriggerUntil != 3) {
				t.Fatalf("within clause = %+v, want Seconds=60 Trigger*=3", w)
			}
		})
		t.Run(name+"/lenient", func(t *testing.T) {
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected within trigger control: %v", err)
			}
			if hasWarningContaining14660(cfg, "#16654") {
				t.Fatalf("lenient control carried #16654 warning: %v", cfg.Warnings)
			}
		})
	}
}

// TestEventWithinCorrelationDirectValidator16654 exercises the clause
// gate directly: a packed-tail `within 60 not events X` node must name
// `not`, and a pure trigger node must pass.
func TestEventWithinCorrelationDirectValidator16654(t *testing.T) {
	findWithin := func(src string) *Node {
		tree := parseHierText(t, src)
		for _, eo := range tree.Children {
			for _, pInst := range namedInstances(eo.FindChildren("policy")) {
				if w := pInst.node.FindChild("within"); w != nil {
					return w
				}
			}
		}
		t.Fatalf("probe: no within node in %q", src)
		return nil
	}
	strictEmit := func(format string, args ...any) error {
		return fmt.Errorf(format, args...)
	}
	packedWithin := findWithin(`event-options { policy p { events ping_test_failed; within 60 not events ping_test_completed; } }`)
	if err := validateEventWithinClause("p", packedWithin, strictEmit); err == nil ||
		!strings.Contains(err.Error(), "not") || !strings.Contains(err.Error(), "#16654") {
		t.Fatalf("direct packed gate = %v, want not + #16654 reject", err)
	}
	goodWithin := findWithin(`event-options { policy p { events ping_test_failed; within 60 { trigger on 3; } } }`)
	if err := validateEventWithinClause("p", goodWithin, strictEmit); err != nil {
		t.Fatalf("direct control gate = %v, want clean", err)
	}
}
