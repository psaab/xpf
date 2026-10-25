package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestComposedPolicyNextPolicySkipsTermsAndDefault11780(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {
				Name:          "A",
				DefaultAction: "reject",
				Terms: []*config.PolicyTerm{
					{Name: "next", NextPolicy: true, HasLocalPreference: true, LocalPreference: 200},
					{Name: "later", Action: "reject"},
				},
			},
			"B": {
				Name:          "B",
				DefaultAction: "reject",
				Terms: []*config.PolicyTerm{
					{Name: "next", NextPolicy: true},
					{Name: "later", Action: "reject"},
				},
			},
			"C": {
				Name:  "C",
				Terms: []*config.PolicyTerm{{Name: "accept", Action: "accept"}},
			},
		},
	}
	const composed = "A-B-C-xpf-chain"
	got := New().renderComposedRouteMap(po, composed, []string{"A", "B", "C"})
	for _, want := range []string{
		"route-map " + composed + " permit 10\n set local-preference 200\n on-match goto 40\n",
		"route-map " + composed + " deny 20\n",
		"route-map " + composed + " deny 30\n",
		"route-map " + composed + " permit 40\n on-match goto 70\n",
		"route-map " + composed + " deny 50\n",
		"route-map " + composed + " deny 60\n",
		"route-map " + composed + " permit 70\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("next-policy sequence missing %q from composed route-map:\n%s", want, got)
		}
	}
	if strings.Contains(got, "route-map "+composed+" permit 10\n set local-preference 200\n on-match next\n") {
		t.Errorf("next policy must skip A's remaining terms, not fall through to the next term:\n%s", got)
	}
}

func TestSinglePolicyNextPolicyBypassesExplicitDefault11780(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"ONLY": {
				Name:          "ONLY",
				DefaultAction: "reject",
				Terms:         []*config.PolicyTerm{{Name: "next", NextPolicy: true}},
			},
		},
	}
	got := New().generatePolicyOptions(po, map[string]bool{"ONLY": true})
	for _, want := range []string{
		"route-map ONLY permit 10\n on-match goto 30\n",
		"route-map ONLY deny 20\n",
		"route-map ONLY permit 30\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("single-policy next-policy fallback missing %q:\n%s", want, got)
		}
	}
}

func TestNextPolicyRedistributeMapKeepsExplicitDefaultFailClosed11780(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"ONLY": {
				Name:          "ONLY",
				DefaultAction: "reject",
				Terms:         []*config.PolicyTerm{{Name: "next", FromProtocols: []string{"static"}, NextPolicy: true}},
			},
		},
	}
	got := New().generatePolicyOptions(po, map[string]bool{"ONLY": true})
	routeMap := "ONLY-static-xpf-redist"
	for _, want := range []string{
		"route-map " + routeMap + " permit 10\n on-match goto 30\n",
		"route-map " + routeMap + " deny 20\n",
		"route-map " + routeMap + " deny 30\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("next-policy redistribute map fallback missing %q:\n%s", want, got)
		}
	}
}

func TestNarrowedSurvivorShapeNextPolicyShadowsLaterMatchAll11780(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"JUMP-THEN-ACCEPT": {Name: "JUMP-THEN-ACCEPT", Terms: []*config.PolicyTerm{
				{Name: "jump", NextPolicy: true},
				{Name: "accept", Action: "accept"},
			}},
			"COND-JUMP-THEN-ACCEPT": {Name: "COND-JUMP-THEN-ACCEPT", Terms: []*config.PolicyTerm{
				{Name: "jump", PrefixList: []string{"PL"}, NextPolicy: true},
				{Name: "accept", Action: "accept"},
			}},
			"ACCEPT-THEN-JUMP": {Name: "ACCEPT-THEN-JUMP", Terms: []*config.PolicyTerm{
				{Name: "accept", Action: "accept"},
				{Name: "jump", NextPolicy: true},
			}},
			"TERMREJECT": {Name: "TERMREJECT", DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: []string{"PL"}, Action: "accept"},
			}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}},
		},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
	}
	// An unconditional next-policy term jumps every route away before the
	// later unconditional accept is reached: the accept is shadowed and the
	// survivor falls through to the next member (or the trailing fallback).
	if got := narrowedSurvivorShape10129([]string{"JUMP-THEN-ACCEPT"}, po); got != "fall-through" {
		t.Errorf("unconditional jump shadows later accept: shape=%q, want fall-through", got)
	}
	// A conditional jump still bypasses the later accept for matching
	// routes, so the survivor cannot prove termination either.
	if got := narrowedSurvivorShape10129([]string{"COND-JUMP-THEN-ACCEPT"}, po); got != "fall-through" {
		t.Errorf("conditional jump bypasses later accept: shape=%q, want fall-through", got)
	}
	// Control: the accept first terminates every route, so the later jump
	// is unreachable and the survivor still terminates.
	if got := narrowedSurvivorShape10129([]string{"ACCEPT-THEN-JUMP"}, po); got != "match-all" {
		t.Errorf("accept-then-jump: shape=%q, want match-all", got)
	}
	// The shadowed member must not stop the scan: jumping routes continue
	// into later members, so a later terminating default still dominates.
	if got := narrowedSurvivorShape10129([]string{"JUMP-THEN-ACCEPT", "TERMREJECT"}, po); got != "terminating-default" {
		t.Errorf("jump-then-accept + terminating default: shape=%q, want terminating-default", got)
	}
	// Eligibility follows the shape: a suffix-narrowed shadowed survivor
	// receives the fail-closed deny alias.
	site := narrowedChainSite{Authored: []string{"JUMP-THEN-ACCEPT", "GHOST"}, Kept: []string{"JUMP-THEN-ACCEPT"}, GhostsAreSuffix: true}
	if !narrowedAliasEligible10129(site, po) {
		t.Errorf("shadowed survivor must be alias-eligible (fall-through), got ineligible")
	}
}

func TestComposedPolicyNextPolicyEmptyMiddleMemberHasNoDanglingGoto11780(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {Name: "A", DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "next", NextPolicy: true},
			}},
			"EMPTY": {Name: "EMPTY"},
			"C": {Name: "C", Terms: []*config.PolicyTerm{
				{Name: "accept", Action: "accept"},
			}},
		},
	}
	const composed = "A-EMPTY-C-xpf-chain"
	got := New().renderComposedRouteMap(po, composed, []string{"A", "EMPTY", "C"})
	if strings.Contains(got, "XPF_NEXT_POLICY_SEQUENCE") {
		t.Fatalf("unresolved next-policy marker:\n%s", got)
	}
	// A renders term 10 + default 20; EMPTY contributes no sequences, so C
	// starts at 30 and lands A's goto.
	want := "route-map " + composed + " permit 10\n on-match goto 30\n"
	if !strings.Contains(got, want) {
		t.Errorf("empty middle member must not dangle the goto; missing %q:\n%s", want, got)
	}
	if !strings.Contains(got, "route-map "+composed+" permit 30\n") {
		t.Errorf("C's first sequence must land the goto at 30:\n%s", got)
	}
}

// #16872: a `then next term` term (NextTerm, no Action) must render
// identically to the same term without the marker — `permit` +
// modifiers + `on-match next` — and must NOT jump (no `on-match goto`,
// no NextPolicy default-bypass). This pins the acceptance criterion
// "renders identically to the term without it".
func TestNextTermRendersIdenticallyToFallThrough16872(t *testing.T) {
	mk := func(nextTerm bool) *config.PolicyOptionsConfig {
		return &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"P": {
					Name:          "P",
					DefaultAction: "reject",
					Terms: []*config.PolicyTerm{
						{Name: "t1", NextTerm: nextTerm, HasLocalPreference: true, LocalPreference: 200},
						{Name: "t2", Action: "accept"},
					},
				},
			},
		}
	}
	withMarker := New().generatePolicyOptions(mk(true), map[string]bool{"P": true})
	without := New().generatePolicyOptions(mk(false), map[string]bool{"P": true})
	if withMarker != without {
		t.Fatalf("next term must render identically to modifier-only fall-through:\nwith:\n%s\nwithout:\n%s", withMarker, without)
	}
	for _, want := range []string{
		"route-map P permit 10\n set local-preference 200\n on-match next\n",
		"route-map P permit 20\n",
	} {
		if !strings.Contains(withMarker, want) {
			t.Errorf("next-term render missing %q:\n%s", want, withMarker)
		}
	}
	if strings.Contains(withMarker, "on-match goto") {
		t.Errorf("next term must not jump to the next policy:\n%s", withMarker)
	}
}

// #16872 (Astra fold): contradictory continuation states constructed
// directly (as a tolerant compile that retained authored fields, or
// any non-compiler producer, could deliver) must render as deny and
// terminate — never as a terminating permit, never as a jump — and
// must not be treated as a valid next-policy jump by sequence
// counting or the narrowed-survivor shape.
func TestConflictingNextTermStatesFailClosed16872(t *testing.T) {
	for _, tc := range []struct {
		name string
		term *config.PolicyTerm
	}{
		{"next-term-plus-accept", &config.PolicyTerm{Name: "bad", Action: "accept", NextTerm: true}},
		{"next-term-plus-reject", &config.PolicyTerm{Name: "bad", Action: "reject", NextTerm: true}},
		{"next-term-plus-next-policy", &config.PolicyTerm{Name: "bad", NextTerm: true, NextPolicy: true}},
		{"next-term-plus-next-policy-plus-accept", &config.PolicyTerm{Name: "bad", Action: "accept", NextTerm: true, NextPolicy: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := &config.PolicyStatement{
				Name:          "ONLY",
				DefaultAction: "reject",
				Terms:         []*config.PolicyTerm{tc.term},
			}
			po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{"ONLY": ps}}
			body, next := New().renderPolicyTermSequences(po, "ONLY", "ONLY", ps, 10)
			if !strings.Contains(body, "route-map ONLY deny 10\n") {
				t.Fatalf("contradictory term must render as deny, got:\n%s", body)
			}
			if strings.Contains(body, "on-match goto") || strings.Contains(body, "on-match next") || strings.Contains(body, nextPolicySequenceMarker) {
				t.Fatalf("contradictory term must not continue or jump, got:\n%s", body)
			}
			if next != 20 {
				t.Fatalf("term sequence end = %d, want 20", next)
			}
			if policyHasNextPolicyTerm(ps) {
				t.Fatal("contradictory term must not be treated as a valid next-policy jump")
			}
			if got := config.RouteMapSequenceCount(po, ps); got != 1 {
				t.Fatalf("sequence count = %d, want one term sequence without a bypassable default", got)
			}
		})
	}
	// Narrowed survivor: an unconditional contradictory term is a
	// terminating deny (match-all), not a fall-through/jump.
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"BAD": {Name: "BAD", Terms: []*config.PolicyTerm{{Name: "bad", Action: "accept", NextTerm: true}}},
		"MIX": {Name: "MIX", Terms: []*config.PolicyTerm{{Name: "bad", NextTerm: true, NextPolicy: true}}},
	}}
	for _, name := range []string{"BAD", "MIX"} {
		if got := narrowedSurvivorShape10129([]string{name}, po); got != "match-all" {
			t.Fatalf("%s: unconditional contradictory term shape=%q, want match-all (terminating deny)", name, got)
		}
	}
	// Redistribute accept predicate must agree with the renderer.
	if termCanAcceptForRedist14698(&config.PolicyTerm{Action: "accept", NextTerm: true}) {
		t.Fatal("next-term+accept must not be accept-capable for redistribute (renders deny)")
	}
	if termCanAcceptForRedist14698(&config.PolicyTerm{NextTerm: true, NextPolicy: true}) {
		t.Fatal("mixed continuations must not be accept-capable for redistribute (renders deny)")
	}
}

// #16872 (Astra fold): the full tolerant-compile -> production-renderer
// pipeline for contradictory continuations. Text goes through
// CompileConfigLenient (the store Load/SyncApply compiler), whose
// result is rendered with generatePolicyOptions. The conflicting term
// must be a terminating deny; the following reject term must still be
// present (not bypassed); valid next term / next policy controls are
// unchanged. Both action orders and both group directions included.
func TestTolerantNextTermConflictsRenderDeny16872(t *testing.T) {
	renderLenient := func(t *testing.T, text string) string {
		t.Helper()
		tree, parseErrors := config.NewParser(text).Parse()
		if len(parseErrors) != 0 {
			t.Fatalf("parse: %v", parseErrors)
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if len(cfg.Warnings) == 0 {
			t.Fatalf("lenient compile of contradictory continuation produced no warning: %s", text)
		}
		return New().generatePolicyOptions(&cfg.PolicyOptions, map[string]bool{"P": true})
	}
	conflicts := []struct {
		name string
		text string
	}{
		{"accept-then-next-term", `policy-options { policy-statement P { term a { then { accept; next term; } } term b { then reject; } then reject; } }`},
		{"next-term-then-accept", `policy-options { policy-statement P { term a { then { next term; accept; } } term b { then reject; } then reject; } }`},
		{"group-next-term-inline-accept", `groups { G { policy-options { policy-statement P { term a { then next term; } } } } }
policy-options { policy-statement P { term a { then accept; } term b { then reject; } apply-groups G; } }`},
		{"group-accept-inline-next-term", `groups { G { policy-options { policy-statement P { term a { then accept; } } } } }
policy-options { policy-statement P { term a { then next term; } term b { then reject; } apply-groups G; } }`},
		{"mixed-inline", `policy-options { policy-statement P { term a { then { next term; next policy; } } term b { then reject; } then reject; } }`},
		{"mixed-group-policy-inline-term", `groups { G { policy-options { policy-statement P { term a { then next policy; } } } } }
policy-options { policy-statement P { term a { then next term; } term b { then reject; } apply-groups G; } }`},
		{"mixed-group-term-inline-policy", `groups { G { policy-options { policy-statement P { term a { then next term; } } } } }
policy-options { policy-statement P { term a { then next policy; } term b { then reject; } apply-groups G; } }`},
	}
	for _, tc := range conflicts {
		t.Run(tc.name, func(t *testing.T) {
			got := renderLenient(t, tc.text)
			if !strings.Contains(got, "route-map P deny 10\n") {
				t.Fatalf("conflicting term a must render terminating deny 10, got:\n%s", got)
			}
			if strings.Contains(got, "route-map P permit 10") {
				t.Fatalf("conflicting term a must not terminate in permit, got:\n%s", got)
			}
			if strings.Contains(got, "on-match goto") || strings.Contains(got, "on-match next") {
				t.Fatalf("conflicting term must not continue/jump past term b, got:\n%s", got)
			}
			if !strings.Contains(got, "route-map P deny 20\n") {
				t.Fatalf("term b reject must still render at 20, got:\n%s", got)
			}
		})
	}
	// Controls: valid actionless next term falls through with its
	// modifier and no goto; valid next policy still jumps. These go
	// through strict compile (they must commit) and the same renderer.
	renderStrict := func(t *testing.T, text string) string {
		t.Helper()
		tree, parseErrors := config.NewParser(text).Parse()
		if len(parseErrors) != 0 {
			t.Fatalf("parse: %v", parseErrors)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile of valid control: %v", err)
		}
		return New().generatePolicyOptions(&cfg.PolicyOptions, map[string]bool{"P": true})
	}
	got := renderStrict(t, `policy-options { policy-statement P { term a { then { local-preference 200; next term; } } term b { then accept; } } }`)
	if !strings.Contains(got, "route-map P permit 10\n set local-preference 200\n on-match next\n") ||
		!strings.Contains(got, "route-map P permit 20\n") || strings.Contains(got, "on-match goto") {
		t.Fatalf("valid next term control must fall through to term b, got:\n%s", got)
	}
	got = renderStrict(t, `policy-options { policy-statement P { term a { then next policy; } term b { then reject; } then reject; } }`)
	if !strings.Contains(got, "on-match goto") {
		t.Fatalf("valid next policy control must still jump, got:\n%s", got)
	}
}
