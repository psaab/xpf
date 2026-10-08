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
