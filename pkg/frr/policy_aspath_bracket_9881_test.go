package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9881 render-side belt + fail-closed term rule. The strict commit gate
// rejects an as-path whose regex was joined from unquoted-bracketed tokens
// (`[0-9]+` becomes the valid-but-different `0-9 +`), but the tolerant load /
// peer-sync paths downgrade that to a warning (#1960 no-brick), so such a
// definition CAN reach the renderer. It must not be emitted: the pattern
// matches a set nobody authored. Omission alone is NOT fail-closed — a
// stripped single-token regex can match real AS paths, so a referencing
// REJECT term that kept its `match as-path` line would silently never fire
// (dangling match = NO MATCH) and fall through to a later accept or the BGP
// permit default. The term rule completes the belt: reject terms over absent
// lists render deny-all, other terms skip the dangling branch — so no
// `match as-path` line ever dangles (the #9493 doctrine).

func aspathFlaggedPO(t *testing.T, name, regex string, flagged bool) *config.PolicyOptionsConfig {
	t.Helper()
	return &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			name: {Name: name, Regex: regex, RegexUnquotedBracket: flagged},
		},
	}
}

// TestASPathRender9881OmitsBracketFlaggedRegex is the belt itself.
//
// FAIL-ON-REVERT: deleting the RegexUnquotedBracket `continue` from
// generatePolicyOptions emits `bgp as-path access-list AP1 permit 0-9 +`,
// which reds here.
func TestASPathRender9881OmitsBracketFlaggedRegex(t *testing.T) {
	got := New().generatePolicyOptions(aspathFlaggedPO(t, "AP1", "0-9 +", true))
	if strings.Contains(got, "bgp as-path access-list AP1") {
		t.Fatalf("a bracket-flagged as-path reached frr.conf — the emitted pattern "+
			"matches a set the operator never wrote:\n%s", got)
	}
}

// TestASPathRender9881EmitsUnflaggedSameRegex is the tightening control: the
// byte-identical regex WITHOUT the flag (provenance-clean authorship) must
// still render. The belt keys on provenance, never on the regex text.
func TestASPathRender9881EmitsUnflaggedSameRegex(t *testing.T) {
	got := New().generatePolicyOptions(aspathFlaggedPO(t, "AP1", "0-9 +", false))
	if !strings.Contains(got, "bgp as-path access-list AP1 permit 0-9 +\n") {
		t.Fatalf("an unflagged as-path regex was omitted — the belt keys on the "+
			"flag, not the text:\n%s", got)
	}
}

// aspathPolicyPO builds a PolicyOptions carrying defs plus one policy P.
func aspathPolicyPO(defs map[string]*config.ASPathDef, terms []*config.PolicyTerm, defAction string) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		ASPaths: defs,
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: terms, DefaultAction: defAction},
		},
	}
}

// TestRejectThenAcceptPolicyRendersFailClosed_9881 drives the full route-map
// the HIGH finding is about: a reject term over a flagged list followed by
// an accept, with a permit trailing default. The definition-only cells above
// cannot detect the fall-through hole — this one renders the whole policy
// and asserts the reject survives as a bare deny-all with no dangling
// reference left for FRR to no-match past.
//
// FAIL-ON-REVERT: deleting the term rule renders
// `route-map P deny 10` + ` match as-path AP1`, which never fires, so every
// route falls through to the permit — red here on the dangling line.
func TestRejectThenAcceptPolicyRendersFailClosed_9881(t *testing.T) {
	po := aspathPolicyPO(
		map[string]*config.ASPathDef{
			"AP1": {Name: "AP1", Regex: "0-9 +", RegexUnquotedBracket: true},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromASPath: []string{"AP1"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		},
		"accept",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match as-path") {
		t.Fatalf("a dangling `match as-path` survived — FRR no-matches it and the "+
			"reject falls through to the permit:\n%s", got)
	}
	if strings.Contains(got, "bgp as-path access-list AP1") {
		t.Fatalf("the flagged list was emitted:\n%s", got)
	}
	// deny-all 10 (the reject, fail-closed), bare permit 20 (t-accept has no
	// matches), bare permit 30 (the accept trailing default).
	for _, want := range []string{
		"route-map P deny 10\nexit\n",
		"route-map P permit 20\nexit\n",
		"route-map P permit 30\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// TestRejectTermWithMixedORRefsDeniesAll_9881: one dangling OR-branch poisons
// the whole reject term — dropping just that branch would fail open for its
// unknowable set, so the term renders as a single deny-all and even the fine
// branch folds into it.
func TestRejectTermWithMixedORRefsDeniesAll_9881(t *testing.T) {
	po := aspathPolicyPO(
		map[string]*config.ASPathDef{
			"AP1": {Name: "AP1", Regex: "0-9 +", RegexUnquotedBracket: true},
			"AP2": {Name: "AP2", Regex: "65002"},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromASPath: []string{"AP1", "AP2"}, Action: "reject"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match as-path") {
		t.Fatalf("a dangling OR-branch survived:\n%s", got)
	}
	if !strings.Contains(got, "bgp as-path access-list AP2 permit 65002\n") {
		t.Fatalf("the FINE list was dropped with the flagged one:\n%s", got)
	}
	for _, want := range []string{
		"route-map P deny 10\nexit\n",
		"route-map P deny 20\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// TestAcceptTermSkipsDanglingBranchKeepsFine_9881: for accept the sound
// direction is the subset — the dangling branch drops while the fine branch
// still emits, so the term accepts strictly less than intended, never more.
func TestAcceptTermSkipsDanglingBranchKeepsFine_9881(t *testing.T) {
	po := aspathPolicyPO(
		map[string]*config.ASPathDef{
			"AP1": {Name: "AP1", Regex: "0-9 +", RegexUnquotedBracket: true},
			"AP2": {Name: "AP2", Regex: "65002"},
		},
		[]*config.PolicyTerm{
			{Name: "t-accept", FromASPath: []string{"AP1", "AP2"}, Action: "accept"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match as-path AP1") {
		t.Fatalf("the dangling branch was emitted:\n%s", got)
	}
	if !strings.Contains(got, "match as-path AP2") {
		t.Fatalf("the fine branch was dropped with the dangling one:\n%s", got)
	}
	if n := strings.Count(got, "route-map P permit "); n != 1 {
		t.Fatalf("expected 1 permit term sequence (AP2 only), got %d:\n%s", n, got)
	}
}

// TestAcceptTermWithOnlyDanglingRefEmitsNothing_9881: an accept term whose
// only match dangles emits no sequence at all and falls through — it must
// NOT degrade to a bare permit, which FRR reads as match-ALL (the #2110
// shape: dropping the match line would flip "accept nothing provable" to
// "accept everything").
func TestAcceptTermWithOnlyDanglingRefEmitsNothing_9881(t *testing.T) {
	po := aspathPolicyPO(
		map[string]*config.ASPathDef{
			"AP1": {Name: "AP1", Regex: "0-9 +", RegexUnquotedBracket: true},
		},
		[]*config.PolicyTerm{
			{Name: "t-accept", FromASPath: []string{"AP1"}, Action: "accept"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match as-path") {
		t.Fatalf("a dangling match was emitted:\n%s", got)
	}
	if strings.Contains(got, "route-map P permit") {
		t.Fatalf("the dangling accept degraded to a permit — match-ALL fail-open:\n%s", got)
	}
	if n := strings.Count(got, "route-map P "); n != 1 {
		t.Fatalf("expected only the trailing deny, got %d route-map lines:\n%s", n, got)
	}
}

// TestNonTerminatingTermSkipsDanglingMatch_9881: a modifying term over a
// dangling list skips the branch rather than emitting a match that can never
// fire — and rather than dropping the match line, which would leave a bare
// permit + on-match next applying the modification to EVERY route.
func TestNonTerminatingTermSkipsDanglingMatch_9881(t *testing.T) {
	po := aspathPolicyPO(
		map[string]*config.ASPathDef{
			"AP1": {Name: "AP1", Regex: "0-9 +", RegexUnquotedBracket: true},
		},
		[]*config.PolicyTerm{
			{Name: "t-mod", FromASPath: []string{"AP1"}, CommunityAdd: "65000:100", CommunityOp: "add"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match as-path") || strings.Contains(got, "set community") {
		t.Fatalf("the dangling modifying branch was emitted:\n%s", got)
	}
	if n := strings.Count(got, "route-map P "); n != 1 {
		t.Fatalf("expected only the trailing deny, got %d route-map lines:\n%s", n, got)
	}
}

// TestUnrenderableAndUndefinedRejectTermsDenyAll_9881 pins the unified
// predicate: an invalid regex (#6686-omitted) and an undefined name dangle
// exactly like a flagged list, so reject terms over them render deny-all
// too — the same fall-through hole, the same fix.
func TestUnrenderableAndUndefinedRejectTermsDenyAll_9881(t *testing.T) {
	po := aspathPolicyPO(
		map[string]*config.ASPathDef{
			"APBAD": {Name: "APBAD", Regex: "((("},
		},
		[]*config.PolicyTerm{
			{Name: "t-bad", FromASPath: []string{"APBAD"}, Action: "reject"},
			{Name: "t-nosuch", FromASPath: []string{"NOSUCH"}, Action: "reject"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match as-path") {
		t.Fatalf("a dangling match survived:\n%s", got)
	}
	for _, want := range []string{
		"route-map P deny 10\nexit\n",
		"route-map P deny 20\nexit\n",
		"route-map P deny 30\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
