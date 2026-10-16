package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14136 fail-closed term rule, the prefix-list sibling of the #9881 as-path
// and #10822 community rules. The #10823 belt omits malformed prefix-list
// entries (and undefined names have no definition at all), but referencing
// terms still emitted `match ip|ipv6 address prefix-list <name>` without a
// matching list definition. FRR resolves a dangling match to NO MATCH, so a
// `then reject` term silently never fires and its routes fall through to a
// later accept or the BGP permit default. This term rule completes the belt:
// reject terms over absent lists render deny-all, other terms skip the
// dangling branch, and no `match ... prefix-list` line dangles.

// prefixListPolicyPO builds a PolicyOptions carrying prefix-list defs plus
// one policy P.
func prefixListPolicyPO(defs map[string]*config.PrefixList, terms []*config.PolicyTerm, defAction string) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PrefixLists: defs,
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: terms, DefaultAction: defAction},
		},
	}
}

// TestRejectThenAcceptPrefixListRendersFailClosed_14136 drives the full
// route-map the finding is about: a reject term over an undefined list
// followed by an accept, with a permit trailing default.
//
// FAIL-ON-REVERT: deleting the term rule renders
// `route-map P deny 10` + ` match ip address prefix-list NOSUCH` instead of
// deny-all — red here.
func TestRejectThenAcceptPrefixListRendersFailClosed_14136(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{},
		[]*config.PolicyTerm{
			{Name: "t-reject", PrefixList: []string{"NOSUCH"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		},
		"accept",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "address prefix-list NOSUCH") {
		t.Fatalf("a dangling `match ... prefix-list NOSUCH` was emitted instead of lowering "+
			"the reject to deny-all:\n%s", got)
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

// TestRejectAllMalformedPrefixListDeniesAll_14136 pins the all-skipped half:
// every entry fails net.ParseCIDR, so the #10823 belt emits no definition.
func TestRejectAllMalformedPrefixListDeniesAll_14136(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{
			"BAD": {Name: "BAD", Prefixes: []string{"999.0.0.0/8", "not-a-cidr"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", PrefixList: []string{"BAD"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		},
		"accept",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "prefix-list BAD seq") {
		t.Fatalf("a malformed entry was emitted:\n%s", got)
	}
	if strings.Contains(got, "address prefix-list BAD") {
		t.Fatalf("a dangling `match ... prefix-list BAD` was emitted:\n%s", got)
	}
	for _, want := range []string{
		"route-map P deny 10\nexit\n",
		"route-map P permit 20\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// TestRejectPrefixListMixedORRefsDeniesAll_14136: one dangling OR-branch
// poisons the whole reject term — dropping just that branch would fail open
// for its unknowable set, so the term renders as a single deny-all and even
// the fine branch folds into it.
func TestRejectPrefixListMixedORRefsDeniesAll_14136(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{
			"GOOD": {Name: "GOOD", Prefixes: []string{"10.0.0.0/8"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", PrefixList: []string{"NOSUCH", "GOOD"}, Action: "reject"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "address prefix-list") {
		t.Fatalf("a dangling OR-branch survived:\n%s", got)
	}
	if !strings.Contains(got, "ip prefix-list GOOD seq 5 permit 10.0.0.0/8\n") {
		t.Fatalf("the FINE list definition was dropped with the undefined one:\n%s", got)
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

// TestAcceptPrefixListSkipsDanglingBranchKeepsFine_14136: for accept the
// sound direction is the subset — the dangling branch drops while the fine
// branch still emits, so the term accepts strictly less than intended, never
// more.
func TestAcceptPrefixListSkipsDanglingBranchKeepsFine_14136(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{
			"GOOD": {Name: "GOOD", Prefixes: []string{"10.0.0.0/8"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-accept", PrefixList: []string{"NOSUCH", "GOOD"}, Action: "accept"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "address prefix-list NOSUCH") {
		t.Fatalf("the dangling branch was emitted:\n%s", got)
	}
	if !strings.Contains(got, "match ip address prefix-list GOOD") {
		t.Fatalf("the fine branch was dropped with the dangling one:\n%s", got)
	}
	if n := strings.Count(got, "route-map P permit "); n != 1 {
		t.Fatalf("expected 1 permit term sequence (GOOD only), got %d:\n%s", n, got)
	}
}

// TestAcceptPrefixListOnlyDanglingEmitsNothing_14136: an accept term whose
// only match dangles emits no sequence at all and falls through — it must
// NOT degrade to a bare permit, which FRR reads as match-ALL.
func TestAcceptPrefixListOnlyDanglingEmitsNothing_14136(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{},
		[]*config.PolicyTerm{
			{Name: "t-accept", PrefixList: []string{"NOSUCH"}, Action: "accept"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "address prefix-list NOSUCH") {
		t.Fatalf("a dangling match was emitted:\n%s", got)
	}
	if strings.Contains(got, "route-map P permit") {
		t.Fatalf("the dangling accept degraded to a permit — match-ALL fail-open:\n%s", got)
	}
	if n := strings.Count(got, "route-map P "); n != 1 {
		t.Fatalf("expected only the trailing deny, got %d route-map lines:\n%s", n, got)
	}
}

// TestNonTerminatingPrefixListSkipsDanglingMatch_14136: a modifying term
// over a dangling list skips the branch rather than emitting a reference to
// an absent definition — and rather than dropping the match line, which
// would leave a bare permit + on-match next applying the modification to
// EVERY route.
func TestNonTerminatingPrefixListSkipsDanglingMatch_14136(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{},
		[]*config.PolicyTerm{
			{Name: "t-mod", PrefixList: []string{"NOSUCH"}, HasLocalPreference: true, LocalPreference: 200},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "address prefix-list NOSUCH") || strings.Contains(got, "set local-preference") {
		t.Fatalf("the dangling modifying branch was emitted:\n%s", got)
	}
	if n := strings.Count(got, "route-map P "); n != 1 {
		t.Fatalf("expected only the trailing deny, got %d route-map lines:\n%s", n, got)
	}
}

// TestMixedPrefixListPartiallyMalformed_14136 pins the per-family half: a
// mixed list whose v6 entries are all malformed has no rendered v6
// definition, so its ipv6 ref dangles even though its v4 ref is fine. Both
// directions keep the fine v4 branch and drop only the dangling v6 ref; a
// reject is NOT broadened to deny-all for routes its fine branch would not
// have rejected (see the term-rule comment in policy_render.go).
func TestMixedPrefixListPartiallyMalformed_14136(t *testing.T) {
	defs := map[string]*config.PrefixList{
		"PARTIAL": {Name: "PARTIAL", Prefixes: []string{"10.0.0.0/8", "2001:db8::/999"}},
	}

	rejectPO := prefixListPolicyPO(defs, []*config.PolicyTerm{
		{Name: "t-reject", PrefixList: []string{"PARTIAL"}, Action: "reject"},
	}, "reject")
	got := New().generatePolicyOptions(rejectPO)
	if !strings.Contains(got, "route-map P deny 10\n match ip address prefix-list PARTIAL\nexit\n") {
		t.Fatalf("reject dropped the fine v4 branch:\n%s", got)
	}
	if strings.Contains(got, "match ipv6 address prefix-list PARTIAL") {
		t.Fatalf("reject kept the dangling v6 branch:\n%s", got)
	}
	if n := strings.Count(got, "route-map P deny "); n != 2 {
		t.Fatalf("expected 1 deny term sequence (v4 only) + trailing deny, got %d:\n%s", n, got)
	}

	acceptPO := prefixListPolicyPO(defs, []*config.PolicyTerm{
		{Name: "t-accept", PrefixList: []string{"PARTIAL"}, Action: "accept"},
	}, "reject")
	got = New().generatePolicyOptions(acceptPO)
	if !strings.Contains(got, "match ip address prefix-list PARTIAL") {
		t.Fatalf("accept dropped the fine v4 branch:\n%s", got)
	}
	if strings.Contains(got, "match ipv6 address prefix-list PARTIAL") {
		t.Fatalf("accept kept the dangling v6 branch:\n%s", got)
	}
	if n := strings.Count(got, "route-map P permit "); n != 1 {
		t.Fatalf("expected 1 permit term sequence (v4 only), got %d:\n%s", n, got)
	}
}

// TestValidPrefixListsRenderMatchLines_14136 is the tightening control:
// terms over fully valid lists must keep their match lines in both
// directions. A belt that narrows working configs is worse than the bug it
// fixes.
func TestValidPrefixListsRenderMatchLines_14136(t *testing.T) {
	po := prefixListPolicyPO(
		map[string]*config.PrefixList{
			"GOOD": {Name: "GOOD", Prefixes: []string{"10.0.0.0/8", "2001:db8::/32"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", PrefixList: []string{"GOOD"}, Action: "reject"},
			{Name: "t-accept", PrefixList: []string{"GOOD"}, Action: "accept"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if !strings.Contains(got, "ip prefix-list GOOD seq 5 permit 10.0.0.0/8\n") ||
		!strings.Contains(got, "ipv6 prefix-list GOOD seq 10 permit 2001:db8::/32\n") {
		t.Fatalf("the valid list was omitted:\n%s", got)
	}
	if n := strings.Count(got, "match ip address prefix-list GOOD"); n != 2 {
		t.Fatalf("expected both valid terms to keep their v4 match lines, got %d:\n%s", n, got)
	}
	if n := strings.Count(got, "match ipv6 address prefix-list GOOD"); n != 2 {
		t.Fatalf("expected both valid terms to keep their v6 match lines, got %d:\n%s", n, got)
	}
}
