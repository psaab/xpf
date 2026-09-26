package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10822 fail-closed term rule, the community sibling of the #9881 as-path
// rule. The #8449 belt omits a community definition with a member failing
// ValidCommunityMember, but referencing terms still emitted
// `match community <name>` without a matching list definition. Depending on
// FRR admission/evaluation, that dangling reference can stall a reload or
// fail to match; either way, it cannot enforce the intended reject. This term
// rule completes the belt: reject terms over absent lists render deny-all,
// other terms skip the dangling branch, and no `match community` line dangles.

// communityPolicyPO builds a PolicyOptions carrying community defs plus one
// policy P.
func communityPolicyPO(defs map[string]*config.CommunityDef, terms []*config.PolicyTerm, defAction string) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		Communities: defs,
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: terms, DefaultAction: defAction},
		},
	}
}

// badCommunityMember10822 forces the expanded list kind but is not valid
// POSIX, so the #8449 belt omits its whole definition (same member the #8449
// belt test uses).
const badCommunityMember10822 = "65000:["

// TestRejectThenAcceptPolicyRendersFailClosed_10822 drives the full route-map
// the finding is about: a reject term over an omitted-member list followed by
// an accept, with a permit trailing default. The definition-only #8449 cells
// cannot detect the missing-reference hole — this one renders the whole policy
// and asserts the reject is lowered to a bare deny-all with no dangling
// reference.
//
// FAIL-ON-REVERT: deleting the term rule renders
// `route-map P deny 10` + ` match community C1` instead of deny-all — red here.
func TestRejectThenAcceptPolicyRendersFailClosed_10822(t *testing.T) {
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{badCommunityMember10822}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromCommunity: []string{"C1"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		},
		"accept",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match community") {
		t.Fatalf("a dangling `match community` was emitted instead of lowering "+
			"the reject to deny-all:\n%s", got)
	}
	if strings.Contains(got, " C1 permit") {
		t.Fatalf("the omitted-member list was emitted:\n%s", got)
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

// TestRejectTermWithMixedORRefsDeniesAll_10822: one dangling OR-branch poisons
// the whole reject term — dropping just that branch would fail open for its
// unknowable set, so the term renders as a single deny-all and even the fine
// branch folds into it.
func TestRejectTermWithMixedORRefsDeniesAll_10822(t *testing.T) {
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{badCommunityMember10822}},
			"C2": {Name: "C2", Members: []string{"65000:200"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromCommunity: []string{"C1", "C2"}, Action: "reject"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match community") {
		t.Fatalf("a dangling OR-branch survived:\n%s", got)
	}
	if !strings.Contains(got, "bgp community-list standard C2 permit 65000:200\n") {
		t.Fatalf("the FINE list was dropped with the omitted one:\n%s", got)
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

// TestAcceptTermSkipsDanglingBranchKeepsFine_10822: for accept the sound
// direction is the subset — the dangling branch drops while the fine branch
// still emits, so the term accepts strictly less than intended, never more.
func TestAcceptTermSkipsDanglingBranchKeepsFine_10822(t *testing.T) {
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{badCommunityMember10822}},
			"C2": {Name: "C2", Members: []string{"65000:200"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-accept", FromCommunity: []string{"C1", "C2"}, Action: "accept"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match community C1") {
		t.Fatalf("the dangling branch was emitted:\n%s", got)
	}
	if !strings.Contains(got, "match community C2") {
		t.Fatalf("the fine branch was dropped with the dangling one:\n%s", got)
	}
	if n := strings.Count(got, "route-map P permit "); n != 1 {
		t.Fatalf("expected 1 permit term sequence (C2 only), got %d:\n%s", n, got)
	}
}

// TestAcceptTermWithOnlyDanglingRefEmitsNothing_10822: an accept term whose
// only match dangles emits no sequence at all and falls through — it must
// NOT degrade to a bare permit, which FRR reads as match-ALL (the #2110
// shape: dropping the match line would flip "accept nothing provable" to
// "accept everything").
func TestAcceptTermWithOnlyDanglingRefEmitsNothing_10822(t *testing.T) {
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{badCommunityMember10822}},
		},
		[]*config.PolicyTerm{
			{Name: "t-accept", FromCommunity: []string{"C1"}, Action: "accept"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match community") {
		t.Fatalf("a dangling match was emitted:\n%s", got)
	}
	if strings.Contains(got, "route-map P permit") {
		t.Fatalf("the dangling accept degraded to a permit — match-ALL fail-open:\n%s", got)
	}
	if n := strings.Count(got, "route-map P "); n != 1 {
		t.Fatalf("expected only the trailing deny, got %d route-map lines:\n%s", n, got)
	}
}

// TestNonTerminatingTermSkipsDanglingMatch_10822: a modifying term over a
// dangling list skips the branch rather than emitting a reference to an absent
// definition — and rather than dropping the match line, which would leave a
// bare permit + on-match next applying the modification to EVERY route.
func TestNonTerminatingTermSkipsDanglingMatch_10822(t *testing.T) {
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{badCommunityMember10822}},
		},
		[]*config.PolicyTerm{
			{Name: "t-mod", FromCommunity: []string{"C1"}, CommunityAdd: "65000:100", CommunityOp: "add"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match community") || strings.Contains(got, "set community") {
		t.Fatalf("the dangling modifying branch was emitted:\n%s", got)
	}
	if n := strings.Count(got, "route-map P "); n != 1 {
		t.Fatalf("expected only the trailing deny, got %d route-map lines:\n%s", n, got)
	}
}

// TestUndefinedCommunityRejectTermDeniesAll_10822 pins the undefined-name half
// of the unified predicate: a name with no definition is absent from the
// rendered community lists, just like an omitted-member list. The strict #2881
// reference gate only warns on the tolerant load path, so the renderer must
// handle this case too.
func TestUndefinedCommunityRejectTermDeniesAll_10822(t *testing.T) {
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{"65000:100"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-nosuch", FromCommunity: []string{"NOSUCH"}, Action: "reject"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "match community") {
		t.Fatalf("a dangling match survived:\n%s", got)
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

// TestValidCommunityListsRenderMatchLines_10822 is the tightening control:
// terms over fully valid lists must keep their `match community` lines in
// both directions. A belt that narrows working configs is worse than the bug
// it fixes.
func TestValidCommunityListsRenderMatchLines_10822(t *testing.T) {
	po := communityPolicyPO(
		map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{"65000:100"}},
		},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromCommunity: []string{"C1"}, Action: "reject"},
			{Name: "t-accept", FromCommunity: []string{"C1"}, Action: "accept"},
		},
		"reject",
	)
	got := New().generatePolicyOptions(po)
	if !strings.Contains(got, "bgp community-list standard C1 permit 65000:100\n") {
		t.Fatalf("the valid list was omitted:\n%s", got)
	}
	if n := strings.Count(got, "match community C1"); n != 2 {
		t.Fatalf("expected both valid terms to keep their match lines, got %d:\n%s", n, got)
	}
}
