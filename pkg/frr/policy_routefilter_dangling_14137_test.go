package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14137 fail-closed term rule, the route-filter sibling of the #9881
// as-path, #10822 community, and #14136 from-prefix-list rules.
//
// renderRouteFilterEntry skips an entry — malformed prefix (e.g. a
// match-type keyword in the prefix slot, `route-filter longer exact`),
// unknown/through match-type, malformed prefix-length-range, bad upto,
// max-length `longer` — and writes NO inline prefix-list definition.
// emitTermBody nevertheless emitted `match ip|ipv6 address prefix-list
// <inline>` against the then-undefined list, documented as fail-closed
// because FRR resolves an undefined list to NOMATCH. That reasoning is
// sound for a PERMIT term (the term simply never fires) but fail-OPEN
// for a DENY (reject) term: NOMATCH means the deny sequence never
// terminates evaluation, so the route falls through to a later permit
// or the BGP trailing permit default. The same hole is reached on the
// tolerant path when failClosedInheritedInvalidRouteFilters12687 turns
// an inherited invalid term into Action="reject" without making its
// skipped filter match (non-inherited tolerant garbage reaches the
// renderer in the same state). This term rule completes the belt:
// when a family group renders zero route-filter entries, reject terms
// render deny-all for that group and other terms skip that group —
// never a dangling inline prefix-list match. A group with at least one
// rendered entry (including the /32 longer control's fine siblings)
// keeps its match line; a legitimately empty set (`10.0.0.0/32 longer`
// as the sole filter) is NOT invalid and never broadens.

// routeFilterPolicyPO builds a PolicyOptions carrying one policy P with
// the given terms, plus the BGP trailing default implied by defAction.
func routeFilterPolicyPO(terms []*config.PolicyTerm, defAction string) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: terms, DefaultAction: defAction},
		},
	}
}

// rejectMalformedThenAccept14137 is the decisive fixture: a reject term
// whose sole route-filter is malformed, followed by a bare accept.
func rejectMalformedThenAccept14137(rf *config.RouteFilter) *config.PolicyOptionsConfig {
	return routeFilterPolicyPO([]*config.PolicyTerm{
		{Name: "t-reject", RouteFilters: []*config.RouteFilter{rf}, Action: "reject"},
		{Name: "t-accept", Action: "accept"},
	}, "accept")
}

// TestRejectMalformedRouteFilterDeniesAll_14137 is the decisive regression:
// a reject term whose sole route-filter renders no entry (keyword in the
// prefix slot — the `route-filter longer exact` shape) must render a bare
// deny-all, not a deny sequence carrying a dangling match against an
// undefined inline list. On current master the dangling deny never fires
// and the route is admitted by the following accept / trailing permit.
//
// FAIL-ON-REVERT: removing the route-filter term rule renders
// `route-map P deny 10` + ` match ip address prefix-list <inline>` with
// no `ip prefix-list <inline> seq` definition — red here.
func TestRejectMalformedRouteFilterDeniesAll_14137(t *testing.T) {
	po := rejectMalformedThenAccept14137(&config.RouteFilter{Prefix: "longer", MatchType: "exact"})
	got := New().generatePolicyOptions(po)
	inlineName := inlinePrefixListName("P", "P", "t-reject", "")
	if strings.Contains(got, "address prefix-list "+inlineName) {
		t.Fatalf("a dangling `match ... prefix-list %s` was emitted instead of lowering "+
			"the reject to deny-all:\n%s", inlineName, got)
	}
	if strings.Contains(got, "ip prefix-list "+inlineName+" seq") {
		t.Fatalf("a malformed entry was materialised:\n%s", got)
	}
	// deny-all 10 (the reject, fail-closed), bare permit 20 (t-accept has
	// no matches), bare permit 30 (the accept trailing default).
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

// TestRejectInvalidRouteFilterVariantsDenyAll_14137 pins the same term rule
// across every skip reason renderRouteFilterEntry has: an invalid OR-branch
// of a reject term has an unknowable match set, so the only sound
// fail-closed render is deny-all for that family group.
func TestRejectInvalidRouteFilterVariantsDenyAll_14137(t *testing.T) {

	cases := []struct {
		name string
		rf   *config.RouteFilter
	}{
		{"unknown match-type", &config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "orlongerr"}},
		{"through", &config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "through", ThroughPrefix: "10.1.0.0/16"}},
		{"malformed prefix-length-range", &config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "prefix-length-range", RangeLow: 4, RangeHigh: 24}},
		{"bad upto", &config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "upto", UptoLen: 4}},
		{"unset upto", &config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "upto"}},
		{"malformed v6 prefix", &config.RouteFilter{Prefix: "2001:db8::/999", MatchType: "exact"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			po := rejectMalformedThenAccept14137(tc.rf)
			got := New().generatePolicyOptions(po)
			if strings.Contains(got, "address prefix-list") {
				t.Fatalf("a dangling route-filter match was emitted:\n%s", got)
			}
			if !strings.Contains(got, "route-map P deny 10\nexit\n") {
				t.Fatalf("reject over an all-skipped route-filter did not render deny-all:\n%s", got)
			}
			if !strings.Contains(got, "route-map P permit 20\nexit\n") {
				t.Fatalf("the following accept term was lost:\n%s", got)
			}
		})
	}
}

// TestAcceptInvalidRouteFilterEmitsNothing_14137: for accept the sound
// direction is the subset — the all-skipped term emits no sequence and
// falls through to the policy default; it must NOT degrade to a bare
// permit (FRR match-ALL) and must NOT broaden to deny-all.
func TestAcceptInvalidRouteFilterEmitsNothing_14137(t *testing.T) {
	po := routeFilterPolicyPO([]*config.PolicyTerm{
		{Name: "t-accept", RouteFilters: []*config.RouteFilter{{Prefix: "longer", MatchType: "exact"}}, Action: "accept"},
	}, "reject")
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "address prefix-list") {
		t.Fatalf("a dangling route-filter match was emitted:\n%s", got)
	}
	if strings.Contains(got, "route-map P permit") {
		t.Fatalf("the dangling accept degraded to a permit — match-ALL fail-open:\n%s", got)
	}
	if n := strings.Count(got, "route-map P "); n != 1 {
		t.Fatalf("expected only the trailing deny, got %d route-map lines:\n%s", n, got)
	}
}

// TestNonTerminatingInvalidRouteFilterSkips_14137: a modifying term over an
// all-skipped route-filter emits no sequence — dropping the match line
// would leave a bare permit + on-match next applying the modification to
// EVERY route, and deny-all would wrongly terminate routes the term
// never decided.
func TestNonTerminatingInvalidRouteFilterSkips_14137(t *testing.T) {
	po := routeFilterPolicyPO([]*config.PolicyTerm{
		{Name: "t-mod", RouteFilters: []*config.RouteFilter{{Prefix: "longer", MatchType: "exact"}}, HasLocalPreference: true, LocalPreference: 200},
	}, "reject")
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "address prefix-list") || strings.Contains(got, "set local-preference") {
		t.Fatalf("the dangling modifying branch was emitted:\n%s", got)
	}
	if n := strings.Count(got, "route-map P "); n != 1 {
		t.Fatalf("expected only the trailing deny, got %d route-map lines:\n%s", n, got)
	}
}

// TestRejectMixedRouteFilterKeepsValidEntry_14137: a reject term with one
// valid and one skipped route-filter in the SAME family group keeps its
// match line against the rendered (partial) list. Route-filters within a
// term are OR'd, and the skipped entry's Junos match set is honestly
// empty-or-invalid, so the rendered subset is the fail-closed direction;
// deny-all would deny routes the valid branch never rejected.
func TestRejectMixedRouteFilterKeepsValidEntry_14137(t *testing.T) {
	po := routeFilterPolicyPO([]*config.PolicyTerm{
		{Name: "t-reject", RouteFilters: []*config.RouteFilter{
			{Prefix: "longer", MatchType: "exact"},
			{Prefix: "10.0.0.0/8", MatchType: "exact"},
		}, Action: "reject"},
	}, "reject")
	got := New().generatePolicyOptions(po)
	inlineName := inlinePrefixListName("P", "P", "t-reject", "")
	if !strings.Contains(got, "ip prefix-list "+inlineName+" seq 10 permit 10.0.0.0/8\n") {
		t.Fatalf("the valid sibling entry was dropped:\n%s", got)
	}
	if !strings.Contains(got, "route-map P deny 10\n match ip address prefix-list "+inlineName+"\nexit\n") {
		t.Fatalf("the partially-rendered reject lost its match line or broadened to deny-all:\n%s", got)
	}
}

// TestRejectSplitMixedFamilyInvalidHalfDeniesAll_14137 pins the split
// half: a mixed-family reject term splits into per-family sequences; the
// family whose only route-filter is invalid renders deny-all for that
// family group while the valid family keeps its match line. Deny-all
// for the INVALID family only denies routes of that family reaching the
// term — a v6 route can never match the (valid) v4 sequence — so this
// does not broaden past the term's own family scope.
func TestRejectSplitMixedFamilyInvalidHalfDeniesAll_14137(t *testing.T) {
	po := routeFilterPolicyPO([]*config.PolicyTerm{
		{Name: "t-reject", RouteFilters: []*config.RouteFilter{
			{Prefix: "2001:db8::/999", MatchType: "exact"},
			{Prefix: "10.0.0.0/8", MatchType: "exact"},
		}, Action: "reject"},
	}, "reject")
	got := New().generatePolicyOptions(po)
	v6Name := inlinePrefixListName("P", "P", "t-reject", "_v6")
	v4Name := inlinePrefixListName("P", "P", "t-reject", "_v4")
	if strings.Contains(got, "address prefix-list "+v6Name) {
		t.Fatalf("a dangling v6 route-filter match was emitted:\n%s", got)
	}
	// v4 first (valid, seq 10), then the invalid v6 group as deny-all 20,
	// then the trailing deny 30.
	if !strings.Contains(got, "route-map P deny 20\nexit\n") {
		t.Fatalf("the invalid v6 half did not render deny-all:\n%s", got)
	}
	if !strings.Contains(got, "match ip address prefix-list "+v4Name) {
		t.Fatalf("the valid v4 half lost its match line:\n%s", got)
	}
}

// TestRejectLongerEmptySetNotBroadened_14137 is the /32 longer control the
// issue calls out: `10.0.0.0/32 longer` is a VALID route-filter whose
// match set is legitimately empty — it must NOT be broadened to deny-all.
// The deny sequence keeps its (undefined-list) match line and matches
// nothing, so the following accept still admits routes. The same holds
// for an accept term over the empty set.
func TestRejectLongerEmptySetNotBroadened_14137(t *testing.T) {
	po := rejectMalformedThenAccept14137(&config.RouteFilter{Prefix: "10.0.0.0/32", MatchType: "longer"})
	got := New().generatePolicyOptions(po)
	inlineName := inlinePrefixListName("P", "P", "t-reject", "")
	if strings.Contains(got, "ip prefix-list "+inlineName+" seq") {
		t.Fatalf("the empty-set /32 longer materialised an entry:\n%s", got)
	}
	if !strings.Contains(got, "route-map P deny 10\n match ip address prefix-list "+inlineName+"\nexit\n") {
		t.Fatalf("the legitimately-empty reject was broadened to deny-all (or lost):\n%s", got)
	}
	if !strings.Contains(got, "route-map P permit 20\nexit\n") {
		t.Fatalf("the following accept term was lost:\n%s", got)
	}

	acceptPO := routeFilterPolicyPO([]*config.PolicyTerm{
		{Name: "t-accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/32", MatchType: "longer"}}, Action: "accept"},
	}, "reject")
	got = New().generatePolicyOptions(acceptPO)
	acceptName := inlinePrefixListName("P", "P", "t-accept", "")
	if !strings.Contains(got, "route-map P permit 10\n match ip address prefix-list "+acceptName+"\nexit\n") {
		t.Fatalf("the legitimately-empty accept was dropped or broadened:\n%s", got)
	}
}

// TestValidRouteFiltersRenderMatchLines_14137 is the tightening control:
// fully valid route-filters keep their entries and match lines in both
// directions. A belt that narrows working configs is worse than the bug
// it fixes.
func TestValidRouteFiltersRenderMatchLines_14137(t *testing.T) {
	po := routeFilterPolicyPO([]*config.PolicyTerm{
		{Name: "t-reject", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, Action: "reject"},
		{Name: "t-accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, Action: "accept"},
	}, "reject")
	got := New().generatePolicyOptions(po)
	rejectName := inlinePrefixListName("P", "P", "t-reject", "")
	acceptName := inlinePrefixListName("P", "P", "t-accept", "")
	for _, want := range []string{
		"ip prefix-list " + rejectName + " seq 5 permit 10.0.0.0/8\n",
		"match ip address prefix-list " + rejectName,
		"ip prefix-list " + acceptName + " seq 5 permit 10.0.0.0/8\n",
		"match ip address prefix-list " + acceptName,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "route-map P deny 10\nexit\n") {
		t.Errorf("a valid reject broadened to deny-all:\n%s", got)
	}
}
