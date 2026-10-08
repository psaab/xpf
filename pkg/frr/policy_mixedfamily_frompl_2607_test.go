package frr

// #2607 (referenced-prefix-list residual): a Junos policy-statement term's
// `from prefix-list <PL>` that names a MIXED v4+v6 list used to collapse to a
// SINGLE family (prefixListMatchKW: "ipv6 if any v6 entry, else ip"), emitting
// exactly one of `match ip address prefix-list PL` / `match ipv6 address
// prefix-list PL`. FRR keeps `ip` and `ipv6` prefix-lists in independent
// namespaces, so the OTHER family's entries were written into the config but
// never bound to a match line — every route of that family silently failed the
// term (routing asymmetry / blackhole, no commit error).
//
// The route-filter mixed-family case was already family-split (#2607 base +
// #5702/#5730). THIS closes the issue's own residual: the REFERENCED
// prefix-list. A mixed list is exactly the Junos OR "(in its v4 half) OR (in its
// v6 half)", so it expands (fromPrefixListRefs) into one `ip` ref and one `ipv6`
// ref, each emitted in its own route-map sequence — mirroring the existing #2642
// one-sequence-per-OR-value mechanism. A single-family / undefined / empty list
// yields exactly one ref, so its render is byte-identical to before.
//
// FAIL-ON-REVERT: restore the single-family collapse (fromPrefixListRefs → a
// lone prefixListMatchKW keyword) and the IPv4 half of every mixed referenced
// list loses its `match ip address` line — TestFromPrefixListMixed_BindsBothFamilies_2607
// and the co-resident v4-route-filter access-list assertion go RED.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// mixedFromPrefixListPO builds a one-term policy "p"/"t1" whose action is
// termAction ("accept" → permit, "reject" → deny), referencing prefix-list
// "mixed" (v4 10.0.0.0/8 + v6 2001:db8::/32), optionally co-resident with a
// route-filter of family rfFamily ("" none, "v4" 10.1.0.0/16, "v6"
// 2001:db8:1::/48 — both intentionally NON-disjoint with the mixed list so a
// same-family route genuinely matches, exercising the fix rather than an
// incidental empty intersection).
func mixedFromPrefixListPO(termAction, rfFamily string) *config.PolicyOptionsConfig {
	term := &config.PolicyTerm{
		Name:       "t1",
		PrefixList: []string{"mixed"},
		Action:     termAction,
	}
	switch rfFamily {
	case "v4":
		term.RouteFilters = []*config.RouteFilter{{Prefix: "10.1.0.0/16", MatchType: "orlonger"}}
	case "v6":
		term.RouteFilters = []*config.RouteFilter{{Prefix: "2001:db8:1::/48", MatchType: "orlonger"}}
	}
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"mixed": {Name: "mixed", Prefixes: []string{"10.0.0.0/8", "2001:db8::/32"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"p": {Name: "p", Terms: []*config.PolicyTerm{term}},
		},
	}
}

// TestFromPrefixListMixed_BindsBothFamilies_2607 is the core assertion: a mixed
// referenced list alone must emit BOTH family match lines, in SEPARATE
// sequences, each against the family-correct FRR prefix-list object.
func TestFromPrefixListMixed_BindsBothFamilies_2607(t *testing.T) {
	m := New()
	got := m.generatePolicyOptions(mixedFromPrefixListPO("accept", ""))

	// Both family match lines must appear (the crux — pre-#2607 only ipv6 did).
	if !strings.Contains(got, " match ip address prefix-list mixed\n") {
		t.Errorf("mixed from-prefix-list: missing the IPv4 matcher — every v4 route silently fails the term:\n%s", got)
	}
	if !strings.Contains(got, " match ipv6 address prefix-list mixed\n") {
		t.Errorf("mixed from-prefix-list: missing the IPv6 matcher:\n%s", got)
	}
	// FRR ANDs match clauses within one index, so the two families cannot share
	// a sequence — they live in two separate sequences.
	seqV4 := routeMapSequenceContaining(got, "p", " match ip address prefix-list mixed\n")
	seqV6 := routeMapSequenceContaining(got, "p", " match ipv6 address prefix-list mixed\n")
	if seqV4 == "" || seqV6 == "" || seqV4 == seqV6 {
		t.Errorf("mixed from-prefix-list: the ip and ipv6 matchers must be in DISTINCT route-map sequences (FRR ANDs within one index):\n%s", got)
	}
	// The family-correct FRR prefix-list objects exist under the shared name.
	if !strings.Contains(got, "ip prefix-list mixed seq 5 permit 10.0.0.0/8\n") {
		t.Errorf("mixed from-prefix-list: missing the v4 prefix-list object:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 prefix-list mixed seq 10 permit 2001:db8::/32\n") {
		t.Errorf("mixed from-prefix-list: missing the v6 prefix-list object:\n%s", got)
	}
}

// TestFromPrefixListMixed_Deny_2607 proves the split preserves the term action:
// a `then reject` term renders BOTH families as `deny` sequences.
func TestFromPrefixListMixed_Deny_2607(t *testing.T) {
	m := New()
	got := m.generatePolicyOptions(mixedFromPrefixListPO("reject", ""))

	seqV4 := routeMapSequenceContaining(got, "p", " match ip address prefix-list mixed\n")
	seqV6 := routeMapSequenceContaining(got, "p", " match ipv6 address prefix-list mixed\n")
	if seqV4 == "" || seqV6 == "" {
		t.Fatalf("deny mixed from-prefix-list: both family matchers must be emitted:\n%s", got)
	}
	if !strings.HasPrefix(seqV4, "route-map p deny ") {
		t.Errorf("deny mixed from-prefix-list: v4 sequence must be a `deny`:\n%s", seqV4)
	}
	if !strings.HasPrefix(seqV6, "route-map p deny ") {
		t.Errorf("deny mixed from-prefix-list: v6 sequence must be a `deny`:\n%s", seqV6)
	}
}

// TestFromPrefixListMixed_CoResidentV4RouteFilter_2607 proves the conjunction
// semantics with a co-resident v4 route-filter (#5730 same-family ACL AND +
// #5702 off-family unsatisfiable AND both preserved):
//   - v4 sequence: the mixed list's v4 half is rendered as an ACCESS-LIST match
//     (distinct FRR type) so it ANDs with the same-type v4 route-filter instead
//     of one silently replacing the other (#5730).
//   - v6 sequence: the mixed list's v6 half (`match ipv6 address prefix-list`)
//     co-resides with the v4 route-filter's `match ip address` — emitted and
//     off-family unsatisfiable, NOT dropped (#5702).
func TestFromPrefixListMixed_CoResidentV4RouteFilter_2607(t *testing.T) {
	m := New()
	got := m.generatePolicyOptions(mixedFromPrefixListPO("accept", "v4"))
	routeFilterName := inlinePrefixListName("p", "p", "t1", "")

	ipACL := routeFilterACLName("mixed", "ip")
	// v4 half ANDs via an access-list (#5730), NOT a colliding prefix-list match.
	if !strings.Contains(got, "access-list "+ipACL+" seq 5 permit 10.0.0.0/8 exact-match\n") {
		t.Errorf("co-resident v4 rf: mixed list v4 half must render as an access-list (#5730 same-family AND):\n%s", got)
	}
	seqV4 := routeMapSequenceContaining(got, "p", " match ip address "+ipACL+"\n")
	if seqV4 == "" {
		t.Fatalf("co-resident v4 rf: missing the access-list match for the mixed v4 half:\n%s", got)
	}
	if !strings.Contains(seqV4, " match ip address prefix-list "+routeFilterName+"\n") {
		t.Errorf("co-resident v4 rf: the v4 route-filter and the mixed v4 half must AND in ONE sequence (#5730):\n%s", seqV4)
	}
	// v6 half: off-family unsatisfiable AND — the v4 route-filter match must
	// STILL co-reside in the v6-half sequence, not be dropped (#5702).
	seqV6 := routeMapSequenceContaining(got, "p", " match ipv6 address prefix-list mixed\n")
	if seqV6 == "" {
		t.Fatalf("co-resident v4 rf: the mixed list v6 half must still be emitted:\n%s", got)
	}
	if !strings.Contains(seqV6, " match ip address prefix-list "+routeFilterName+"\n") {
		t.Errorf("co-resident v4 rf: the off-family v6 sequence must still AND the v4 route-filter (unsatisfiable, not dropped — #5702):\n%s", seqV6)
	}
}

// TestFromPrefixListMixed_CoResidentV6RouteFilter_2607 is the mirror: a
// co-resident v6 route-filter ANDs the mixed list's v6 half via an ipv6
// access-list (#5730), and the v4 half is the off-family unsatisfiable AND.
func TestFromPrefixListMixed_CoResidentV6RouteFilter_2607(t *testing.T) {
	m := New()
	got := m.generatePolicyOptions(mixedFromPrefixListPO("accept", "v6"))
	routeFilterName := inlinePrefixListName("p", "p", "t1", "")

	v6ACL := routeFilterACLName("mixed", "ipv6")
	if !strings.Contains(got, "ipv6 access-list "+v6ACL+" seq 5 permit 2001:db8::/32 exact-match\n") {
		t.Errorf("co-resident v6 rf: mixed list v6 half must render as an ipv6 access-list (#5730 same-family AND):\n%s", got)
	}
	seqV6 := routeMapSequenceContaining(got, "p", " match ipv6 address "+v6ACL+"\n")
	if seqV6 == "" {
		t.Fatalf("co-resident v6 rf: missing the ipv6 access-list match for the mixed v6 half:\n%s", got)
	}
	if !strings.Contains(seqV6, " match ipv6 address prefix-list "+routeFilterName+"\n") {
		t.Errorf("co-resident v6 rf: the v6 route-filter and the mixed v6 half must AND in ONE sequence (#5730):\n%s", seqV6)
	}
	// v4 half off-family unsatisfiable, still emitted (#5702).
	seqV4 := routeMapSequenceContaining(got, "p", " match ip address prefix-list mixed\n")
	if seqV4 == "" {
		t.Fatalf("co-resident v6 rf: the mixed list v4 half must still be emitted:\n%s", got)
	}
	if !strings.Contains(seqV4, " match ipv6 address prefix-list "+routeFilterName+"\n") {
		t.Errorf("co-resident v6 rf: the off-family v4 sequence must still AND the v6 route-filter (unsatisfiable, not dropped — #5702):\n%s", seqV4)
	}
}

// TestPrefixListFamilies_2607 unit-tests the per-family SSOT that drives both
// the renderer and the collision precheck.
func TestPrefixListFamilies_2607(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []string
		want     []string
	}{
		{"v4-only", []string{"10.0.0.0/8", "172.16.0.0/12"}, []string{"ip"}},
		{"v6-only", []string{"2001:db8::/32"}, []string{"ipv6"}},
		{"mixed", []string{"10.0.0.0/8", "2001:db8::/32"}, []string{"ip", "ipv6"}},
		{"mixed-v6-first", []string{"2001:db8::/32", "10.0.0.0/8"}, []string{"ip", "ipv6"}}, // order is fixed ip-before-ipv6
		{"empty", nil, []string{"ip"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pl *config.PrefixList
			if tc.prefixes != nil {
				pl = &config.PrefixList{Name: tc.name, Prefixes: tc.prefixes}
			}
			got := prefixListFamilies(pl)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("prefixListFamilies(%v) = %v, want %v", tc.prefixes, got, tc.want)
			}
		})
	}
	// nil list defaults to IPv4 (fail-closed, no panic).
	if got := prefixListFamilies(nil); len(got) != 1 || got[0] != "ip" {
		t.Errorf("prefixListFamilies(nil) = %v, want [ip]", got)
	}
}

// TestFromPrefixListEmpty_FailClosed_2607 proves an undefined/empty referenced
// list does not panic and defaults to a single IPv4 matcher against the
// (undefined) list, which FRR resolves to NOMATCH — fail-closed, no silent
// permit-all, byte-identical to the pre-#2607 undefined-list behavior.
func TestFromPrefixListEmpty_FailClosed_2607(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{}, // "ghost" undefined
		PolicyStatements: map[string]*config.PolicyStatement{
			"p": {Name: "p", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: []string{"ghost"}, Action: "accept"},
			}},
		},
	}
	got := m.generatePolicyOptions(po)
	if !strings.Contains(got, " match ip address prefix-list ghost\n") {
		t.Errorf("undefined from-prefix-list: must default to a single `match ip address prefix-list ghost` (undefined → NOMATCH, fail-closed):\n%s", got)
	}
	if strings.Contains(got, "match ipv6 address prefix-list ghost") {
		t.Errorf("undefined from-prefix-list: must NOT emit an IPv6 matcher for an empty list:\n%s", got)
	}
}

// TestRouteFilterACLNameCollision_MixedPerFamily_2607 proves the collision
// precheck now inspects EVERY family a referenced list renders under. A mixed
// list intruding on the reserved namespace is rejected regardless of family
// (fail-closed), and a normal mix of mixed + single-family lists is accepted
// without a false positive.
func TestRouteFilterACLNameCollision_MixedPerFamily_2607(t *testing.T) {
	ok := &config.PolicyOptionsConfig{PrefixLists: map[string]*config.PrefixList{
		"mixed":  {Name: "mixed", Prefixes: []string{"10.0.0.0/8", "2001:db8::/32"}},
		"v4only": {Name: "v4only", Prefixes: []string{"192.0.2.0/24"}},
		"v6only": {Name: "v6only", Prefixes: []string{"2001:db8:aaaa::/48"}},
	}}
	if err := routeFilterACLNameCollision(ok); err != nil {
		t.Errorf("clean mixed + single-family lists must not collide: %v", err)
	}
	// A mixed list whose NAME intrudes on the reserved generated-ACL namespace
	// is rejected — the fail-closed path (#5872), now reached for mixed lists too.
	bad := &config.PolicyOptionsConfig{PrefixLists: map[string]*config.PrefixList{
		routeFilterACLNamespace + "x": {
			Name:     routeFilterACLNamespace + "x",
			Prefixes: []string{"10.0.0.0/8", "2001:db8::/32"},
		},
	}}
	if err := routeFilterACLNameCollision(bad); err == nil {
		t.Error("a mixed prefix-list intruding on the reserved ACL namespace must be rejected (fail-closed)")
	}
}
