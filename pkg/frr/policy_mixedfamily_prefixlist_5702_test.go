package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// routeMapSequenceContaining returns the text of the single `route-map <name>
// <action> <seq>` block (up to its `exit`) that contains needle, or "" if no
// sequence contains it. Used to assert that an AND predicate co-resides in the
// SAME sequence as a route-filter match (FRR ANDs match clauses within one
// sequence).
func routeMapSequenceContaining(render, name, needle string) string {
	marker := "route-map " + name + " "
	idx := 0
	for {
		start := strings.Index(render[idx:], marker)
		if start < 0 {
			return ""
		}
		start += idx
		// The sequence body runs to its terminating "exit\n" line.
		rest := render[start:]
		end := strings.Index(rest, "\nexit\n")
		var block string
		if end < 0 {
			block = rest
		} else {
			block = rest[:end+len("\nexit\n")]
		}
		if strings.Contains(block, needle) {
			return block
		}
		idx = start + len(marker)
	}
}

// TestMixedFamilyRouteFilterFromPrefixList_OffFamilyNonMatching_5702 proves the
// #5702 fix. A policy term whose route-filters mix families (v4 + v6) SPLITS
// into a per-family v4 sequence and a v6 sequence (#2607). When that term ALSO
// carries a `from prefix-list` of a SINGLE family, the split must AND that
// prefix-list predicate into BOTH sequences. In the OFF-family sequence the
// predicate is unsatisfiable (a v4 route can never be in a v6-only list), so
// that sequence must AND-NOMATCH — i.e. be NON-MATCHING for its family.
//
// Pre-#5702 the renderer DROPPED the off-family `from prefix-list` match line
// and emitted the surviving sequence with only its route-filter match, silently
// LOOSENING the term's AND to its route-filter half: a v4 route matching the v4
// route-filter matched the term even though the term also required membership in
// a v6-only prefix-list — a fail-open policy-semantics change.
//
// FAIL-ON-REVERT: restoring the family guard (drop the off-family match) removes
// the `match ipv6 address prefix-list V6ONLY` line from the v4 sequence, so the
// assertion that the v4 route-filter sequence also carries the v6 prefix-list
// AND predicate fires RED.
func TestMixedFamilyRouteFilterFromPrefixList_OffFamilyNonMatching_5702(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			// A v6-ONLY prefix-list — no v4 route can ever be a member.
			"V6ONLY": {Name: "V6ONLY", Prefixes: []string{"2001:db8:aaaa::/48"}},
		},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"MIX": {Name: "MIX", Terms: []*config.PolicyTerm{
				{
					Name: "t1",
					RouteFilters: []*config.RouteFilter{
						{Prefix: "10.0.0.0/8", MatchType: "orlonger"},    // v4 → splits
						{Prefix: "2001:db8::/32", MatchType: "orlonger"}, // v6 → splits
					},
					// The AND predicate: membership in a v6-only prefix-list.
					PrefixList: []string{"V6ONLY"},
					Action:     "reject",
				},
			}, DefaultAction: "accept"},
		},
	}
	got := New().generatePolicyOptions(po)
	v4Name := inlinePrefixListName("MIX", "MIX", "t1", "_v4")
	v6Name := inlinePrefixListName("MIX", "MIX", "t1", "_v6")

	// The v4 sequence is the one carrying the v4 route-filter match.
	v4seq := routeMapSequenceContaining(got, "MIX", "match ip address prefix-list "+v4Name)
	if v4seq == "" {
		t.Fatalf("expected a v4 route-filter sequence in render:\n%s", got)
	}
	// #5702: that v4 sequence MUST also carry the v6-only prefix-list AND
	// predicate, so it AND-NOMATCHes every v4 route (non-matching for v4)
	// instead of matching the v4 route-filter alone.
	if !strings.Contains(v4seq, "match ipv6 address prefix-list V6ONLY\n") {
		t.Fatalf("v4 sequence must AND the off-family `from prefix-list` predicate "+
			"(match ipv6 address prefix-list V6ONLY) so it is NON-MATCHING for v4 "+
			"routes; the predicate was dropped (pre-#5702 fail-open):\n%s", v4seq)
	}

	// #5730: the V6ONLY predicate ANDs into BOTH split sequences, but the
	// ON-family (v6) sequence must render it as a DISTINCT FRR rule type
	// (access-list), NOT a second `match ipv6 address prefix-list` — that would
	// COLLIDE with the v6 route-filter's own prefix-list match (FRR's
	// route_map_add_match REPLACES a same-type rule, keeping only the last, so
	// the v6 route-filter constraint would be silently dropped). Therefore the
	// prefix-list form of V6ONLY appears ONLY in the off-family v4 sequence
	// (exactly once); the v6 sequence carries the access-list form.
	if n := strings.Count(got, "match ipv6 address prefix-list V6ONLY\n"); n != 1 {
		t.Errorf("expected the V6ONLY prefix-list match ONLY in the off-family v4 "+
			"sequence (the on-family v6 sequence renders it as an access-list per "+
			"#5730), got %d occurrences:\n%s", n, got)
	}
	// The v6 route-filter sequence ANDs V6ONLY as an access-list (#5730),
	// coexisting with the derived _v6 inline prefix-list name as a distinct
	// FRR rule type instead of colliding with it.
	v6seq := routeMapSequenceContaining(got, "MIX", "match ipv6 address prefix-list "+v6Name)
	if v6seq == "" {
		t.Fatalf("expected a v6 route-filter sequence in render:\n%s", got)
	}
	// The on-family V6ONLY predicate renders as an access-list under the #5872
	// bounded/namespaced/hashed name (definition and reference share it).
	v6ACL := routeFilterACLName("V6ONLY", "ipv6")
	if !strings.Contains(v6seq, "match ipv6 address "+v6ACL+"\n") {
		t.Fatalf("v6 sequence must AND the on-family V6ONLY predicate as an "+
			"access-list (#5730), not a colliding same-type prefix-list match:\n%s", v6seq)
	}
	if !strings.Contains(got, "ipv6 access-list "+v6ACL+" seq 5 permit 2001:db8:aaaa::/48 exact-match\n") {
		t.Fatalf("missing the #5730 access-list definition for the on-family V6ONLY predicate:\n%s", got)
	}
}

// TestMixedFamilyRouteFilterFromPrefixList_V4List_OffFamilyNonMatching_5702 is
// the mirror: a v4-ONLY `from prefix-list` combined with mixed-family
// route-filters must AND-NOMATCH the V6 sequence (a v6 route can never be in a
// v4-only list).
func TestMixedFamilyRouteFilterFromPrefixList_V4List_OffFamilyNonMatching_5702(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V4ONLY": {Name: "V4ONLY", Prefixes: []string{"192.0.2.0/24"}},
		},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"MIX": {Name: "MIX", Terms: []*config.PolicyTerm{
				{
					Name: "t1",
					RouteFilters: []*config.RouteFilter{
						{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
						{Prefix: "2001:db8::/32", MatchType: "orlonger"},
					},
					PrefixList: []string{"V4ONLY"},
					Action:     "reject",
				},
			}, DefaultAction: "accept"},
		},
	}
	got := New().generatePolicyOptions(po)
	v6Name := inlinePrefixListName("MIX", "MIX", "t1", "_v6")

	v6seq := routeMapSequenceContaining(got, "MIX", "match ipv6 address prefix-list "+v6Name)
	if v6seq == "" {
		t.Fatalf("expected a v6 route-filter sequence in render:\n%s", got)
	}
	if !strings.Contains(v6seq, "match ip address prefix-list V4ONLY\n") {
		t.Fatalf("v6 sequence must AND the off-family v4-only `from prefix-list` "+
			"predicate (match ip address prefix-list V4ONLY) so it is NON-MATCHING "+
			"for v6 routes (pre-#5702 fail-open dropped it):\n%s", v6seq)
	}
}

// TestMixedFamilyRouteFilterNoPrefixList_Unchanged_5702 guards the common case:
// a mixed-family route-filter term with NO `from prefix-list` is byte-identical
// to the pre-#5702 render (the fix only touches the off-family prefix-list
// emission). Both family sequences carry only their own route-filter match.
func TestMixedFamilyRouteFilterNoPrefixList_Unchanged_5702(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"MIX": {Name: "MIX", Terms: []*config.PolicyTerm{
				{
					Name: "t1",
					RouteFilters: []*config.RouteFilter{
						{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
						{Prefix: "2001:db8::/32", MatchType: "orlonger"},
					},
					Action: "reject",
				},
			}, DefaultAction: "accept"},
		},
	}
	got := New().generatePolicyOptions(po)
	v4Name := inlinePrefixListName("MIX", "MIX", "t1", "_v4")
	v6Name := inlinePrefixListName("MIX", "MIX", "t1", "_v6")
	// No stray prefix-list AND predicate leaks into either sequence.
	if strings.Contains(got, "prefix-list V6ONLY") || strings.Contains(got, "prefix-list V4ONLY") {
		t.Fatalf("no from-prefix-list configured; render must not emit one:\n%s", got)
	}
	// Exactly the two per-family route-filter matches, nothing else.
	if !strings.Contains(got, "match ip address prefix-list "+v4Name+"\n") ||
		!strings.Contains(got, "match ipv6 address prefix-list "+v6Name+"\n") {
		t.Fatalf("mixed-family split must keep both per-family route-filter matches:\n%s", got)
	}
}
