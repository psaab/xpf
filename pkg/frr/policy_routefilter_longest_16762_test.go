package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16762: a term's route-filters render as ONE first-match FRR
// prefix-list (walkup/OR semantics) instead of Junos' default
// longest-match, so a more-specific filter whose match type fails no
// longer ends evaluation. Junos performs a longest-match lookup over
// ALL of a term's route-filters: the most specific containing filter
// decides even when its match type then fails (no fall-through to a
// broader filter; only opt-in `walkup`, unmodelled by xpf, differs).
// FRR prefix-lists are ordered first-match, so authoring-order permits
// admitted e.g. 192.168.100.128/25 via `192.168.0.0/16 orlonger` even
// though `192.168.100.0/24 exact` is the longest match and fails for
// /25. The layout (renderRouteFilterListGroup) sorts permits by
// descending base length and interposes `deny P le <max>` after each
// distinct prefix P that some other renderable filter's base CONTAINS;
// single / disjoint / same-base lists keep their historical bytes.
//
// These tests assert RENDERED TEXT only — the same direct-render seam
// as the sibling policy_* tests — plus a small first-match simulator
// over the rendered lines that reproduces FRR evaluation, so the
// acceptance routes are checked against the actual FRR semantics
// rather than against Go re-derivations of them.

// rfPolicy16762 builds a one-statement / one-term PolicyOptionsConfig.
func rfPolicy16762(rfs ...*config.RouteFilter) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: rfs, Action: "accept"},
			}, DefaultAction: "reject"},
		},
	}
}

// prefixListLines16762 extracts the rendered `ip|ipv6 prefix-list <name>
// seq <n> <action> <rest>` lines for list name, in rendered order.
func prefixListLines16762(t *testing.T, got, name string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, " prefix-list "+name+" seq ") {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no prefix-list entries for %s in:\n%s", name, got)
	}
	return out
}

// simulatePrefixList16762 evaluates route (CIDR string) against the
// rendered lines with FRR first-match semantics: the first line whose
// prefix contains the route address AND whose ge/le window contains
// the route length decides; no match is NOMATCH (route-map deny for
// the referencing term). This mirrors lib/prefix_list.c: a bare entry
// matches only the exact prefix; `le N` caps the length; `ge M le N`
// bounds it below and above.
func simulatePrefixList16762(lines []string, route string) string {
	routeNet, _ := parseRouteFilterPrefix16762(route)
	if routeNet == nil {
		return "NOMATCH"
	}
	rplen, _ := routeNet.Mask.Size()
	for _, line := range lines {
		f := strings.Fields(line)
		// ip|ipv6 prefix-list NAME seq N ACTION PREFIX [ge G] [le L]
		if len(f) < 7 {
			continue
		}
		action, pfx := f[5], f[6]
		base, _ := parseRouteFilterPrefix16762(pfx)
		if base == nil {
			continue
		}
		bplen, _ := base.Mask.Size()
		ge, le := 0, -1
		for i := 7; i+1 < len(f); i += 2 {
			switch f[i] {
			case "ge":
				ge = atoi16762(f[i+1])
			case "le":
				le = atoi16762(f[i+1])
			}
		}
		if le < 0 {
			// Bare entry: exact prefix only.
			le, ge = bplen, bplen
		}
		if !routeFilterContains16762(base, routeNet.IP, rplen) {
			continue
		}
		if rplen < ge || rplen > le {
			continue
		}
		return action
	}
	return "NOMATCH"
}

func atoi16762(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// TestRouteFilterLongestMatchAcceptance_16762 is the issue's decisive
// fixture: `192.168.0.0/16 orlonger` + `192.168.100.0/24 exact`.
// 192.168.100.128/25 must first-match a deny (the /24 exact fails for
// /25 and Junos stops), while the /24 itself and an unrelated /24
// under the /16 permit.
func TestRouteFilterLongestMatchAcceptance_16762(t *testing.T) {
	po := rfPolicy16762(
		&config.RouteFilter{Prefix: "192.168.0.0/16", MatchType: "orlonger"},
		&config.RouteFilter{Prefix: "192.168.100.0/24", MatchType: "exact"},
	)
	got := New().generatePolicyOptions(po)
	name := inlinePrefixListName("P", "P", "t1", "")
	lines := prefixListLines16762(t, got, name)
	want := []string{
		"ip prefix-list " + name + " seq 5 permit 192.168.100.0/24",
		"ip prefix-list " + name + " seq 10 deny 192.168.100.0/24 le 32",
		"ip prefix-list " + name + " seq 15 permit 192.168.0.0/16 le 32",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d entries, want %d:\n%s", len(lines), len(want), got)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
	for route, wantAction := range map[string]string{
		"192.168.100.128/25": "deny",
		"192.168.100.0/24":   "permit",
		"192.168.5.0/24":     "permit",
	} {
		if a := simulatePrefixList16762(lines, route); a != wantAction {
			t.Errorf("route %s: FRR first-match = %s, want %s (Junos longest-match)", route, a, wantAction)
		}
	}
	if !strings.Contains(got, "match ip address prefix-list "+name+"\n") {
		t.Errorf("term match line missing:\n%s", got)
	}
}

// TestRouteFilterLongestMatchAuthoringOrderIndependent_16762: the
// more-specific filter authored FIRST must render identically — the
// layout depends on prefix lengths, not authoring order.
func TestRouteFilterLongestMatchAuthoringOrderIndependent_16762(t *testing.T) {
	a := New().generatePolicyOptions(rfPolicy16762(
		&config.RouteFilter{Prefix: "192.168.0.0/16", MatchType: "orlonger"},
		&config.RouteFilter{Prefix: "192.168.100.0/24", MatchType: "exact"},
	))
	b := New().generatePolicyOptions(rfPolicy16762(
		&config.RouteFilter{Prefix: "192.168.100.0/24", MatchType: "exact"},
		&config.RouteFilter{Prefix: "192.168.0.0/16", MatchType: "orlonger"},
	))
	if a != b {
		t.Errorf("authoring order changed the render:\nbroad-first:\n%s\nspecific-first:\n%s", a, b)
	}
}

// TestRouteFilterDisjointByteIdentical_16762: disjoint equal-length
// filters render byte-identically to the historical render — stability
// keeps the authored order and, disjoint bases being unable to fall
// through to one another, no stop is interposed (acceptance
// criterion: single or disjoint lists render byte-identically).
func TestRouteFilterDisjointByteIdentical_16762(t *testing.T) {
	po := rfPolicy16762(
		&config.RouteFilter{Prefix: "192.168.50.0/24", MatchType: "exact"},
		&config.RouteFilter{Prefix: "10.10.0.0/24", MatchType: "exact"},
	)
	got := New().generatePolicyOptions(po)
	name := inlinePrefixListName("P", "P", "t1", "")
	lines := prefixListLines16762(t, got, name)
	want := []string{
		"ip prefix-list " + name + " seq 5 permit 192.168.50.0/24",
		"ip prefix-list " + name + " seq 10 permit 10.10.0.0/24",
	}
	if len(lines) != len(want) {
		t.Fatalf("disjoint list must stay byte-identical: got %d entries, want %d:\n%s", len(lines), len(want), got)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestRouteFilterSingleAndSameBaseByteIdentical_16762 pins the
// no-change cases: a single filter, and two filters on the SAME base
// (hierarchical `from` condition copies, #11779), render exactly the
// historical lines — no stop deny, authored seq slots preserved by
// stable equal-length order.
func TestRouteFilterSingleAndSameBaseByteIdentical_16762(t *testing.T) {
	t.Run("single", func(t *testing.T) {
		po := rfPolicy16762(&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "orlonger"})
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		lines := prefixListLines16762(t, got, name)
		if len(lines) != 1 || lines[0] != "ip prefix-list "+name+" seq 5 permit 10.0.0.0/8 le 32" {
			t.Errorf("single filter must render one bare permit, got %v:\n%s", lines, got)
		}
	})
	t.Run("same base windows", func(t *testing.T) {
		po := rfPolicy16762(
			&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "prefix-length-range", RangeLow: 16, RangeHigh: 20},
			&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "prefix-length-range", RangeLow: 24, RangeHigh: 28},
		)
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		lines := prefixListLines16762(t, got, name)
		want := []string{
			"ip prefix-list " + name + " seq 5 permit 10.0.0.0/8 ge 16 le 20",
			"ip prefix-list " + name + " seq 10 permit 10.0.0.0/8 ge 24 le 28",
		}
		if len(lines) != len(want) {
			t.Fatalf("same-base windows: got %d entries, want %d (no stop):\n%s", len(lines), len(want), got)
		}
		for i := range want {
			if lines[i] != want[i] {
				t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
			}
		}
		// /22 falls in NEITHER window: Junos fails the term (NOMATCH),
		// it must not match via any stop or broader permit.
		if a := simulatePrefixList16762(lines, "10.1.2.0/22"); a != "NOMATCH" {
			t.Errorf("10.1.2.0/22 = %s, want NOMATCH", a)
		}
		if a := simulatePrefixList16762(lines, "10.1.0.0/18"); a != "permit" {
			t.Errorf("10.1.0.0/18 = %s, want permit", a)
		}
	})
}

// TestRouteFilterNestedChainStops_16762: three nested bases — each
// level's failed match must stop before the next broader permit.
func TestRouteFilterNestedChainStops_16762(t *testing.T) {
	po := rfPolicy16762(
		&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
		&config.RouteFilter{Prefix: "10.1.0.0/16", MatchType: "upto", UptoLen: 20},
		&config.RouteFilter{Prefix: "10.1.2.0/24", MatchType: "exact"},
	)
	got := New().generatePolicyOptions(po)
	name := inlinePrefixListName("P", "P", "t1", "")
	lines := prefixListLines16762(t, got, name)
	for route, wantAction := range map[string]string{
		"10.1.2.0/24":   "permit", // longest: /24 exact
		"10.1.2.128/25": "deny",   // under /24, fails exact, stops
		"10.1.3.0/24":   "deny",   // under /16, len 24 > upto 20, stops
		"10.1.0.0/18":   "permit", // under /16 within upto 20
		"10.2.0.0/16":   "permit", // only /8 orlonger contains it
	} {
		if a := simulatePrefixList16762(lines, route); a != wantAction {
			t.Errorf("route %s: FRR first-match = %s, want %s", route, a, wantAction)
		}
	}
}

// TestRouteFilterLongestV6_16762: the same layout for IPv6 (le 128).
func TestRouteFilterLongestV6_16762(t *testing.T) {
	po := rfPolicy16762(
		&config.RouteFilter{Prefix: "2001:db8::/32", MatchType: "orlonger"},
		&config.RouteFilter{Prefix: "2001:db8:1::/48", MatchType: "exact"},
	)
	got := New().generatePolicyOptions(po)
	name := inlinePrefixListName("P", "P", "t1", "")
	lines := prefixListLines16762(t, got, name)
	want := []string{
		"ipv6 prefix-list " + name + " seq 5 permit 2001:db8:1::/48",
		"ipv6 prefix-list " + name + " seq 10 deny 2001:db8:1::/48 le 128",
		"ipv6 prefix-list " + name + " seq 15 permit 2001:db8::/32 le 128",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d entries, want %d:\n%s", len(lines), len(want), got)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
	if a := simulatePrefixList16762(lines, "2001:db8:1::/64"); a != "deny" {
		t.Errorf("2001:db8:1::/64 = %s, want deny", a)
	}
	if a := simulatePrefixList16762(lines, "2001:db8:2::/48"); a != "permit" {
		t.Errorf("2001:db8:2::/48 = %s, want permit", a)
	}
}

// TestRouteFilterRootHasNoStop_16762: a /0 base never gets a stop (it
// has no broader sibling and a stop would be the whole space anyway).
func TestRouteFilterRootHasNoStop_16762(t *testing.T) {
	po := rfPolicy16762(
		&config.RouteFilter{Prefix: "0.0.0.0/0", MatchType: "orlonger"},
		&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "exact"},
	)
	got := New().generatePolicyOptions(po)
	name := inlinePrefixListName("P", "P", "t1", "")
	lines := prefixListLines16762(t, got, name)
	want := []string{
		"ip prefix-list " + name + " seq 5 permit 10.0.0.0/8",
		"ip prefix-list " + name + " seq 10 deny 10.0.0.0/8 le 32",
		"ip prefix-list " + name + " seq 15 permit 0.0.0.0/0 le 32",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d entries, want %d:\n%s", len(lines), len(want), got)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
	if a := simulatePrefixList16762(lines, "10.1.0.0/16"); a != "deny" {
		t.Errorf("10.1.0.0/16 = %s, want deny (under /8 exact, failed)", a)
	}
	if a := simulatePrefixList16762(lines, "192.0.2.0/24"); a != "permit" {
		t.Errorf("192.0.2.0/24 = %s, want permit (via /0)", a)
	}
}
