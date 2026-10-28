package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17823: the #16762 longest-match layout must preserve the COMPLETE
// base identity (masked address AND prefix length) and must retain
// valid empty match boundaries. Two defects in the retro-review:
//
//  1. sameRouteFilterBase16762 compared only Addr(), so 10.0.0.0/8 and
//     10.0.0.0/24 (same masked address, different plen) were one base
//     group and the /24's stop-deny was suppressed — a route under the
//     /24 whose match type failed fell through to the /8 permit.
//     (Fixed incidentally by #16866's aa==bb, this file pins it.)
//  2. A max-length `longer` (10.0.0.42/32 longer, 2001:db8::1/128
//     longer) is VALID with an honestly empty match set
//     (RouteFilterEntrySkipped == false) but renders no permit, so the
//     layout discarded it before containment/stop computation. As the
//     longest base it must still act as a boundary: routes at/under it
//     fail the term instead of falling through to a broader permit.

func TestRouteFilterLongest17823SameAddressDifferentPlenStop(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		po := rfPolicy16762(
			&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
			&config.RouteFilter{Prefix: "10.0.0.0/24", MatchType: "exact"},
		)
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		lines := prefixListLines16762(t, got, name)
		want := []string{
			"ip prefix-list " + name + " seq 5 permit 10.0.0.0/24",
			"ip prefix-list " + name + " seq 10 deny 10.0.0.0/24 le 32",
			"ip prefix-list " + name + " seq 15 permit 10.0.0.0/8 le 32",
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
			"10.0.0.128/25": "deny",   // longest /24 exact fails -> stop
			"10.0.0.0/24":   "permit", // /24 exact
			"10.1.0.0/16":   "permit", // only /8 orlonger contains it
		} {
			if a := simulatePrefixList16762(lines, route); a != wantAction {
				t.Errorf("route %s: FRR first-match = %s, want %s", route, a, wantAction)
			}
		}
	})
	t.Run("v6", func(t *testing.T) {
		po := rfPolicy16762(
			&config.RouteFilter{Prefix: "2001:db8::/32", MatchType: "orlonger"},
			&config.RouteFilter{Prefix: "2001:db8::/64", MatchType: "exact"},
		)
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		lines := prefixListLines16762(t, got, name)
		want := []string{
			"ipv6 prefix-list " + name + " seq 5 permit 2001:db8::/64",
			"ipv6 prefix-list " + name + " seq 10 deny 2001:db8::/64 le 128",
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
		for route, wantAction := range map[string]string{
			"2001:db8::1/65":  "deny",
			"2001:db8::/64":   "permit",
			"2001:db8:1::/48": "permit",
		} {
			if a := simulatePrefixList16762(lines, route); a != wantAction {
				t.Errorf("route %s: FRR first-match = %s, want %s", route, a, wantAction)
			}
		}
	})
}

// TestRouteFilterLongest17823EmptyLongerBoundary: a valid max-length
// `longer` over a broader permit emits ONLY a boundary stop. Since FRR
// rejects `le max` on a /32 or /128, that stop is the bare deny prefix.
func TestRouteFilterLongest17823EmptyLongerBoundary(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		po := rfPolicy16762(
			&config.RouteFilter{Prefix: "10.0.0.0/24", MatchType: "orlonger"},
			&config.RouteFilter{Prefix: "10.0.0.42/32", MatchType: "longer"},
		)
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		lines := prefixListLines16762(t, got, name)
		want := []string{
			"ip prefix-list " + name + " seq 5 deny 10.0.0.42/32",
			"ip prefix-list " + name + " seq 10 permit 10.0.0.0/24 le 32",
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
			"10.0.0.42/32": "deny",   // longest /32 longer fails -> stop
			"10.0.0.43/32": "permit", // only /24 orlonger contains it
			"10.0.0.0/25":  "permit",
		} {
			if a := simulatePrefixList16762(lines, route); a != wantAction {
				t.Errorf("route %s: FRR first-match = %s, want %s", route, a, wantAction)
			}
		}
	})
	t.Run("v6", func(t *testing.T) {
		po := rfPolicy16762(
			&config.RouteFilter{Prefix: "2001:db8::/64", MatchType: "orlonger"},
			&config.RouteFilter{Prefix: "2001:db8::1/128", MatchType: "longer"},
		)
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		lines := prefixListLines16762(t, got, name)
		want := []string{
			"ipv6 prefix-list " + name + " seq 5 deny 2001:db8::1/128",
			"ipv6 prefix-list " + name + " seq 10 permit 2001:db8::/64 le 128",
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
			"2001:db8::1/128": "deny",
			"2001:db8::2/128": "permit",
		} {
			if a := simulatePrefixList16762(lines, route); a != wantAction {
				t.Errorf("route %s: FRR first-match = %s, want %s", route, a, wantAction)
			}
		}
	})
	// Authoring order must not matter: boundary authored first still
	// sorts ahead of the broader permit.
	t.Run("authoring order independent", func(t *testing.T) {
		a := New().generatePolicyOptions(rfPolicy16762(
			&config.RouteFilter{Prefix: "10.0.0.0/24", MatchType: "orlonger"},
			&config.RouteFilter{Prefix: "10.0.0.42/32", MatchType: "longer"},
		))
		b := New().generatePolicyOptions(rfPolicy16762(
			&config.RouteFilter{Prefix: "10.0.0.42/32", MatchType: "longer"},
			&config.RouteFilter{Prefix: "10.0.0.0/24", MatchType: "orlonger"},
		))
		if a != b {
			t.Errorf("authoring order changed the render:\nbroad-first:\n%s\nboundary-first:\n%s", a, b)
		}
	})
}

// TestRouteFilterLongest17823EmptyBoundaryControls pins the shapes
// that must NOT gain a boundary stop.
func TestRouteFilterLongest17823EmptyBoundaryControls(t *testing.T) {
	t.Run("lone max-length longer stays empty list", func(t *testing.T) {
		po := rfPolicy16762(&config.RouteFilter{Prefix: "10.0.0.42/32", MatchType: "longer"})
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		// No prefix-list definition lines at all: the undefined list
		// NOMATCHes (#2103). Extract manually because the shared
		// helper fatals on zero lines.
		for _, l := range strings.Split(got, "\n") {
			if strings.Contains(l, " prefix-list "+name+" seq ") {
				t.Errorf("lone empty longer must emit no entries, got %q in:\n%s", l, got)
			}
		}
	})
	t.Run("invalid entry never becomes a boundary", func(t *testing.T) {
		// prefix-length-range with RangeLow <= base plen is invalid
		// (RouteFilterEntrySkipped) — it must not stop the broader
		// permit's routes.
		po := rfPolicy16762(
			&config.RouteFilter{Prefix: "10.0.0.0/24", MatchType: "orlonger"},
			&config.RouteFilter{Prefix: "10.0.0.128/25", MatchType: "prefix-length-range", RangeLow: 20, RangeHigh: 28},
		)
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		lines := prefixListLines16762(t, got, name)
		if len(lines) != 1 || lines[0] != "ip prefix-list "+name+" seq 5 permit 10.0.0.0/24 le 32" {
			t.Errorf("invalid entry must render nothing and no stop, got %v:\n%s", lines, got)
		}
		if a := simulatePrefixList16762(lines, "10.0.0.200/32"); a != "permit" {
			t.Errorf("10.0.0.200/32 = %s, want permit (no boundary from invalid entry)", a)
		}
	})
	t.Run("same-base windows unchanged alongside broader permit", func(t *testing.T) {
		po := rfPolicy16762(
			&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
			&config.RouteFilter{Prefix: "10.9.0.0/16", MatchType: "prefix-length-range", RangeLow: 20, RangeHigh: 24},
			&config.RouteFilter{Prefix: "10.9.0.0/16", MatchType: "prefix-length-range", RangeLow: 28, RangeHigh: 32},
		)
		got := New().generatePolicyOptions(po)
		name := inlinePrefixListName("P", "P", "t1", "")
		lines := prefixListLines16762(t, got, name)
		want := []string{
			"ip prefix-list " + name + " seq 5 permit 10.9.0.0/16 ge 20 le 24",
			"ip prefix-list " + name + " seq 10 permit 10.9.0.0/16 ge 28 le 32",
			"ip prefix-list " + name + " seq 15 deny 10.9.0.0/16 le 32",
			"ip prefix-list " + name + " seq 20 permit 10.0.0.0/8 le 32",
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
			"10.9.1.0/22": "permit", // window 20-24
			"10.9.1.0/26": "deny",   // gap between windows -> stop
			"10.9.1.0/30": "permit", // window 28-32
			"10.8.0.0/16": "permit", // only /8
		} {
			if a := simulatePrefixList16762(lines, route); a != wantAction {
				t.Errorf("route %s: FRR first-match = %s, want %s", route, a, wantAction)
			}
		}
	})
}

// TestRouteFilterLongest17823UnequalLengthDisjointByteIdentity proves
// that longest-match sorting does not reorder a list with no containment:
// disjoint filters have no precedence relationship, regardless of plen.
func TestRouteFilterLongest17823UnequalLengthDisjointByteIdentity(t *testing.T) {
	po := rfPolicy16762(
		&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
		&config.RouteFilter{Prefix: "172.16.0.0/12", MatchType: "orlonger"},
	)
	got := New().generatePolicyOptions(po)
	name := inlinePrefixListName("P", "P", "t1", "")
	lines := prefixListLines16762(t, got, name)
	want := []string{
		"ip prefix-list " + name + " seq 5 permit 10.0.0.0/8 le 32",
		"ip prefix-list " + name + " seq 10 permit 172.16.0.0/12 le 32",
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
