package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6568 (member 1): a route destination the Rust FIB cannot PARSE must never
// reach the wire silently.
//
// `populate_routes` (userspace-dp/src/afxdp/forwarding_build/fib.rs) tries
// `Ipv4Net` then `Ipv6Net` and, before the fix, fell off the end of the loop
// body when both failed — no Err, no counter, no log — at a boundary whose
// whole #2409/#2410/#3771 contract is "no silent skips".
//
// The cohort filed this as a low-materiality residual with "no traffic
// fail-open". Measured, that is wrong on both counts. `ipnet`'s parsers REQUIRE
// a prefix length and nothing in the config compiler validates the destination,
// so all three of these commit cleanly, ship, and vanish in the helper:
//
//	set routing-options static route 10.0.0.1 discard
//	set routing-options static route 2001:db8::1 discard
//	set routing-options static route default discard
//
// For a discard/reject route that is a FAIL-OPEN: with no blackhole entry the
// packet longest-prefix matches a LESS-SPECIFIC route (typically the default)
// and is FORWARDED where the operator asked for it to be dropped — presenting
// as a routing mystery, because the control plane, FRR and the kernel all show
// the route as configured.
//
// FAIL-ON-REVERT: drop the routeDestinationForWire call from addSnapshot and
// the bare-host cases below ship their unparseable destination again.

func TestRouteDestinationForWire(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
		why  string
	}{
		{"10.9.0.0/16", "10.9.0.0/16", true, "a valid v4 CIDR passes through unchanged"},
		{"2001:db8::/64", "2001:db8::/64", true, "a valid v6 CIDR passes through unchanged"},
		{"0.0.0.0/0", "0.0.0.0/0", true, "the default route is a valid CIDR"},
		{"10.0.0.1", "10.0.0.1/32", true, "a bare v4 host gains its /32"},
		{"2001:db8::1", "2001:db8::1/128", true, "a bare v6 host gains its /128"},
		{"default", "", false, "the Junos default keyword is not a prefix"},
		{"", "", false, "empty is not a prefix"},
		{"10.0.0.300/24", "", false, "an out-of-range octet is not a prefix"},
		{"not-an-address", "", false, "a typo is not a prefix"},
		// A host-bearing prefix must NOT be re-masked: rewriting 10.0.0.5/24 to
		// 10.0.0.0/24 would change the installed prefix AND the addSnapshot
		// dedupe key. This fix has no business making that change.
		{"10.0.0.5/24", "10.0.0.5/24", true, "a host-bearing prefix is not re-masked"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := routeDestinationForWire(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (%s)", ok, tc.ok, tc.why)
			}
			if ok && got != tc.want {
				t.Errorf("= %q, want %q (%s)", got, tc.want, tc.why)
			}
		})
	}
}

// TestRouteDestinationForWireDoesNotFoldMappedIPv6 pins the net.IP.To4() trap:
// To4() folds an IPv4-MAPPED IPv6 address to its 4-byte form, so a family test
// keyed on it would emit "::ffff:10.0.0.1/32" — a v6 literal carrying a v4
// prefix length, which parses as NEITHER family and would be exactly the silent
// drop this fix exists to remove.
func TestRouteDestinationForWireDoesNotFoldMappedIPv6(t *testing.T) {
	got, ok := routeDestinationForWire("::ffff:10.0.0.1")
	if !ok {
		t.Skip("mapped-IPv6 destinations are rejected outright, which is also safe")
	}
	if strings.HasSuffix(got, "/32") {
		t.Fatalf("= %q — To4() folded a mapped IPv6 address into a v4 prefix "+
			"length; the result parses as neither family", got)
	}
	if got != "::ffff:10.0.0.1/128" {
		t.Errorf("= %q, want ::ffff:10.0.0.1/128", got)
	}
}

// staticRouteSnapshots builds the helper FIB for a config carrying one static
// route with the given destination.
func staticRouteSnapshots(t *testing.T, dest string, discard bool) []RouteSnapshot {
	t.Helper()
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: dest, Discard: discard, NextHops: nil},
	}
	snaps, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots(%q): %v", dest, err)
	}
	return snaps
}

// TestBareHostDiscardRouteReachesTheWireInstallable is the core RED-on-revert:
// the exact config that used to vanish must now ship a prefix the Rust FIB can
// parse.
func TestBareHostDiscardRouteReachesTheWireInstallable(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.1/32"},
		{"2001:db8::1", "2001:db8::1/128"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			snaps := staticRouteSnapshots(t, tc.in, true)
			found := false
			for _, s := range snaps {
				if s.Destination == tc.want {
					found = true
					if !s.Discard {
						t.Errorf("the discard flag was lost: %+v", s)
					}
				}
				if s.Destination == tc.in {
					t.Errorf("the raw bare host %q reached the wire — the Rust "+
						"FIB parses neither family for it and would drop the "+
						"blackhole silently", tc.in)
				}
			}
			if !found {
				t.Fatalf("no snapshot carries %q; got %+v", tc.want, snaps)
			}
		})
	}
}

// TestUnusableDestinationNeverReachesTheWire: a destination that cannot be made
// into a prefix is dropped HERE (loudly, with a WARN naming the route) rather
// than shipped for the helper to skip in silence.
func TestUnusableDestinationNeverReachesTheWire(t *testing.T) {
	for _, dest := range []string{"default", "not-an-address"} {
		t.Run(dest, func(t *testing.T) {
			for _, s := range staticRouteSnapshots(t, dest, true) {
				if s.Destination == dest {
					t.Errorf("unusable destination %q reached the wire", dest)
				}
			}
		})
	}
}

// TestValidPrefixRoutesAreUnaffected is the negative control: the fix must not
// disturb the ordinary case, including the default route.
func TestValidPrefixRoutesAreUnaffected(t *testing.T) {
	for _, dest := range []string{"10.9.0.0/16", "0.0.0.0/0", "2001:db8::/64", "::/0"} {
		t.Run(dest, func(t *testing.T) {
			snaps := staticRouteSnapshots(t, dest, true)
			found := false
			for _, s := range snaps {
				if s.Destination == dest {
					found = true
				}
			}
			if !found {
				t.Fatalf("valid prefix %q no longer reaches the wire: %+v", dest, snaps)
			}
		})
	}
}
