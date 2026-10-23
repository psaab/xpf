package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRouteSnapshotRejectSurvivesForRecursiveExpansion15948 closes the
// producer premise of #15948 H36-03: a `reject` static route must reach
// the Rust snapshot as Reject=true (not folded into Discard), in both
// families, so the Rust recursive next-hop expansion can treat it as
// terminal. The Rust-side terminal behaviour itself is pinned by
// recursive_static_reject_terminal_15948 in forwarding_build/tests.rs.
func TestRouteSnapshotRejectSurvivesForRecursiveExpansion15948(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", Preference: 5, NextHops: []config.NextHopEntry{{Address: "198.51.100.1", Interface: "ge-0/0/5"}}},
		{Destination: "10.20.0.0/16", Reject: true, Preference: 5},
		{Destination: "172.16.50.0/24", Preference: 5, NextHops: []config.NextHopEntry{{Address: "10.20.1.1"}}},
	}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
		{Destination: "::/0", Preference: 5, NextHops: []config.NextHopEntry{{Address: "2001:db8:ffff::1", Interface: "ge-0/0/5"}}},
		{Destination: "2001:db8:20::/48", Reject: true, Preference: 5},
		{Destination: "2001:db8:50::/64", Preference: 5, NextHops: []config.NextHopEntry{{Address: "2001:db8:20::1"}}},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	byDest := make(map[string]RouteSnapshot, len(routes))
	for _, r := range routes {
		byDest[r.Destination] = r
	}
	for _, dest := range []string{"10.20.0.0/16", "2001:db8:20::/48"} {
		got, ok := byDest[dest]
		if !ok {
			t.Fatalf("%s: reject route missing from snapshot", dest)
		}
		if !got.Reject || got.Discard {
			t.Errorf("%s: Reject=%v Discard=%v, want Reject=true Discard=false (reject must not fold into discard)", dest, got.Reject, got.Discard)
		}
		if len(got.NextHops) != 0 {
			t.Errorf("%s: reject route carries next-hops %v, want none", dest, got.NextHops)
		}
	}
	// The indirect destinations must still be published (their resolution
	// is the Rust builder's job, not the snapshot's).
	for _, dest := range []string{"172.16.50.0/24", "2001:db8:50::/64"} {
		if _, ok := byDest[dest]; !ok {
			t.Errorf("%s: indirect route missing from snapshot", dest)
		}
	}
}
