package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRouteSnapshotCarriesPreference verifies #2390: StaticRoute.Preference
// is serialized into the RouteSnapshot so the Rust FIB can tie-break
// same-prefix routes by preference instead of insertion order. Before the
// fix the field was dropped at this boundary.
func TestRouteSnapshotCarriesPreference(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "203.0.113.0/24", Preference: 50, NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
		{Destination: "198.51.100.0/24", Preference: 5, NextHops: []config.NextHopEntry{{Address: "172.16.50.2"}}},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]int{}
	for _, r := range routes {
		got[r.Destination] = r.Preference
	}
	if got["203.0.113.0/24"] != 50 {
		t.Fatalf("preference 50 dropped: route 203.0.113.0/24 has preference %d", got["203.0.113.0/24"])
	}
	if got["198.51.100.0/24"] != 5 {
		t.Fatalf("preference 5 dropped: route 198.51.100.0/24 has preference %d", got["198.51.100.0/24"])
	}
}

// TestRouteSnapshotRetainsAllECMPNextHops verifies #2389: an ECMP static
// route with multiple next-hops serializes EVERY next-hop (the Rust FIB
// retains and distributes across them). The Go side always emitted all
// next-hops; this pins that contract so a future refactor cannot collapse
// the slice and silently disable multipath downstream.
func TestRouteSnapshotRetainsAllECMPNextHops(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "203.0.113.0/24", NextHops: []config.NextHopEntry{
			{Address: "172.16.50.1"},
			{Address: "172.16.50.2", Interface: "ge-0/0/2"},
		}},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	var found *RouteSnapshot
	for i := range routes {
		if routes[i].Destination == "203.0.113.0/24" {
			found = &routes[i]
			break
		}
	}
	if found == nil {
		t.Fatal("ECMP route not in snapshot")
	}
	if len(found.NextHops) != 2 {
		t.Fatalf("ECMP next-hops collapsed: got %d want 2 (%v)", len(found.NextHops), found.NextHops)
	}
	if found.NextHops[0] != "172.16.50.1" || found.NextHops[1] != "172.16.50.2@ge-0/0/2" {
		t.Fatalf("ECMP next-hop encoding wrong: %v", found.NextHops)
	}
}

// TestBuildInterfaceRoutingInstances verifies #2388: each interface is
// mapped to the bare routing-instance it belongs to, so the InterfaceSnapshot
// carries the data the Rust dataplane needs to table-scope connected routes.
func TestBuildInterfaceRoutingInstances(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "tenant-a", Interfaces: []string{"ge-0/0/1.80"}},
		{Name: "tenant-b", Interfaces: []string{"ge-0/0/1.90", "ge-0/0/3"}},
	}
	m := buildInterfaceRoutingInstances(cfg)

	if m["ge-0/0/1.80"] != "tenant-a" {
		t.Fatalf("ge-0/0/1.80 routing-instance = %q, want tenant-a", m["ge-0/0/1.80"])
	}
	if m["ge-0/0/1.90"] != "tenant-b" {
		t.Fatalf("ge-0/0/1.90 routing-instance = %q, want tenant-b", m["ge-0/0/1.90"])
	}
	if m["ge-0/0/3"] != "tenant-b" {
		t.Fatalf("ge-0/0/3 routing-instance = %q, want tenant-b", m["ge-0/0/3"])
	}
	// An interface not in any routing-instance is the default ("").
	if _, ok := m["fxp0"]; ok {
		t.Fatalf("unmapped interface fxp0 should be absent (default instance), got %q", m["fxp0"])
	}
}
