package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestBuildRouteSnapshotsNormalizesFamilyFromDestination(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name: "blue",
			StaticRoutes: []*config.StaticRoute{
				// #5830: a per-instance next-table is now DROPPED from the
				// userspace snapshot (it is not programmed on kernel/FRR — a
				// split-brain). This test only exercises family-normalization
				// from the destination, so use a forwarding next-hop route (which
				// survives) as the vehicle. A v6 destination in the inet-labeled
				// StaticRoutes list must still normalize to inet6 / blue.inet6.0.
				{Destination: "2001:db8:1::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:1::1"}}},
			},
		},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if routes[0].Family != "inet6" || routes[0].Table != "blue.inet6.0" {
		t.Fatalf("routes[0] = %+v, want family inet6 table blue.inet6.0", routes[0])
	}
	if routes[1].Family != "inet6" || routes[1].Table != "inet6.0" {
		t.Fatalf("routes[1] = %+v, want family inet6 table inet6.0", routes[1])
	}
}

func TestBuildRouteSnapshotsIncludesConnectedPrefixes(t *testing.T) {
	routes, _, err := buildRouteSnapshots(&config.Config{}, []InterfaceSnapshot{
		{
			Name:    "reth1.0",
			Ifindex: 11,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.61.1/24", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet6", Address: "2001:559:8585:ef00::1/64", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet6", Address: "fe80::1/64", Scope: int(netlink.SCOPE_LINK)},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if routes[0].Destination != "10.0.61.0/24" || routes[0].Table != "inet.0" {
		t.Fatalf("routes[0] = %+v", routes[0])
	}
	if routes[1].Destination != "2001:559:8585:ef00::/64" || routes[1].Table != "inet6.0" {
		t.Fatalf("routes[1] = %+v", routes[1])
	}
}

func TestBuildRouteSnapshotsCompactsDuplicateConnectedAddresses11452(t *testing.T) {
	routes, _, err := buildRouteSnapshots(&config.Config{}, []InterfaceSnapshot{
		{
			Name:    "reth1.0",
			Ifindex: 12,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.30.3/24", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet", Address: "10.0.30.2/24", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet", Address: "10.0.30.1/24", Scope: int(netlink.SCOPE_UNIVERSE)},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Table != "inet.0" || routes[0].Destination != "10.0.30.0/24" {
		t.Fatalf("connected FIB rows = %+v, want one inet.0 row for 10.0.30.0/24", routes)
	}
}

func TestBuildRouteSnapshotsDropsCrossFamilyRoutes11421(t *testing.T) {
	oldRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = oldRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	badMixed := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops: []config.NextHopEntry{
			{Address: "2001:db8::1"},
			{Address: "192.0.2.1"},
		},
	}
	badOnly := &config.StaticRoute{
		Destination: "172.16.0.0/12",
		NextHops:    []config.NextHopEntry{{Address: "2001:db8::2"}},
	}
	healthy := &config.StaticRoute{
		Destination: "192.0.2.0/24",
		NextHops:    []config.NextHopEntry{{Address: "192.0.2.254"}},
	}
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{badMixed, badOnly, healthy}

	exclusions := config.StaticRouteExclusions(cfg)
	if exclusions[badMixed] == "" || exclusions[badOnly] == "" {
		t.Fatalf("cross-family routes missing from the shared exclusion verdict: %+v", exclusions)
	}
	if exclusions[healthy] != "" {
		t.Fatalf("healthy route was excluded: %q", exclusions[healthy])
	}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	foundHealthy := false
	for _, route := range routes {
		switch route.Destination {
		case badMixed.Destination, badOnly.Destination:
			t.Fatalf("cross-family route entered the helper FIB: %+v", route)
		case healthy.Destination:
			foundHealthy = route.Family == "inet" &&
				len(route.NextHops) == 1 && route.NextHops[0] == "192.0.2.254"
		}
	}
	if !foundHealthy {
		t.Fatal("same-family control route did not enter the helper FIB")
	}
}
