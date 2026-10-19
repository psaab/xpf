package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func connectedRGInterfaces15742() []InterfaceSnapshot {
	return []InterfaceSnapshot{
		{
			Name:            "reth0.80",
			Ifindex:         12,
			RedundancyGroup: 1,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "172.16.80.8/24", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet6", Address: "2001:559:8585:80::8/64", Scope: int(netlink.SCOPE_UNIVERSE)},
			},
		},
		{
			Name:            "reth1.0",
			Ifindex:         24,
			RedundancyGroup: 2,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.61.1/24", Scope: int(netlink.SCOPE_UNIVERSE)},
				{Family: "inet6", Address: "2001:559:8585:ef00::1/64", Scope: int(netlink.SCOPE_UNIVERSE)},
			},
		},
		{
			Name:    "ge-0/0/9.0",
			Ifindex: 30,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet", Address: "192.0.2.1/24", Scope: int(netlink.SCOPE_UNIVERSE)},
			},
		},
	}
}

func clusteredConfig15742() *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1, NodeID: 1}
	return cfg
}

func hasConnectedRoute15742(routes []RouteSnapshot, destination string) bool {
	for _, route := range routes {
		if route.Destination == destination && route.NextTable == "" && len(route.NextHops) == 0 && !route.Discard && !route.Reject {
			return true
		}
	}
	return false
}

// The live split shape: WAN connected prefixes are addresses on the RG1
// unit while RG2/LAN is locally owned. On the non-owner they must not be
// published as transit connected prefixes, or LPM shadows the default and
// prevents the HAInactive -> FabricRedirect chain.
func TestConnectedPrefixesFilteredForPeerOwnedRG15742(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	provider := func(rgID int) (bool, bool) {
		switch rgID {
		case 1:
			return false, true
		case 2:
			return true, true
		default:
			return false, false
		}
	}
	cfg := clusteredConfig15742()
	interfaces := connectedRGInterfaces15742()
	routes, _, err := buildRouteSnapshotsWithRGPrimary(cfg, interfaces, nil, provider)
	if err != nil {
		t.Fatalf("buildRouteSnapshotsWithRGPrimary: %v", err)
	}
	if hasConnectedRoute15742(routes, "172.16.80.0/24") || hasConnectedRoute15742(routes, "2001:559:8585:80::/64") {
		t.Fatalf("peer-owned RG1 connected prefixes published: %+v", routes)
	}
	if !hasConnectedRoute15742(routes, "10.0.61.0/24") || !hasConnectedRoute15742(routes, "2001:559:8585:ef00::/64") {
		t.Fatalf("locally owned RG2 connected prefixes missing: %+v", routes)
	}
	if !hasConnectedRoute15742(routes, "192.0.2.0/24") {
		t.Fatalf("non-RETH connected prefix missing: %+v", routes)
	}
	marked := markConnectedRGPeerOwned(cfg, interfaces, provider)
	if !marked[0].ConnectedRGPeerOwned || marked[1].ConnectedRGPeerOwned || marked[2].ConnectedRGPeerOwned {
		t.Fatalf("marked rows = %+v, want only RG1 peer-owned", marked)
	}
	if interfaces[0].ConnectedRGPeerOwned {
		t.Fatal("markConnectedRGPeerOwned mutated caller's interface rows")
	}
}

func TestConnectedPrefixesKeptForLocalAndStandaloneRG15742(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	local := func(rgID int) (bool, bool) { return true, rgID == 1 || rgID == 2 }
	routes, _, err := buildRouteSnapshotsWithRGPrimary(clusteredConfig15742(), connectedRGInterfaces15742(), nil, local)
	if err != nil {
		t.Fatalf("local build: %v", err)
	}
	if !hasConnectedRoute15742(routes, "172.16.80.0/24") || !hasConnectedRoute15742(routes, "2001:559:8585:80::/64") {
		t.Fatalf("locally owned RG1 connected prefixes missing: %+v", routes)
	}

	standalone, _, err := buildRouteSnapshotsWithRGPrimary(&config.Config{}, connectedRGInterfaces15742(), nil, nil)
	if err != nil {
		t.Fatalf("standalone build: %v", err)
	}
	if !hasConnectedRoute15742(standalone, "172.16.80.0/24") {
		t.Fatalf("standalone connected prefix missing: %+v", standalone)
	}
}

func TestConnectedPrefixesFilterUnknownClusteredRG15742(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	for name, provider := range map[string]RGPrimaryProvider{
		"nil provider": nil,
		"unknown RG":   func(int) (bool, bool) { return false, false },
	} {
		routes, _, err := buildRouteSnapshotsWithRGPrimary(clusteredConfig15742(), connectedRGInterfaces15742(), nil, provider)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hasConnectedRoute15742(routes, "172.16.80.0/24") {
			t.Fatalf("%s published unknown clustered RG prefix: %+v", name, routes)
		}
	}
}

func TestFormatFIBDumpShowsReject15742(t *testing.T) {
	out := FormatFIBDump(9, []FibRouteWire{
		{Table: "inet.0", Family: "inet", Destination: "0.0.0.0/0", Kind: "route", Reject: true, Preference: 200},
		{Table: "inet.0", Family: "inet", Destination: "10.0.0.0/8", Kind: "route", Discard: true, Preference: 200},
	})
	if !strings.Contains(out, "reject") || !strings.Contains(out, "discard") {
		t.Fatalf("FIB dump does not distinguish reject from discard:\n%s", out)
	}
}
