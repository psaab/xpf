package userspace

// #18517: on a split node (WAN RG peer-owned) the configured default whose
// gateway sits in the peer-owned RETH prefix must stay in the helper
// snapshot. The helper FIB binds that bare gateway to the peer-owned egress
// (`peer_owned_connected_target_v4/v6`, which scans only the peer-owned
// connected rows of the route's own table), so the row HA-demotes and
// crosses the fabric. Filtering it as recursive (#11317) left only the
// unstamped Null0 terminal and every new flow toward the WAN was discarded
// instead of fabric-redirected. The peer-owned prefix itself stays out of the
// transit FIB (#15742).

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

func splitNodeConfig18517() *config.Config {
	cfg := clusteredConfig15742()
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		// Gateway inside reth0.80 (RG1, peer-owned below).
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.80.1"}}},
		// Gateway covered by no prefix at all: still recursive.
		{Destination: "10.30.0.0/24", NextHops: []config.NextHopEntry{{Address: "198.51.100.1"}}},
	}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
		{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:559:8585:80::1"}}},
	}
	return cfg
}

func TestSplitNodeKeepsStaticViaPeerOwnedGateway18517(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	splitNode := func(rgID int) (bool, bool) {
		switch rgID {
		case 1:
			return false, true // WAN RG peer-owned
		case 2:
			return true, true // LAN RG local
		default:
			return false, false
		}
	}
	routes, _, err := buildRouteSnapshotsWithRGPrimary(splitNodeConfig18517(), connectedRGInterfaces15742(), nil, splitNode)
	if err != nil {
		t.Fatalf("buildRouteSnapshotsWithRGPrimary: %v", err)
	}
	if hasConnectedRoute15742(routes, "172.16.80.0/24") || hasConnectedRoute15742(routes, "2001:559:8585:80::/64") {
		t.Fatalf("peer-owned RG1 prefix entered the transit FIB (#15742 regression): %+v", routes)
	}
	v4 := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", routes)
	if len(v4) != 1 || !reflect.DeepEqual(v4[0].NextHops, []string{"172.16.80.1"}) {
		t.Fatalf("split node lost the configured v4 default via the peer-owned gateway: %+v (all rows: %+v)", v4, routes)
	}
	v6 := snapshotFor(t, "inet6.0", "inet6", "::/0", routes)
	if len(v6) != 1 || !reflect.DeepEqual(v6[0].NextHops, []string{"2001:559:8585:80::1"}) {
		t.Fatalf("split node lost the configured v6 default via the peer-owned gateway: %+v", v6)
	}
	// #11317 unchanged: a gateway no prefix covers is still recursive.
	if hits := snapshotFor(t, "inet.0", "inet", "10.30.0.0/24", routes); len(hits) != 0 {
		t.Fatalf("recursive static must still be filtered: %+v", hits)
	}
}

// The owner keeps the same default and additionally the transit prefix: the
// fix must not change the locally-owned shape.
func TestOwnerNodeStaticAndConnectedUnchanged18517(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	owner := func(rgID int) (bool, bool) { return true, rgID == 1 || rgID == 2 }
	routes, _, err := buildRouteSnapshotsWithRGPrimary(splitNodeConfig18517(), connectedRGInterfaces15742(), nil, owner)
	if err != nil {
		t.Fatalf("buildRouteSnapshotsWithRGPrimary: %v", err)
	}
	if !hasConnectedRoute15742(routes, "172.16.80.0/24") {
		t.Fatalf("owner lost its transit prefix: %+v", routes)
	}
	if v4 := snapshotFor(t, "inet.0", "inet", "0.0.0.0/0", routes); len(v4) != 1 {
		t.Fatalf("owner default = %+v, want one row", v4)
	}
	if hits := snapshotFor(t, "inet.0", "inet", "10.30.0.0/24", routes); len(hits) != 0 {
		t.Fatalf("recursive static must still be filtered on the owner: %+v", hits)
	}
}

// #18517 review fold (HA/semantics seat MINOR, routing seat A1/A2): on the
// split node a configured static via the peer-owned WAN gateway now REPLACES
// a same-prefix learned route via a LOCAL interface (a BGP default from a
// second ISP on the locally-owned LAN RG, say). The static is at least as
// preferred as the learned protocol distance, so addLearnedRouteSnapshots
// suppresses the twin, and the Rust FIB binds the static to the peer-owned
// egress (HAInactive, then FabricRedirect). That is Junos semantics: a
// preference-5 static via a RETH is active cluster-wide. The owner node emits
// the same row. Production-shaped learned input: the kernel twin for both
// families; the non-default shape also carries the cluster-mode Null0
// terminals the kernel holds while no real default exists. They are inert
// for the asserted prefixes (their coexistence with a configured default is
// TestLearnedClusterDiscardCoexistsWithConfigDefault15742's cell).
//
// FAIL-ON-REVERT: drop the peer-owned addGatewayNetworks calls in
// buildRouteSnapshotsWithRGPrimary and the split node filters the static as
// recursive and keeps the learned twin; drop the suppression `continue` in
// addLearnedRouteSnapshots and both nodes keep the twin beside the static.
func TestSplitNodeStaticReplacesLocalLearnedTwin18517(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	const (
		lanGW4 = "10.0.61.254"             // inside reth1.0 (RG2, local on both nodes)
		lanGW6 = "2001:559:8585:ef00::254" // inside reth1.0
		wanGW4 = "172.16.80.1"             // inside reth0.80 (RG1)
		wanGW6 = "2001:559:8585:80::1"     // inside reth0.80
	)
	terminal := func(family int, dst string) routing.LearnedRoute {
		return routing.LearnedRoute{
			TableID: 254, Family: family, Destination: dst,
			Protocol: "static", Discard: true, ClusterTerminal: true,
		}
	}
	type prefixCase struct {
		name, table, family, dest, wanGW, lanGW string
	}
	shapes := []struct {
		name     string
		statics  []*config.StaticRoute
		statics6 []*config.StaticRoute
		learned  []routing.LearnedRoute
		cases    []prefixCase
	}{
		{
			name:     "default twin (A2)",
			statics:  []*config.StaticRoute{{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: wanGW4}}}},
			statics6: []*config.StaticRoute{{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: wanGW6}}}},
			learned:  []routing.LearnedRoute{learnedV4("0.0.0.0/0", lanGW4), learnedV6("::/0", lanGW6)},
			cases: []prefixCase{
				{"v4", "inet.0", "inet", "0.0.0.0/0", wanGW4, lanGW4},
				{"v6", "inet6.0", "inet6", "::/0", wanGW6, lanGW6},
			},
		},
		{
			name:     "non-default twin (A1)",
			statics:  []*config.StaticRoute{{Destination: "10.50.0.0/16", NextHops: []config.NextHopEntry{{Address: wanGW4}}}},
			statics6: []*config.StaticRoute{{Destination: "2001:db8:50::/48", NextHops: []config.NextHopEntry{{Address: wanGW6}}}},
			learned: []routing.LearnedRoute{
				learnedV4("10.50.0.0/16", lanGW4), learnedV6("2001:db8:50::/48", lanGW6),
				terminal(netlink.FAMILY_V4, "0.0.0.0/0"), terminal(netlink.FAMILY_V6, "::/0"),
			},
			cases: []prefixCase{
				{"v4", "inet.0", "inet", "10.50.0.0/16", wanGW4, lanGW4},
				{"v6", "inet6.0", "inet6", "2001:db8:50::/48", wanGW6, lanGW6},
			},
		},
	}
	nodes := []struct {
		name     string
		provider func(int) (bool, bool)
	}{
		{"split", func(rgID int) (bool, bool) {
			switch rgID {
			case 1:
				return false, true // WAN RG peer-owned
			case 2:
				return true, true // LAN RG local
			default:
				return false, false
			}
		}},
		{"owner", func(rgID int) (bool, bool) { return true, rgID == 1 || rgID == 2 }},
	}
	for _, shape := range shapes {
		for _, node := range nodes {
			t.Run(shape.name+"/"+node.name, func(t *testing.T) {
				withLearnedRoutes(t, fixedLearned(shape.learned...))
				cfg := clusteredConfig15742()
				cfg.RoutingOptions.StaticRoutes = shape.statics
				cfg.RoutingOptions.Inet6StaticRoutes = shape.statics6
				routes, _, err := buildRouteSnapshotsWithRGPrimary(cfg, connectedRGInterfaces15742(), nil, node.provider)
				if err != nil {
					t.Fatalf("buildRouteSnapshotsWithRGPrimary: %v", err)
				}
				for _, c := range shape.cases {
					var forwarding []RouteSnapshot
					for _, row := range snapshotFor(t, c.table, c.family, c.dest, routes) {
						if !row.Discard && !row.Reject {
							forwarding = append(forwarding, row)
						}
					}
					if len(forwarding) != 1 || !reflect.DeepEqual(forwarding[0].NextHops, []string{c.wanGW}) {
						t.Fatalf("%s %s: want exactly the configured static via %s (learned twin via %s suppressed), got %+v",
							c.name, c.dest, c.wanGW, c.lanGW, forwarding)
					}
				}
			})
		}
	}
}
