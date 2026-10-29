package userspace

// #18517: on a split node (WAN RG peer-owned) the configured default whose
// gateway sits in the peer-owned RETH prefix must stay in the helper
// snapshot. It is the row the cluster-terminal attribution resolves through
// the by-ifindex ledger; filtering it as recursive (#11317) left only the
// unstamped Null0 terminal and every new flow toward the WAN was discarded
// instead of fabric-redirected. The peer-owned prefix itself stays out of the
// transit FIB (#15742).

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
