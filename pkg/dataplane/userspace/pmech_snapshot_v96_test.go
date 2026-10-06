package userspace

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func v96MainRoute(t *testing.T, destination string, disposition, ifindex int) netlink.Route {
	t.Helper()
	_, dst, err := net.ParseCIDR(destination)
	if err != nil {
		t.Fatalf("parse route prefix %q: %v", destination, err)
	}
	return netlink.Route{
		Table:     int(pmechMainTable),
		Family:    unix.AF_INET,
		Dst:       dst,
		Type:      disposition,
		LinkIndex: ifindex,
	}
}

func TestPMechMainRouteStampRequiresMainTableAndEmitsDomainBytes(t *testing.T) {
	route := v96MainRoute(t, "203.0.113.0/24", unix.RTN_UNICAST, 3)
	snapshot := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
	stampPMechInventoryFromRoutes(snapshot, []netlink.Route{route}, nil)

	if !snapshot.PMechInventory.Complete {
		t.Fatal("one valid main-table route must complete the inventory")
	}
	got, err := json.Marshal(snapshot.PMechInventory.MainRoutes)
	if err != nil {
		t.Fatalf("marshal stamped routes: %v", err)
	}
	want := []byte(`[{"domain":0,"table":254,"family":"inet","destination":"203.0.113.0/24","protocol":0,"disposition":1,"next_hops":[{"ifindex":3,"weight":1}]}]`)
	if !bytes.Equal(got, want) {
		t.Fatalf("stamped route bytes differ\n got: %s\nwant: %s", got, want)
	}

	for _, table := range []int{0, 253} {
		bad := route
		bad.Table = table
		poisoned := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
		stampPMechInventoryFromRoutes(poisoned, []netlink.Route{bad}, nil)
		if poisoned.PMechInventory.Complete {
			t.Fatalf("route table %d must poison inventory completeness", table)
		}
		if got := poisoned.PMechInventory.MainRoutes[0].Table; got != uint32(table) {
			t.Fatalf("audit row lost explicit route table: got %d want %d", got, table)
		}
	}
}

func TestPMechInventoryEmptyRoutesAreIncomplete(t *testing.T) {
	snapshot := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
	stampPMechInventoryFromRoutes(snapshot, nil, nil)
	if snapshot.PMechInventory.Complete {
		t.Fatal("an empty route dump must not claim a complete inventory")
	}
	if len(snapshot.PMechInventory.MainRoutes) != 0 {
		t.Fatalf("empty route dump produced %d audit rows", len(snapshot.PMechInventory.MainRoutes))
	}
}

func TestPMechDiscardRowsAreRetainedWithoutLegsButMalformedRoutesPoison(t *testing.T) {
	blackhole := v96MainRoute(t, "10.1.0.0/16", unix.RTN_BLACKHOLE, 0)
	valid := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
	stampPMechInventoryFromRoutes(valid, []netlink.Route{blackhole}, nil)
	if !valid.PMechInventory.Complete {
		t.Fatal("known blackhole route must be retained without poisoning completeness")
	}
	if len(valid.PMechInventory.MainRoutes) != 1 ||
		valid.PMechInventory.MainRoutes[0].Disposition != unix.RTN_BLACKHOLE {
		t.Fatalf("blackhole audit row not retained: %+v", valid.PMechInventory.MainRoutes)
	}
	if len(valid.PMechInventory.MainRoutes[0].NextHops) != 0 {
		t.Fatalf("blackhole without an output leg acquired legs: %+v", valid.PMechInventory.MainRoutes[0].NextHops)
	}

	malformedDiscard := v96MainRoute(t, "10.3.0.0/16", unix.RTN_BLACKHOLE, 0)
	malformedDiscard.MultiPath = []*netlink.NexthopInfo{{LinkIndex: 0, Hops: 0}}
	poisonedDiscard := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
	stampPMechInventoryFromRoutes(poisonedDiscard, []netlink.Route{malformedDiscard}, nil)
	if poisonedDiscard.PMechInventory.Complete {
		t.Fatal("malformed captured discard nexthop must poison inventory")
	}

	malformed := v96MainRoute(t, "10.2.0.0/16", unix.RTN_UNICAST, 0)
	poisoned := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
	stampPMechInventoryFromRoutes(poisoned, []netlink.Route{malformed}, nil)
	if poisoned.PMechInventory.Complete {
		t.Fatal("unicast route missing its exact output ifindex must poison completeness")
	}
	if len(poisoned.PMechInventory.MainRoutes) != 1 ||
		len(poisoned.PMechInventory.MainRoutes[0].NextHops) != 1 ||
		poisoned.PMechInventory.MainRoutes[0].NextHops[0].Ifindex != 0 {
		t.Fatalf("malformed route audit row/leg was not preserved: %+v", poisoned.PMechInventory.MainRoutes)
	}
}

func TestPMechKnownNonForwardingRoutesRemainAuditable(t *testing.T) {
	for _, disposition := range []int{
		unix.RTN_LOCAL,
		unix.RTN_BLACKHOLE,
		unix.RTN_UNREACHABLE,
		unix.RTN_PROHIBIT,
	} {
		snapshot := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
		route := v96MainRoute(t, "10.4.0.0/16", disposition, 0)
		stampPMechInventoryFromRoutes(snapshot, []netlink.Route{route}, nil)
		if !snapshot.PMechInventory.Complete {
			t.Fatalf("known disposition %d must not poison inventory", disposition)
		}
		if len(snapshot.PMechInventory.MainRoutes) != 1 {
			t.Fatalf("known disposition %d audit row missing: %+v",
				disposition, snapshot.PMechInventory.MainRoutes)
		}
		row := snapshot.PMechInventory.MainRoutes[0]
		if row.Domain != 0 || row.Table != pmechMainTable || row.Disposition != uint8(disposition) {
			t.Fatalf("known disposition %d lost explicit identity: %+v", disposition, row)
		}
		if len(row.NextHops) != 0 {
			t.Fatalf("known disposition %d acquired a forwarding leg: %+v", disposition, row.NextHops)
		}
	}
}

func TestPMechProjectionHonorsMoreSpecificBlackhole(t *testing.T) {
	unicast := v96MainRoute(t, "10.0.0.0/8", unix.RTN_UNICAST, 10)
	blackhole := v96MainRoute(t, "10.1.0.0/16", unix.RTN_BLACKHOLE, 10)
	snapshot := &ConfigSnapshot{
		Generation:    11,
		FIBGeneration: 7,
		Config: &config.Config{Security: config.SecurityConfig{IPsec: config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
			"vpn": {
				BindInterface: "st0",
				LocalID:       "192.0.2.0/24",
				RemoteID:      "10.0.0.0/8",
			},
		}}}},
		IpsecTunnelRows: []IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}},
	}
	stampPMechInventoryFromRoutes(snapshot, []netlink.Route{unicast, blackhole}, nil)
	inventory := snapshot.PMechInventory
	if !inventory.Complete || len(inventory.MainRoutes) != 2 {
		t.Fatalf("blackhole should be audited without poisoning inventory: %+v", inventory)
	}
	var discard *IpsecMainRouteSnapshot
	for i := range inventory.MainRoutes {
		if inventory.MainRoutes[i].Disposition == unix.RTN_BLACKHOLE {
			discard = &inventory.MainRoutes[i]
			break
		}
	}
	if discard == nil || len(discard.NextHops) != 1 || discard.NextHops[0].Ifindex != 10 {
		t.Fatalf("discard audit row did not retain its captured nexthop: %+v", discard)
	}
	if inventory.TunnelRows[0].InventoryReason != "" || !inventory.TunnelRows[0].InventoryValid {
		t.Fatalf("eligible route projection unexpectedly invalid: %+v", inventory.TunnelRows[0])
	}
	if len(inventory.TunnelRows[0].EffectivePrefixes) != 8 {
		t.Fatalf("/8 minus /16 should canonicalize to eight prefixes, got %v", inventory.TunnelRows[0].EffectivePrefixes)
	}
	blocked := netip.MustParseAddr("10.1.1.1")
	allowed := netip.MustParseAddr("10.2.1.1")
	contains := func(address netip.Addr) bool {
		for _, value := range inventory.TunnelRows[0].EffectivePrefixes {
			prefix := netip.MustParsePrefix(value)
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	if contains(blocked) {
		t.Fatal("broad unicast route must not project through its more-specific blackhole")
	}
	if !contains(allowed) {
		t.Fatal("unshadowed unicast destination was lost from selector projection")
	}
}
func TestPMechProjectionHonorsMoreSpecificForeignUnicast(t *testing.T) {
	parse := func(route netlink.Route) pmechParsedMainRoute {
		row, prefix, legs, ok := snapshotPMechMainRoute(route)
		if !ok {
			t.Fatalf("parse valid route: %+v", route)
		}
		return pmechParsedMainRoute{snapshot: row, prefix: prefix, nextHops: legs}
	}
	routes := []pmechParsedMainRoute{
		parse(v96MainRoute(t, "10.0.0.0/8", unix.RTN_UNICAST, 10)),
		parse(v96MainRoute(t, "10.1.0.0/16", unix.RTN_UNICAST, 11)),
	}
	eligible := pmechRoutePrefixesForLeg(routes[0], 10, routes)
	blocked := netip.MustParseAddr("10.1.1.1")
	allowed := netip.MustParseAddr("10.2.1.1")
	contains := func(address netip.Addr) bool {
		for _, prefix := range eligible {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	if contains(blocked) || !contains(allowed) {
		t.Fatalf("more-specific foreign egress did not shadow only its prefix: %v", eligible)
	}
}

func TestPMechConflictingSamePrefixLegsPoisonInventory(t *testing.T) {
	routes := []netlink.Route{
		v96MainRoute(t, "10.0.0.0/24", unix.RTN_UNICAST, 10),
		v96MainRoute(t, "10.0.0.0/24", unix.RTN_UNICAST, 11),
	}
	snapshot := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
	stampPMechInventoryFromRoutes(snapshot, routes, nil)
	if snapshot.PMechInventory.Complete {
		t.Fatal("conflicting same-prefix output legs must poison route authority")
	}
	if len(snapshot.PMechInventory.MainRoutes) != 2 {
		t.Fatalf("conflicting route audit rows were lost: %+v", snapshot.PMechInventory.MainRoutes)
	}
}
