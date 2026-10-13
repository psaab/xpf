package userspace

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestPMechPreferredSourceIsNotASourceSelector9506(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route netlink.Route
	}{
		{
			name: "connected kernel route",
			route: func() netlink.Route {
				route := v96MainRoute(t, "192.0.2.0/24", unix.RTN_UNICAST, 3)
				route.Protocol = unix.RTPROT_KERNEL
				route.Scope = netlink.SCOPE_LINK
				route.Src = net.ParseIP("192.0.2.1")
				route.Flags = pmechRouteFlagLinkDown
				return route
			}(),
		},
		{
			name: "DHCP preferred-source default",
			route: netlink.Route{
				Table:     int(pmechMainTable),
				Family:    unix.AF_INET,
				Type:      unix.RTN_UNICAST,
				Protocol:  unix.RTPROT_DHCP,
				Scope:     netlink.SCOPE_UNIVERSE,
				LinkIndex: 3,
				Gw:        net.ParseIP("192.0.2.254"),
				Src:       net.ParseIP("192.0.2.1"),
			},
		},
		{
			name: "linkdown multipath nexthop metadata",
			route: func() netlink.Route {
				route := v96MainRoute(t, "198.51.100.0/24", unix.RTN_UNICAST, 0)
				route.MultiPath = []*netlink.NexthopInfo{{
					LinkIndex: 3,
					Flags:     unix.RTNH_F_LINKDOWN,
				}}
				return route
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := &ConfigSnapshot{Generation: 11, FIBGeneration: 7}
			stampPMechInventoryFromRoutes(snapshot, []netlink.Route{tc.route}, nil)
			if !snapshot.PMechInventory.Complete {
				t.Fatalf("preferred source invalidated a representable route: %+v", snapshot.PMechInventory)
			}
		})
	}
}

func TestPMechUnrelatedPreferredSourceKeepsTunnelAuthority9506(t *testing.T) {
	tunnelRoute := v96MainRoute(t, "10.0.0.0/24", unix.RTN_UNICAST, 10)
	unrelated := v96MainRoute(t, "192.0.2.0/24", unix.RTN_UNICAST, 3)
	unrelated.Protocol = unix.RTPROT_KERNEL
	unrelated.Scope = netlink.SCOPE_LINK
	unrelated.Src = net.ParseIP("192.0.2.1")
	snapshot := &ConfigSnapshot{
		Generation:    11,
		FIBGeneration: 7,
		Config: &config.Config{Security: config.SecurityConfig{IPsec: config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
			"vpn": {BindInterface: "st0", LocalID: "198.51.100.0/24", RemoteID: "10.0.0.0/24"},
		}}}},
		IpsecTunnelRows: []IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}},
	}
	stampPMechInventoryFromRoutes(snapshot, []netlink.Route{tunnelRoute, unrelated}, nil)
	if !snapshot.PMechInventory.Complete {
		t.Fatalf("unrelated preferred-source route poisoned authority: %+v", snapshot.PMechInventory)
	}
	row := snapshot.PMechInventory.TunnelRows[0]
	if !row.InventoryValid || row.InventoryReason != "" || !reflect.DeepEqual(row.EffectivePrefixes, []string{"10.0.0.0/24"}) {
		t.Fatalf("valid tunnel projection changed beside unrelated prefsrc: %+v", row)
	}
}

func rawPMechRouteMessage(srcLen uint8, source []byte) []byte {
	message := nl.NewRtMsg()
	message.Family = unix.AF_INET6
	message.Table = uint8(pmechMainTable)
	message.Dst_len = 64
	message.Src_len = srcLen
	raw := message.Serialize()
	if source != nil {
		raw = append(raw, nl.NewRtAttr(unix.RTA_SRC, source).Serialize()...)
	}
	return raw
}

func TestPMechTrueSourceSelectorRefusesAuthority9506(t *testing.T) {
	source := netip.MustParseAddr("2001:db8:20::").As16()
	control := rawPMechRouteMessage(0, nil)
	conditional := rawPMechRouteMessage(64, source[:])
	controlTable, controlSelector, err := pmechRawRouteSourceSelector(control)
	if err != nil || controlTable != pmechMainTable || controlSelector {
		t.Fatalf("unconditional raw RTM route = table %d selector %v error %v", controlTable, controlSelector, err)
	}
	conditionalTable, conditionalSelector, err := pmechRawRouteSourceSelector(conditional)
	if err != nil || conditionalTable != pmechMainTable || !conditionalSelector {
		t.Fatalf("conditional raw RTM route = table %d selector %v error %v", conditionalTable, conditionalSelector, err)
	}

	sourceAttributeOnly := rawPMechRouteMessage(0, source[:])
	_, attributeOnlySelector, err := pmechRawRouteSourceSelector(sourceAttributeOnly)
	if err != nil || !attributeOnlySelector {
		t.Fatalf("RTA_SRC without a prefix length was not detected: selector %v error %v",
			attributeOnlySelector, err)
	}

	_, destination, err := net.ParseCIDR("2001:db8:10::/64")
	if err != nil {
		t.Fatal(err)
	}
	projected := netlink.Route{
		Table: int(pmechMainTable), Family: unix.AF_INET6, Dst: destination,
		Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_STATIC, LinkIndex: 10,
	}
	controlRow, controlPrefix, controlHops, controlValid := snapshotPMechMainRoute(projected)
	conditionalRow, conditionalPrefix, conditionalHops, conditionalValid := snapshotPMechMainRoute(projected)
	if !reflect.DeepEqual(
		[]any{controlRow, controlPrefix, controlHops, controlValid},
		[]any{conditionalRow, conditionalPrefix, conditionalHops, conditionalValid},
	) {
		t.Fatal("lossy netlink.Route projection unexpectedly distinguishes raw source-selector state")
	}

	snapshot := func() *ConfigSnapshot {
		return &ConfigSnapshot{
			Generation: 7, FIBGeneration: 3,
			Config: &config.Config{Security: config.SecurityConfig{IPsec: config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
				"vpn": {BindInterface: "st0", LocalID: "2001:db8:30::/64", RemoteID: "2001:db8:10::/64"},
			}}}},
			IpsecTunnelRows: []IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}},
		}
	}
	unconditional := snapshot()
	stampPMechInventoryFromRoutesAndSelectors(unconditional, []netlink.Route{projected}, nil, controlSelector)
	if !unconditional.PMechInventory.Complete || !unconditional.PMechInventory.TunnelRows[0].InventoryValid {
		t.Fatalf("unconditional control route should be representable: %+v", unconditional.PMechInventory)
	}
	refused := snapshot()
	stampPMechInventoryFromRoutesAndSelectors(refused, []netlink.Route{projected}, nil, conditionalSelector)
	if refused.PMechInventory.Complete || refused.PMechInventory.TunnelRows[0].InventoryValid ||
		refused.PMechInventory.TunnelRows[0].InventoryReason != "MAIN_ROUTE_SOURCE_SELECTOR_UNREPRESENTABLE" {
		t.Fatalf("raw source-specific route must refuse authority: %+v", refused.PMechInventory)
	}
	setPMechRouteDump9506(t, []netlink.Route{projected}, nil)
	previousSource := pmechMainRouteSourceSelectorFn
	t.Cleanup(func() { pmechMainRouteSourceSelectorFn = previousSource })
	pmechMainRouteSourceSelectorFn = func() (bool, error) { return conditionalSelector, nil }
	integrated := snapshot()
	stampPMechInventory(integrated)
	if integrated.PMechInventory.Complete || integrated.PMechInventory.TunnelRows[0].InventoryValid {
		t.Fatalf("raw selector detection did not reach the production stamp: %+v", integrated.PMechInventory)
	}
}

func TestPMechEmptyTunnelInventorySkipsRouteDumps9506(t *testing.T) {
	calls := setPMechRouteDump9506(t, nil, nil)
	previousSource := pmechMainRouteSourceSelectorFn
	t.Cleanup(func() { pmechMainRouteSourceSelectorFn = previousSource })
	pmechMainRouteSourceSelectorFn = func() (bool, error) {
		*calls++
		return false, nil
	}
	snap := &ConfigSnapshot{Generation: 4, FIBGeneration: 2}
	stampPMechInventory(snap)
	if *calls != 0 || snap.PMechInventory == nil || snap.PMechInventory.Complete {
		t.Fatalf("zero-tunnel stamp called route dump or claimed authority: calls=%d inventory=%+v", *calls, snap.PMechInventory)
	}
}

// setPMechRouteDump9506 replaces the main-table stream for one test and
// returns the number of dumps taken.
func setPMechRouteDump9506(t testing.TB, routes []netlink.Route, err error) *int {
	t.Helper()
	previous := pmechMainRouteIterFn
	t.Cleanup(func() { pmechMainRouteIterFn = previous })
	calls := new(int)
	pmechMainRouteIterFn = func(visit func(netlink.Route) bool) error {
		*calls++
		for _, route := range routes {
			if !visit(route) {
				break
			}
		}
		return err
	}
	return calls
}
