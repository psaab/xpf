package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestAssembleFRRConfigKeepsManagementStaticsOutOfDataTable11449(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/24",
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8:20::2/64",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1",
		"set routing-options static route 198.51.101.0/24 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 203.0.114.0/24 next-hop 203.0.113.1",
		"set routing-options rib inet6.0 static route 2001:db8:100::/64 next-hop 2001:db8:10::1",
		"set routing-options rib inet6.0 static route 2001:db8:101::/64 next-hop 2001:db8:10::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:200::/64 next-hop 2001:db8:20::1",
	})
	fc := (&Daemon{}).assembleFRRConfig(store.ActiveConfig(), nil)
	if len(fc.StaticRoutes) != 1 || fc.StaticRoutes[0].Destination != "203.0.114.0/24" {
		t.Fatalf("FRR global static routes = %+v, want only the data-scoped route", fc.StaticRoutes)
	}
	if len(fc.Inet6StaticRoutes) != 1 || fc.Inet6StaticRoutes[0].Destination != "2001:db8:200::/64" {
		t.Fatalf("FRR global IPv6 static routes = %+v, want only the data-scoped route", fc.Inet6StaticRoutes)
	}
}

func TestFRRExcludesStaticResolvedByLiveMgmtConnectedRoute11449(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet dhcp",
		"set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/24",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1",
		"set routing-options static route 203.0.114.0/24 next-hop 203.0.113.1",
	})
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 2},
		routes: []netlink.Route{{
			Family:    netlink.FAMILY_V4,
			Dst:       mustRoute11449(t, "192.0.2.0/24"),
			LinkIndex: 2,
			Table:     mgmtVRFTableID,
			Type:      unix.RTN_UNICAST,
			Protocol:  unix.RTPROT_KERNEL,
			Scope:     netlink.SCOPE_LINK,
		}},
	}
	d := &Daemon{store: store}
	mgmtSet := map[string]bool{"fxp0": true}
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	var reconciled bool
	for _, route := range fake.routes {
		if route.Table == mgmtVRFTableID && route.Protocol == unix.RTPROT_STATIC &&
			route.Gw.Equal(net.ParseIP("192.0.2.1")) &&
			routeDst11449(route, netlink.FAMILY_V4) == "198.51.100.0/24" {
			reconciled = true
			break
		}
	}
	if !reconciled {
		t.Fatalf("live-connected management static was not reconciled into table 999: %+v", fake.routes)
	}

	current := [2][]netlink.Route{}
	routes, err := fake.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: mgmtVRFTableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("table-999 route snapshot: %v", err)
	}
	current[0] = routes
	if _, ok := mgmtStaticConnectedLinkIndex(net.ParseIP("192.0.2.1"), current[0]); !ok {
		t.Fatalf("reconciler's live connected route was not visible in FRR inventory: %+v", current[0])
	}
	mgmtSet = managementVRFIfaceSet(store.ActiveConfig())
	staticRoutes, _ := mgmtStaticRoutesForFRR(store.ActiveConfig(), mgmtSet, nil, current)
	if len(staticRoutes) != 1 || staticRoutes[0].Destination != "203.0.114.0/24" {
		t.Fatalf("management FRR exclusion = %+v, want only data route", staticRoutes)
	}
	fc := d.assembleFRRConfigWithMgmtRouteInventory(store.ActiveConfig(), nil, current)
	if len(fc.StaticRoutes) != 1 || fc.StaticRoutes[0].Destination != "203.0.114.0/24" {
		t.Fatalf("FRR static routes = %+v, want reconciled mgmt route excluded and data route retained",
			fc.StaticRoutes)
	}
}
