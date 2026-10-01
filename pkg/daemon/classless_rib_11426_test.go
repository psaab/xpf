package daemon

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const mainRouteTable11426 = 254

type classlessRouteLister11426 struct {
	routes    map[[2]int][]netlink.Route
	listErr   map[int]error
	filterErr map[int]error
}

func (f *classlessRouteLister11426) RouteList(_ netlink.Link, family int) ([]netlink.Route, error) {
	if err := f.listErr[family]; err != nil {
		return nil, err
	}
	return f.routes[[2]int{family, mainRouteTable11426}], nil
}

func (f *classlessRouteLister11426) RouteListFiltered(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
	if err := f.filterErr[family]; err != nil {
		return nil, err
	}
	table := mainRouteTable11426
	if filter != nil && filter.Table != 0 {
		table = filter.Table
	}
	return f.routes[[2]int{family, table}], nil
}

func (*classlessRouteLister11426) RouteListFilteredIter(int, *netlink.Route, uint64, func(netlink.Route) bool) error {
	return nil
}

func (*classlessRouteLister11426) LinkByIndex(int) (netlink.Link, error) {
	return nil, errors.New("unused")
}

func (*classlessRouteLister11426) LinkByName(string) (netlink.Link, error) {
	return nil, errors.New("unused")
}

func route11426(t *testing.T, table int, destination string, protocol netlink.RouteProtocol) netlink.Route {
	t.Helper()
	_, dst, err := net.ParseCIDR(destination)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", destination, err)
	}
	return netlink.Route{Table: table, Dst: dst, Protocol: protocol}
}

func TestCollectFRRClasslessRIBRoutes11426(t *testing.T) {
	lister := &classlessRouteLister11426{
		routes: map[[2]int][]netlink.Route{
			{netlink.FAMILY_V4, mainRouteTable11426}: {
				route11426(t, mainRouteTable11426, "0.0.0.0/0", unix.RTPROT_BGP),
				route11426(t, mainRouteTable11426, "10.0.0.0/8", unix.RTPROT_BGP),
				route11426(t, mainRouteTable11426, "192.0.2.0/24", unix.RTPROT_STATIC),
				route11426(t, mainRouteTable11426, "10.5.0.0/16", netlink.RouteProtocol(196)), // FRR staticd DHCP classless route
				route11426(t, mainRouteTable11426, "198.51.100.0/24", unix.RTPROT_DHCP),
			},
			{netlink.FAMILY_V4, 100}: {
				route11426(t, 100, "203.0.113.0/24", unix.RTPROT_OSPF),
			},
		},
	}
	d := &Daemon{routing: routing.NewManagerWithRouteListerForTest(lister)}
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{Name: "tenant", TableID: 100}},
	}
	routes, failed := d.collectFRRClasslessRIBRoutes(cfg, []frr.DHCPRoute{{Destination: "10.5.0.0/16"}})
	if failed {
		t.Fatal("complete route-table inventory marked failed")
	}
	got := make(map[string]string, len(routes))
	for _, route := range routes {
		got[route.VRF+"|"+route.Destination] = route.Destination
	}
	for _, key := range []string{"|0.0.0.0/0", "|10.0.0.0/8", "tenant|203.0.113.0/24"} {
		if _, ok := got[key]; !ok {
			t.Errorf("live dynamic route %q missing from RIB coverage: %+v", key, routes)
		}
	}
	for _, key := range []string{"|192.0.2.0/24", "|198.51.100.0/24", "|10.5.0.0/16"} {
		if _, ok := got[key]; ok {
			t.Errorf("static/DHCP route %q must not be dynamic-RIB suppression evidence: %+v", key, routes)
		}
	}
}

func TestCollectFRRClasslessRIBInventoryFailure11426(t *testing.T) {
	lister := &classlessRouteLister11426{
		listErr: map[int]error{netlink.FAMILY_V4: errors.New("injected v4 route dump failure")},
	}
	d := &Daemon{routing: routing.NewManagerWithRouteListerForTest(lister)}
	routes, failed := d.collectFRRClasslessRIBRoutes(
		&config.Config{}, []frr.DHCPRoute{{Destination: "203.0.113.0/24"}},
	)
	if !failed {
		t.Fatalf("failed route-table read did not mark inventory incomplete: %+v", routes)
	}
	if len(routes) != 0 {
		t.Fatalf("failed v4 inventory unexpectedly yielded RIB coverage: %+v", routes)
	}
}

func TestCollectFRRClasslessRIBSkipsLookupWithoutClasslessRoutes11426(t *testing.T) {
	lister := &classlessRouteLister11426{
		listErr: map[int]error{netlink.FAMILY_V4: errors.New("unexpected route dump")},
	}
	d := &Daemon{routing: routing.NewManagerWithRouteListerForTest(lister)}
	routes, failed := d.collectFRRClasslessRIBRoutes(
		&config.Config{}, []frr.DHCPRoute{{Gateway: "192.0.2.1"}},
	)
	if failed || len(routes) != 0 {
		t.Fatalf("default-only DHCP state queried/failed the classless RIB inventory: routes=%+v failed=%v", routes, failed)
	}
}

func TestAssembleFRRConfigCarriesSameVRFDynamicRIB11426(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet dhcp",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/1.0",
	})
	cfg := store.ActiveConfig()
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("setup has %d routing instances, want one", len(cfg.RoutingInstances))
	}
	table := cfg.RoutingInstances[0].TableID
	lister := &classlessRouteLister11426{
		routes: map[[2]int][]netlink.Route{
			{netlink.FAMILY_V4, table}: {
				route11426(t, table, "10.0.0.0/8", unix.RTPROT_BGP),
			},
		},
	}
	dhcpManager := dhcp.NewManagerForTesting(nil)
	dhcpManager.SeedLeaseForTesting("ge-0-0-1", dhcp.AFInet, &dhcp.Lease{
		Interface: "ge-0-0-1",
		Family:    dhcp.AFInet,
		Address:   netip.MustParsePrefix("198.51.100.10/24"),
		ClasslessRoutes: []dhcp.LeaseRoute{{
			Destination: netip.MustParsePrefix("10.5.0.0/16"),
			Gateway:     netip.MustParseAddr("198.51.100.1"),
		}},
	})
	d := &Daemon{
		store:   store,
		dhcp:    dhcpManager,
		routing: routing.NewManagerWithRouteListerForTest(lister),
	}
	fc := d.assembleFRRConfig(cfg, nil)
	foundLease, foundRIB := false, false
	for _, route := range fc.DHCPRoutes {
		if route.Destination == "10.5.0.0/16" {
			foundLease = route.VRF == "tenant-a"
		}
	}
	for _, route := range fc.RIBRoutes {
		if route.Destination == "10.0.0.0/8" {
			foundRIB = route.VRF == "tenant-a"
		}
	}
	if !foundLease {
		t.Fatalf("assembler did not retain the tenant DHCP classless route: %+v", fc.DHCPRoutes)
	}
	if !foundRIB {
		t.Fatalf("assembler did not attach the same-VRF BGP RIB route: %+v", fc.RIBRoutes)
	}
	if fc.RIBRouteInventoryFailed {
		t.Fatal("complete assembler RIB inventory was marked failed")
	}
}

func TestCollectFRRClasslessRIBFailsClosedWithoutRoutingManager11426(t *testing.T) {
	routes, failed := (&Daemon{}).collectFRRClasslessRIBRoutes(
		&config.Config{}, []frr.DHCPRoute{{Destination: "203.0.113.0/24"}},
	)
	if !failed || len(routes) != 0 {
		t.Fatalf("missing route manager did not fail closed: routes=%+v failed=%v", routes, failed)
	}
}
