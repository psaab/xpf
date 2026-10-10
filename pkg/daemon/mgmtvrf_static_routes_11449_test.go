package daemon

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const mgmtStaticRouteRealm11449 = 0x585046

type mgmtStaticRouteFake11449 struct {
	routes   []netlink.Route
	links    map[string]int
	replaced []*netlink.Route
	deleted  []netlink.Route
}

func (f *mgmtStaticRouteFake11449) LinkByName(name string) (netlink.Link, error) {
	if index, ok := f.links[name]; ok {
		return fakeMgmtLink{idx: index}, nil
	}
	return nil, errors.New("link not found")
}

func routeFamily11449(route netlink.Route) int {
	if route.Family == netlink.FAMILY_V6 ||
		(route.Dst != nil && route.Dst.Mask != nil && route.Dst.IP.To4() == nil) ||
		(route.Gw != nil && route.Gw.To4() == nil) {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

func routeDst11449(route netlink.Route, family int) string {
	if route.Dst == nil {
		if family == netlink.FAMILY_V6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	}
	return route.Dst.String()
}

func (f *mgmtStaticRouteFake11449) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	var out []netlink.Route
	for _, route := range f.routes {
		if routeFamily11449(route) != family {
			continue
		}
		if filter != nil {
			if mask&netlink.RT_FILTER_TABLE != 0 && route.Table != filter.Table {
				continue
			}
			if mask&netlink.RT_FILTER_PROTOCOL != 0 && route.Protocol != filter.Protocol {
				continue
			}
		}
		out = append(out, route)
	}
	return out, nil
}

func (f *mgmtStaticRouteFake11449) RouteReplace(route *netlink.Route) error {
	cp := *route
	if cp.Type == 0 {
		cp.Type = unix.RTN_UNICAST // kernel returns the default route type explicitly
	}
	f.replaced = append(f.replaced, &cp)
	for i := range f.routes {
		old := f.routes[i]
		if old.Table == route.Table && old.Priority == route.Priority &&
			routeFamily11449(old) == routeFamily11449(*route) &&
			routeDst11449(old, routeFamily11449(old)) == routeDst11449(*route, routeFamily11449(*route)) {
			f.routes[i] = cp
			return nil
		}
	}
	f.routes = append(f.routes, cp)
	return nil
}

func (f *mgmtStaticRouteFake11449) RouteDel(route *netlink.Route) error {
	family := routeFamily11449(*route)
	dst := routeDst11449(*route, family)
	for i := len(f.routes) - 1; i >= 0; i-- {
		current := f.routes[i]
		if current.Table == route.Table && current.Protocol == route.Protocol &&
			current.Realm == route.Realm && current.Priority == route.Priority &&
			current.LinkIndex == route.LinkIndex && current.Gw.String() == route.Gw.String() &&
			routeFamily11449(current) == family && routeDst11449(current, family) == dst {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
		}
	}
	f.deleted = append(f.deleted, *route)
	return nil
}

func mustRoute11449(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, route, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return route
}

func TestMgmtStaticRoutesInstallInTable999WithoutDHCP11449(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set system backup-router 192.0.2.1",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1",
		"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 198.18.0.0/15 next-hop 203.0.113.1",
	})
	mainRoute := netlink.Route{
		Family:   netlink.FAMILY_V4,
		Dst:      mustRoute11449(t, "0.0.0.0/0"),
		Gw:       net.ParseIP("203.0.113.254"),
		Table:    unix.RT_TABLE_MAIN,
		Type:     unix.RTN_UNICAST,
		Protocol: unix.RTPROT_STATIC,
		Priority: 10,
	}
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 2},
		routes: []netlink.Route{
			mainRoute,
			{
				Family:    netlink.FAMILY_V4,
				Dst:       mustRoute11449(t, "192.0.2.0/24"),
				LinkIndex: 2,
				Table:     mgmtVRFTableID,
				Type:      unix.RTN_UNICAST,
				Protocol:  unix.RTPROT_KERNEL,
				Scope:     netlink.SCOPE_LINK,
			},
			{
				Family:   netlink.FAMILY_V4,
				Dst:      mustRoute11449(t, "192.0.2.128/25"),
				Gw:       net.ParseIP("192.0.2.9"),
				Table:    mgmtVRFTableID,
				Type:     unix.RTN_UNICAST,
				Protocol: unix.RTPROT_STATIC, // an operator route is not xpf-owned
			},
			{
				Family:   netlink.FAMILY_V4,
				Dst:      mustRoute11449(t, "192.0.2.200/32"),
				Gw:       net.ParseIP("192.0.2.3"),
				Table:    mgmtVRFTableID,
				Type:     unix.RTN_UNICAST,
				Protocol: unix.RTPROT_STATIC,
				Realm:    mgmtStaticRouteRealm11449, // stale xpf route from old config
			},
		},
	}
	d := &Daemon{store: store} // deliberately no DHCP client and no FRR
	mgmtSet := map[string]bool{"fxp0": true}
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo without DHCP: %v", err)
	}

	var backup, inferredStatic, explicitStatic, wrongScope bool
	var operatorStillPresent, staleStillPresent bool
	for _, route := range fake.routes {
		if route.Table != mgmtVRFTableID {
			continue
		}
		dst := routeDst11449(route, netlink.FAMILY_V4)
		if route.Protocol == unix.RTPROT_STATIC && route.Realm == mgmtStaticRouteRealm11449 {
			if dst == "0.0.0.0/0" && route.Gw.Equal(net.ParseIP("192.0.2.1")) &&
				route.Priority == 250 && route.Type == unix.RTN_UNICAST {
				backup = true
			}
			if dst == "198.51.100.0/24" && route.Gw.Equal(net.ParseIP("192.0.2.1")) &&
				route.Priority == 5 && route.Type == unix.RTN_UNICAST {
				inferredStatic = true
			}
			if dst == "203.0.113.0/24" && route.Gw.Equal(net.ParseIP("192.0.2.1")) &&
				route.LinkIndex == 2 && route.Type == unix.RTN_UNICAST {
				explicitStatic = true
			}
			if dst == "198.18.0.0/15" {
				wrongScope = true
			}
			if dst == "192.0.2.200/32" {
				staleStillPresent = true
			}
		}
		if dst == "192.0.2.128/25" && route.Protocol == unix.RTPROT_STATIC && route.Realm == 0 {
			operatorStillPresent = true
		}
	}
	if !backup || !inferredStatic || !explicitStatic {
		t.Fatalf("management static routes missing: backup=%v inferred=%v explicit=%v routes=%+v", backup, inferredStatic, explicitStatic, fake.routes)
	}
	if wrongScope {
		t.Fatal("data-scoped static route leaked into management table 999")
	}
	if !operatorStillPresent {
		t.Fatal("operator-owned RTPROT_STATIC route was deleted or claimed")
	}
	if staleStillPresent || len(fake.deleted) != 1 {
		t.Fatalf("stale xpf route not reconciled: stale=%v deleted=%+v", staleStillPresent, fake.deleted)
	}
	gotMain := fake.routes[0]
	if gotMain.Table != unix.RT_TABLE_MAIN || gotMain.Protocol != unix.RTPROT_STATIC ||
		gotMain.Priority != mainRoute.Priority || !gotMain.Gw.Equal(mainRoute.Gw) ||
		routeDst11449(gotMain, netlink.FAMILY_V4) != routeDst11449(mainRoute, netlink.FAMILY_V4) {
		t.Fatalf("data/main table changed: first route = %+v, want %+v", gotMain, mainRoute)
	}

	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(fake.replaced) != 3 {
		t.Fatalf("second reconcile churned routes: RouteReplace count=%d, want 3 total", len(fake.replaced))
	}
}

func TestBackupRouterIPv6DefaultUsesTable99911449(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set system backup-router 2001:db8:10::1",
	})
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 7},
		routes: []netlink.Route{{
			Family:    netlink.FAMILY_V6,
			Dst:       mustRoute11449(t, "2001:db8:10::/64"),
			LinkIndex: 7,
			Table:     mgmtVRFTableID,
			Type:      unix.RTN_UNICAST,
			Protocol:  unix.RTPROT_KERNEL,
			Scope:     netlink.SCOPE_LINK,
		}},
	}
	d := &Daemon{store: store}
	if err := d.applyMgmtVRFRoutesTo(fake, nil, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo without DHCP: %v", err)
	}
	for _, route := range fake.routes {
		if route.Table == mgmtVRFTableID && route.Protocol == unix.RTPROT_STATIC &&
			route.Realm == mgmtStaticRouteRealm11449 && route.Gw.Equal(net.ParseIP("2001:db8:10::1")) {
			if route.Dst == nil || routeDst11449(route, netlink.FAMILY_V6) != "::/0" ||
				route.Priority != 250 || route.Type != unix.RTN_UNICAST {
				t.Fatalf("IPv6 backup-router = %+v, want table-999 ::/0 metric 250 unicast", route)
			}
			return
		}
	}
	t.Fatalf("IPv6 backup-router default missing from table 999: %+v", fake.routes)
}
func TestMgmtV6StaticRouteFoldDeduplicatesNextHops_12084(t *testing.T) {
	cases := []struct {
		name        string
		destination string
		sets        []string
		wantHops    []string
	}{
		{
			name:        "same-single-member-from-bare-and-rib",
			destination: "::/0",
			sets: []string{
				"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
				"set routing-options static route ::/0 next-hop 2001:db8:10::1 interface fxp0",
				"set routing-options rib inet6.0 static route ::/0 next-hop 2001:db8:10::1 interface fxp0",
			},
			wantHops: []string{"2001:db8:10::1"},
		},
		{
			name:        "repeated-member-in-folded-multipath",
			destination: "2001:db8:20::/48",
			sets: []string{
				"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
				"set routing-options static route 2001:db8:20::/48 next-hop 2001:db8:10::1 interface fxp0",
				"set routing-options rib inet6.0 static route 2001:db8:20::/48 next-hop 2001:db8:10::1 interface fxp0",
				"set routing-options rib inet6.0 static route 2001:db8:20::/48 next-hop 2001:db8:10::3 interface fxp0",
			},
			wantHops: []string{"2001:db8:10::1", "2001:db8:10::3"},
		},
		{
			name:        "repeated-member-in-one-route-block",
			destination: "2001:db8:30::/48",
			sets: []string{
				"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
				"set routing-options static route 2001:db8:30::/48 next-hop 2001:db8:10::1 interface fxp0",
				"set routing-options static route 2001:db8:30::/48 next-hop 2001:db8:10::1 interface fxp0",
			},
			wantHops: []string{"2001:db8:10::1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := testStoreWithSetConfig(t, tc.sets)
			fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7}}
			desired := mgmtStaticRoutesDesired(fake, store.ActiveConfig(),
				map[string]bool{"fxp0": true}, [2][]netlink.Route{})
			if len(desired) != 1 {
				t.Fatalf("desired management routes = %+v, want one route", desired)
			}
			var route netlink.Route
			for _, target := range desired {
				route = target.route
			}
			if got := routeDst11449(route, netlink.FAMILY_V6); got != tc.destination {
				t.Fatalf("management destination = %s, want %s", got, tc.destination)
			}
			var gotHops []string
			if len(route.MultiPath) == 0 {
				if route.Gw != nil {
					gotHops = append(gotHops, route.Gw.String())
				}
			} else {
				for _, nextHop := range route.MultiPath {
					if nextHop.Gw != nil {
						gotHops = append(gotHops, nextHop.Gw.String())
					}
				}
			}
			if !reflect.DeepEqual(gotHops, tc.wantHops) {
				t.Fatalf("management route next-hops = %v, want deduped %v (route %+v)",
					gotHops, tc.wantHops, route)
			}
		})
	}
}
