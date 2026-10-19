package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// FAIL-ON-REVERT (#12539, #14972): the kernel accepts a top-level RTA_FLOW on a
// multipath route only when it equals the first leg's per-nexthop RTA_FLOW,
// and vishvananda/netlink cannot emit a per-leg RTA_FLOW, so a realm-stamped
// ECMP mgmt static fails with EINVAL. Every mgmt static is therefore owned
// through config.ManagementVRFMultipathStaticProtocol; a single-path route
// additionally carries the realm (which IPv6 never stores, #14972).
func TestMgmtStaticRoutesDesiredECMPOwnershipMarker12539(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.3 interface fxp0",
		"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1 interface fxp0",
	})
	fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7}}
	mgmtSet := map[string]bool{"fxp0": true}
	desired := mgmtStaticRoutesDesired(fake, store.ActiveConfig(), mgmtSet, [2][]netlink.Route{})

	byDst := map[string]netlink.Route{}
	for _, target := range desired {
		route := target.route
		if route.Dst != nil {
			byDst[route.Dst.String()] = route
		}
	}
	ecmp, ok := byDst["198.51.100.0/24"]
	if !ok {
		t.Fatal("ECMP static 198.51.100.0/24 missing from desired set")
	}
	if len(ecmp.MultiPath) != 2 {
		t.Fatalf("ECMP route has %d legs, want 2", len(ecmp.MultiPath))
	}
	if ecmp.Realm != 0 {
		t.Fatalf("ECMP route carries realm %#x; the kernel rejects a top-level RTA_FLOW that no leg carries", ecmp.Realm)
	}
	if ecmp.Protocol != config.ManagementVRFMultipathStaticProtocol {
		t.Fatalf("ECMP route protocol = %d, want the xpf multipath ownership protocol %d",
			ecmp.Protocol, config.ManagementVRFMultipathStaticProtocol)
	}
	if !mgmtStaticRouteOwned(ecmp) {
		t.Fatalf("ECMP route %+v is not recognized as xpf-owned", ecmp)
	}
	if ecmp.Gw != nil || ecmp.LinkIndex != 0 {
		t.Fatalf("ECMP route has single-path fields set: gw=%v ifindex=%d", ecmp.Gw, ecmp.LinkIndex)
	}
	legs := map[string]bool{}
	for _, hop := range ecmp.MultiPath {
		legs[hop.Gw.String()] = true
	}
	if !legs["192.0.2.1"] || !legs["192.0.2.3"] {
		t.Fatalf("ECMP legs = %v, want .1 and .3", legs)
	}
	single, ok := byDst["203.0.113.0/24"]
	if !ok {
		t.Fatal("single-path static 203.0.113.0/24 missing from desired set")
	}
	if len(single.MultiPath) != 0 {
		t.Fatalf("single-path route unexpectedly multipath: %+v", single.MultiPath)
	}
	if single.Protocol != config.ManagementVRFMultipathStaticProtocol || single.Realm != mgmtStaticRouteRealm {
		t.Fatalf("single-path route protocol/realm = %d/%#x, want %d/%#x",
			single.Protocol, single.Realm, config.ManagementVRFMultipathStaticProtocol, mgmtStaticRouteRealm)
	}
	if single.Gw == nil || !single.Gw.Equal(net.ParseIP("192.0.2.1")) || single.LinkIndex != 7 {
		t.Fatalf("single-path route = gw %v ifindex %d, want .1/7", single.Gw, single.LinkIndex)
	}
}

func ecmpRoute12539(t *testing.T, cidr string, priority int, protocol netlink.RouteProtocol, gateways ...string) netlink.Route {
	t.Helper()
	route := netlink.Route{
		Family:   netlink.FAMILY_V4,
		Dst:      mustRoute11449(t, cidr),
		Table:    mgmtVRFTableID,
		Type:     unix.RTN_UNICAST,
		Protocol: protocol,
		Priority: priority,
	}
	for _, gateway := range gateways {
		route.MultiPath = append(route.MultiPath, &netlink.NexthopInfo{LinkIndex: 7, Gw: net.ParseIP(gateway)})
	}
	return route
}

// renderMgmtStatics12539 renders the non-kernel table-999 routes in a stable,
// order-independent form: destination, priority, protocol, realm, gateways.
func renderMgmtStatics12539(routes []netlink.Route) []string {
	var out []string
	for _, route := range routes {
		if route.Table != mgmtVRFTableID || route.Protocol == unix.RTPROT_KERNEL {
			continue
		}
		family := netlink.FAMILY_V4
		if (route.Dst != nil && route.Dst.IP.To4() == nil) || (route.Gw != nil && route.Gw.To4() == nil) ||
			route.Family == netlink.FAMILY_V6 {
			family = netlink.FAMILY_V6
		}
		var gateways []string
		if route.Gw != nil {
			gateways = append(gateways, route.Gw.String())
		}
		for _, hop := range route.MultiPath {
			gateways = append(gateways, hop.Gw.String())
		}
		sort.Strings(gateways)
		out = append(out, fmt.Sprintf("%s prio=%d proto=%d realm=%#x via=%s",
			mgmtRouteDstKey(route.Dst, family), route.Priority, route.Protocol, route.Realm,
			strings.Join(gateways, ",")))
	}
	sort.Strings(out)
	return out
}

// F1/F4 of #12539 against the fake: an xpf ECMP static is reaped when its
// preference (kernel priority) or destination changes or it is removed, a
// same-slot leg change never issues a delete that would hit its own
// replacement, and an operator ECMP route in table 999 is never claimed.
func TestMgmtStaticECMPReconcileReapsStaleRoutes12539(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.3 interface fxp0",
		"set routing-options static route 198.51.100.0/24 preference 7",
		"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.3 interface fxp0",
	})
	owned := netlink.RouteProtocol(config.ManagementVRFMultipathStaticProtocol)
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 7},
		routes: []netlink.Route{
			// Installed before the preference moved from 5 to 7.
			ecmpRoute12539(t, "198.51.100.0/24", 5, owned, "192.0.2.1", "192.0.2.3"),
			// Installed for a destination the config no longer has.
			ecmpRoute12539(t, "198.51.0.0/16", 5, owned, "192.0.2.1", "192.0.2.3"),
			// Installed before leg .4 was removed: same slot as the new route,
			// and its legs extend the new legs, so a stale delete would match
			// the replacement.
			ecmpRoute12539(t, "203.0.113.0/24", 5, owned, "192.0.2.1", "192.0.2.3", "192.0.2.4"),
			// Operator ECMP route: RTPROT_STATIC, realm 0.
			ecmpRoute12539(t, "192.0.2.128/25", 5, unix.RTPROT_STATIC, "192.0.2.1", "192.0.2.3"),
			// Single-path xpf route from an older config.
			{
				Family:    netlink.FAMILY_V4,
				Dst:       mustRoute11449(t, "10.9.0.0/16"),
				Gw:        net.ParseIP("192.0.2.1"),
				LinkIndex: 7,
				Table:     mgmtVRFTableID,
				Type:      unix.RTN_UNICAST,
				Protocol:  unix.RTPROT_STATIC,
				Realm:     mgmtStaticRouteRealm,
				Priority:  5,
			},
		},
	}
	d := &Daemon{}
	mgmtSet := map[string]bool{"fxp0": true}
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFStaticRoutesTo: %v", err)
	}
	want := []string{
		"192.0.2.128/25 prio=5 proto=4 realm=0x0 via=192.0.2.1,192.0.2.3",
		"198.51.100.0/24 prio=7 proto=88 realm=0x0 via=192.0.2.1,192.0.2.3",
		"203.0.113.0/24 prio=5 proto=88 realm=0x0 via=192.0.2.1,192.0.2.3",
	}
	if got := renderMgmtStatics12539(fake.routes); !reflect.DeepEqual(got, want) {
		t.Fatalf("table 999 after reconcile =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	for _, route := range fake.deleted {
		if mgmtRouteDstKey(route.Dst, netlink.FAMILY_V4) == "203.0.113.0/24" {
			t.Fatalf("stale delete issued for the replaced 203.0.113.0/24 slot: %+v", route)
		}
	}

	replaced, deleted := len(fake.replaced), len(fake.deleted)
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if len(fake.replaced) != replaced || len(fake.deleted) != deleted {
		t.Fatalf("steady-state reconcile churned: replaced %d->%d deleted %d->%d",
			replaced, len(fake.replaced), deleted, len(fake.deleted))
	}
}

// An xpf ECMP management static default is DHCP-precedence authority exactly
// like its single-path RTPROT_STATIC form (#9943): it must suppress the learned
// DHCP default instead of being ignored as an unknown-protocol route.
func TestMgmtVRFECMPStaticDefaultSuppressesDHCPDefault12539(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1 interface fxp0",
		"set routing-options static route 0.0.0.0/0 next-hop 192.0.2.3 interface fxp0",
	})
	fake := &fakeMgmtProgrammer{linkIdx: 7}
	lease := &dhcp.Lease{
		Interface: "fxp0",
		Family:    dhcp.AFInet,
		Gateway:   netip.MustParseAddr("192.0.2.254"),
	}
	d := &Daemon{store: store}
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	var staticDefault bool
	for _, route := range fake.replaced {
		if route.Protocol == unix.RTPROT_DHCP {
			t.Fatalf("DHCP route installed despite the ECMP static default: %+v", route)
		}
		if route.Protocol == config.ManagementVRFMultipathStaticProtocol &&
			mgmtRouteDstKey(route.Dst, netlink.FAMILY_V4) == "0.0.0.0/0" && len(route.MultiPath) == 2 {
			staticDefault = true
		}
	}
	if !staticDefault {
		t.Fatalf("ECMP static default was not installed: %+v", fake.replaced)
	}
}
