package daemon

import (
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #14972: Linux drops RTA_FLOW on IPv6, so a single-path IPv6 mgmt static (and
// the IPv6 backup-router) stamped only RTPROT_STATIC+realm reads back with
// realm 0 and mgmtStaticRouteOwned never claims it. Deleting the static,
// changing its preference, or rolling back left the kernel route forwarding
// forever. The fix stamps every mgmt static with
// config.ManagementVRFMultipathStaticProtocol, which survives in both
// families. These cells simulate the kernel read-back form (IPv6 realm
// dropped to 0) and FAIL on master, where the desired routes carry
// RTPROT_STATIC and the seeded kernel routes are never reaped.

func v6MgmtRoute14972(t *testing.T, cidr string, priority int, protocol netlink.RouteProtocol, realm int, gw string) netlink.Route {
	return netlink.Route{
		Family:    netlink.FAMILY_V6,
		Dst:       mustRoute11449(t, cidr),
		Gw:        net.ParseIP(gw),
		LinkIndex: 7,
		Table:     mgmtVRFTableID,
		Type:      unix.RTN_UNICAST,
		Protocol:  protocol,
		Realm:     realm,
		Priority:  priority,
	}
}

// dropRealmV6 simulates the IPv6 read-back round-trip through the fake,
// which stores replaced routes verbatim: the real kernel stores no RTA_FLOW
// for IPv6, so a listed IPv6 single-path route always has realm 0.
func dropRealmV6(fake *mgmtStaticRouteFake11449) {
	for i := range fake.routes {
		if routeFamily11449(fake.routes[i]) == netlink.FAMILY_V6 {
			fake.routes[i].Realm = 0
		}
	}
}

func sortedDst14972(routes []netlink.Route) []string {
	var out []string
	for _, route := range routes {
		if route.Table != mgmtVRFTableID || route.Protocol == unix.RTPROT_KERNEL {
			continue
		}
		family := routeFamily11449(route)
		gw := ""
		if route.Gw != nil {
			gw = route.Gw.String()
		} else if len(route.MultiPath) > 0 {
			gw = route.MultiPath[0].Gw.String()
		}
		out = append(out, routeDst11449(route, family)+" via "+gw)
	}
	sort.Strings(out)
	return out
}

// Desired IPv6 single-path and backup-router routes must carry the protocol
// marker (the realm is dropped by the kernel for IPv6).
func TestMgmtV6SinglePathDesiredCarriesProtocolMarker14972(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set system backup-router 2001:db8:10::1",
		"set routing-options rib inet6.0 static route 2001:db8:70::/48 next-hop 2001:db8:10::1 interface fxp0",
	})
	fake := &mgmtStaticRouteFake11449{links: map[string]int{"fxp0": 7}}
	desired := mgmtStaticRoutesDesired(fake, store.ActiveConfig(), map[string]bool{"fxp0": true}, [2][]netlink.Route{})
	if len(desired) != 2 {
		t.Fatalf("desired = %+v, want backup-router + one static", desired)
	}
	for key, target := range desired {
		if target.route.Protocol != config.ManagementVRFMultipathStaticProtocol {
			t.Fatalf("desired %s protocol = %d, want xpf protocol %d (IPv6 drops the realm, so RTPROT_STATIC is unowned on read-back)",
				key, target.route.Protocol, config.ManagementVRFMultipathStaticProtocol)
		}
		if !mgmtStaticRouteOwned(target.route) {
			t.Fatalf("desired %s not owned: %+v", key, target.route)
		}
		// Even with the realm dropped, as IPv6 read-back does, it stays owned.
		readback := target.route
		readback.Realm = 0
		if !mgmtStaticRouteOwned(readback) {
			t.Fatalf("IPv6 read-back of %s (realm dropped) not owned: %+v", key, readback)
		}
	}
	backup, _, ok := mgmtBackupRouterRoute("2001:db8:10::1", "")
	if !ok || backup.Protocol != config.ManagementVRFMultipathStaticProtocol {
		t.Fatalf("backup-router = %+v ok=%v, want protocol %d", backup, ok, config.ManagementVRFMultipathStaticProtocol)
	}
}

// A removed IPv6 single-path static and a removed IPv6 backup-router, listed
// exactly as the kernel lists them (protocol as installed, realm 0), are
// reaped; an operator IPv6 route is never touched. RED on master: the
// desired set is empty but the seeded routes carry no claimable marker.
func TestMgmtV6SinglePathAndBackupReapedOnDelete14972(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
	})
	installed := netlink.RouteProtocol(config.ManagementVRFMultipathStaticProtocol)
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 7},
		routes: []netlink.Route{
			{Family: netlink.FAMILY_V6, Dst: mustRoute11449(t, "2001:db8:10::/64"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_KERNEL, Scope: netlink.SCOPE_UNIVERSE},
			v6MgmtRoute14972(t, "2001:db8:70::/48", 5, installed, 0, "2001:db8:10::1"),
			v6MgmtRoute14972(t, "::/0", 250, installed, 0, "2001:db8:10::1"),
			// Operator IPv6 route: never claimed.
			v6MgmtRoute14972(t, "2001:db8:99::/48", 5, unix.RTPROT_STATIC, 0, "2001:db8:10::9"),
		},
	}
	d := &Daemon{}
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store.ActiveConfig(), map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got, want := sortedDst14972(fake.routes), []string{"2001:db8:99::/48 via 2001:db8:10::9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("table 999 after delete = %v, want only operator %v (deleted=%+v)", got, want, fake.deleted)
	}
	if len(fake.deleted) != 2 {
		t.Fatalf("deleted = %+v, want the IPv6 static and the IPv6 backup-router", fake.deleted)
	}
}

// Preference change: the prio-5 IPv6 route is reaped and only prio 7 remains;
// an unchanged second reconcile does not churn (kernel read-back, realm 0,
// matches the desired key).
func TestMgmtV6SinglePathPreferenceChangeAndSteadyState14972(t *testing.T) {
	base := []string{"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64"}
	store5 := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set routing-options rib inet6.0 static route 2001:db8:70::/48 next-hop 2001:db8:10::1 interface fxp0",
	})
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 7},
		routes: []netlink.Route{
			{Family: netlink.FAMILY_V6, Dst: mustRoute11449(t, "2001:db8:10::/64"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_KERNEL, Scope: netlink.SCOPE_UNIVERSE},
		},
	}
	d := &Daemon{}
	mgmtSet := map[string]bool{"fxp0": true}
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store5.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("apply prio5: %v", err)
	}
	dropRealmV6(fake)
	if got, want := sortedDst14972(fake.routes), []string{"2001:db8:70::/48 via 2001:db8:10::1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after prio5 install = %v, want %v", got, want)
	}
	// Steady state: read-back (realm dropped) must match desired, no churn.
	replaced, deleted := len(fake.replaced), len(fake.deleted)
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store5.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("steady-state: %v", err)
	}
	if len(fake.replaced) != replaced || len(fake.deleted) != deleted {
		t.Fatalf("steady-state churned: replaced %d->%d deleted %d->%d", replaced, len(fake.replaced), deleted, len(fake.deleted))
	}
	// Preference 5 -> 7: old slot reaped, new slot present, nothing else.
	store7 := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set routing-options rib inet6.0 static route 2001:db8:70::/48 next-hop 2001:db8:10::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:70::/48 preference 7",
	})
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store7.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("apply prio7: %v", err)
	}
	dropRealmV6(fake)
	var prios []int
	for _, route := range fake.routes {
		if routeDst11449(route, netlink.FAMILY_V6) == "2001:db8:70::/48" {
			prios = append(prios, route.Priority)
		}
	}
	if !reflect.DeepEqual(prios, []int{7}) {
		t.Fatalf("priorities after preference change = %v, want [7] (routes=%+v deleted=%+v)", prios, fake.routes, fake.deleted)
	}
	// Rollback to prio 5 (and then deletion) also reaps.
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store5.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("rollback prio5: %v", err)
	}
	dropRealmV6(fake)
	empty := testStoreWithSetConfig(t, base)
	if err := d.applyMgmtVRFStaticRoutesTo(fake, empty.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := sortedDst14972(fake.routes); len(got) != 0 {
		t.Fatalf("after rollback+delete = %v, want empty (deleted=%+v)", got, fake.deleted)
	}
}

// Control: IPv4 single-path behavior is unchanged in shape — an operator
// IPv4 route survives, a legacy realm-marked IPv4 route is still reaped, and
// a newly installed IPv4 route is owned on read-back (realm present).
func TestMgmtV4SinglePathControlsUnchanged14972(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
	})
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 7},
		routes: []netlink.Route{
			{Family: netlink.FAMILY_V4, Dst: mustRoute11449(t, "192.0.2.0/24"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_KERNEL, Scope: netlink.SCOPE_LINK},
			// Legacy xpf IPv4 route (pre-#14972 stamp): RTPROT_STATIC+realm.
			{Family: netlink.FAMILY_V4, Dst: mustRoute11449(t, "10.9.0.0/16"), Gw: net.ParseIP("192.0.2.1"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_STATIC, Realm: mgmtStaticRouteRealm, Priority: 5},
			// Operator IPv4 route.
			{Family: netlink.FAMILY_V4, Dst: mustRoute11449(t, "192.0.2.128/25"), Gw: net.ParseIP("192.0.2.9"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_STATIC, Priority: 5},
		},
	}
	d := &Daemon{}
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store.ActiveConfig(), map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got, want := sortedDst14972(fake.routes), []string{"192.0.2.128/25 via 192.0.2.9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4 controls = %v, want only operator %v", got, want)
	}
	if len(fake.deleted) != 1 {
		t.Fatalf("deleted = %+v, want exactly the legacy realm route", fake.deleted)
	}
	if mgmtStaticRouteOwned(netlink.Route{Protocol: unix.RTPROT_STATIC}) {
		t.Fatal("operator RTPROT_STATIC route without realm claimed as owned")
	}
	if !mgmtStaticRouteOwned(netlink.Route{Protocol: config.ManagementVRFMultipathStaticProtocol}) {
		t.Fatal("protocol-marked route not owned")
	}
}
