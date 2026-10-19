package daemon

import (
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #15163 (B21-01): the IPv6 single-path form of the #14972 mechanism. Linux
// stores no RTA_FLOW for IPv6, so an IPv6 single-path static and the IPv6
// system backup-router stamped only RTPROT_STATIC+realm read back with
// realm 0 and mgmtStaticRouteOwned never claims them: deleting the config
// entry, changing its preference, or removing the backup-router leaves the
// kernel route in table 999 forever. The fix must stamp both IPv6
// single-path routes with config.ManagementVRFMultipathStaticProtocol
// (0x58), which survives in both families. These cells simulate the kernel
// read-back (IPv6 realm dropped to 0) and FAIL on pre-fix master, where the
// desired IPv6 routes carry RTPROT_STATIC and the seeded routes (stamped
// exactly as the old build stamps them) are never reaped.

// dropRealmV6 simulates the IPv6 read-back round-trip through the fake,
// which stores replaced routes verbatim: the real kernel stores no RTA_FLOW
// for IPv6, so a listed IPv6 single-path route always has realm 0.
func dropRealmV6_15163(fake *mgmtStaticRouteFake11449) {
	for i := range fake.routes {
		if routeFamily11449(fake.routes[i]) == netlink.FAMILY_V6 {
			fake.routes[i].Realm = 0
		}
	}
}

func sortedMgmtDst15163(routes []netlink.Route) []string {
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
	return out
}

// Desired IPv6 single-path static and backup-router routes must carry the
// protocol marker: the realm is dropped by the kernel for IPv6, so
// RTPROT_STATIC would read back unowned. RED on pre-fix master: both
// desired routes (and mgmtBackupRouterRoute directly) carry protocol 4.
func TestMgmtV6SinglePathDesiredCarriesProtocolMarker15163(t *testing.T) {
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
		if int(target.route.Protocol) != 88 {
			t.Fatalf("desired %s protocol = %d, want xpf protocol 88 (IPv6 drops the realm, so RTPROT_STATIC is unowned on read-back)", key, target.route.Protocol)
		}
		if !mgmtStaticRouteOwned(target.route) {
			t.Fatalf("desired %s not owned: %+v", key, target.route)
		}
		readback := target.route
		readback.Realm = 0
		if !mgmtStaticRouteOwned(readback) {
			t.Fatalf("IPv6 read-back of %s (realm dropped) not owned: %+v", key, readback)
		}
	}
	backup, _, ok := mgmtBackupRouterRoute("2001:db8:10::1", "")
	if !ok || int(backup.Protocol) != 88 {
		t.Fatalf("backup-router = %+v ok=%v, want protocol 88", backup, ok)
	}
}

// A removed IPv6 single-path static and a removed IPv6 backup-router, listed
// exactly as the kernel lists them (protocol as installed, realm 0), are
// reaped; an operator IPv6 route is never touched. The seeded xpf routes are
// stamped 0x58 exactly as the fixed build installs them. RED on pre-fix
// master: nothing seeds or claims them there, but the desired set is empty
// while the seeded routes carry no claimable marker there only in the sense
// that the pre-fix build never installs 0x58 single-path routes; see the
// legacy-stamp variant below for the exact pre-fix read-back form.
func TestMgmtV6SinglePathAndBackupReapedOnDelete15163(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
	})
	mk := func(cidr string, priority int, protocol netlink.RouteProtocol, gw string) netlink.Route {
		return netlink.Route{
			Family:    netlink.FAMILY_V6,
			Dst:       mustRoute11449(t, cidr),
			Gw:        net.ParseIP(gw),
			LinkIndex: 7,
			Table:     mgmtVRFTableID,
			Type:      unix.RTN_UNICAST,
			Protocol:  protocol,
			Realm:     0, // IPv6 read-back: realm always dropped
			Priority:  priority,
		}
	}
	installed := netlink.RouteProtocol(88)
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 7},
		routes: []netlink.Route{
			{Family: netlink.FAMILY_V6, Dst: mustRoute11449(t, "2001:db8:10::/64"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_KERNEL, Scope: netlink.SCOPE_UNIVERSE},
			mk("2001:db8:70::/48", 5, installed, "2001:db8:10::1"),
			mk("::/0", 250, installed, "2001:db8:10::1"),
			// Operator IPv6 route: never claimed, never deleted.
			mk("2001:db8:99::/48", 5, unix.RTPROT_STATIC, "2001:db8:10::9"),
		},
	}
	d := &Daemon{}
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store.ActiveConfig(), map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got, want := sortedMgmtDst15163(fake.routes), []string{"2001:db8:99::/48 via 2001:db8:10::9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("table 999 after delete = %v, want only operator %v (deleted=%+v)", got, want, fake.deleted)
	}
	if len(fake.deleted) != 2 {
		t.Fatalf("deleted = %+v, want the IPv6 static and the IPv6 backup-router", fake.deleted)
	}
}

// The exact pre-fix read-back form: an IPv6 single-path static stamped
// RTPROT_STATIC+realm by an older build reads back RTPROT_STATIC realm 0.
// It stays indistinguishable from an operator route and must NOT be deleted
// (fail-closed bound documented in #15163): claiming every realm-0
// RTPROT_STATIC IPv6 route would delete operator routes in shared table
// 999. This control passes on both master and the fix and pins the bound.
func TestMgmtV6LegacyUnmarkedStaticNotClaimed15163(t *testing.T) {
	if mgmtStaticRouteOwned(netlink.Route{Family: netlink.FAMILY_V6, Protocol: unix.RTPROT_STATIC, Realm: 0}) {
		t.Fatal("realm-0 RTPROT_STATIC IPv6 route claimed as xpf-owned; operator routes would be reaped")
	}
	if !mgmtStaticRouteOwned(netlink.Route{Family: netlink.FAMILY_V6, Protocol: netlink.RouteProtocol(88), Realm: 0}) {
		t.Fatal("0x58-protocol IPv6 route without realm not owned")
	}
	if mgmtStaticRouteOwned(netlink.Route{Family: netlink.FAMILY_V6, Protocol: unix.RTPROT_STATIC, Realm: mgmtStaticRouteRealm}) {
		// IPv4 legacy form keeps the realm; the IPv6 kernel never returns it,
		// so this arm is unreachable for a real IPv6 listing. Only the
		// protocol arm may claim an IPv6 route.
		t.Log("note: RTPROT_STATIC+realm arm exercised only by IPv4 listings")
	}
}

// Preference change on an IPv6 single-path static: the prio-5 route is
// reaped and only prio 7 remains; an unchanged second reconcile does not
// churn (kernel read-back, realm 0, matches the desired key); rollback to
// prio 5 and then full deletion also reap. RED on pre-fix master: the
// prio-5 route survives the 5->7 change (deleted=[]).
func TestMgmtV6SinglePathPreferenceChangeAndSteadyState15163(t *testing.T) {
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
	dropRealmV6_15163(fake)
	if got, want := sortedMgmtDst15163(fake.routes), []string{"2001:db8:70::/48 via 2001:db8:10::1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after prio5 install = %v, want %v", got, want)
	}
	replaced, deleted := len(fake.replaced), len(fake.deleted)
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store5.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("steady-state: %v", err)
	}
	if len(fake.replaced) != replaced || len(fake.deleted) != deleted {
		t.Fatalf("steady-state churned: replaced %d->%d deleted %d->%d", replaced, len(fake.replaced), deleted, len(fake.deleted))
	}
	store7 := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet6 address 2001:db8:10::2/64",
		"set routing-options rib inet6.0 static route 2001:db8:70::/48 next-hop 2001:db8:10::1 interface fxp0",
		"set routing-options rib inet6.0 static route 2001:db8:70::/48 preference 7",
	})
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store7.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("apply prio7: %v", err)
	}
	dropRealmV6_15163(fake)
	var prios []int
	for _, route := range fake.routes {
		if routeDst11449(route, netlink.FAMILY_V6) == "2001:db8:70::/48" {
			prios = append(prios, route.Priority)
		}
	}
	if !reflect.DeepEqual(prios, []int{7}) {
		t.Fatalf("priorities after preference change = %v, want [7] (routes=%+v deleted=%+v)", prios, fake.routes, fake.deleted)
	}
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store5.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("rollback prio5: %v", err)
	}
	dropRealmV6_15163(fake)
	empty := testStoreWithSetConfig(t, base)
	if err := d.applyMgmtVRFStaticRoutesTo(fake, empty.ActiveConfig(), mgmtSet); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := sortedMgmtDst15163(fake.routes); len(got) != 0 {
		t.Fatalf("after rollback+delete = %v, want empty (deleted=%+v)", got, fake.deleted)
	}
}

// Control: IPv4 single-path behavior is unchanged in shape — an operator
// IPv4 route survives, a legacy realm-marked IPv4 route is still reaped, and
// the IPv4 read-back keeps its realm (IPv4 does store RTA_FLOW).
func TestMgmtV4SinglePathControlsUnchanged15163(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
	})
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 7},
		routes: []netlink.Route{
			{Family: netlink.FAMILY_V4, Dst: mustRoute11449(t, "192.0.2.0/24"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_KERNEL, Scope: netlink.SCOPE_LINK},
			{Family: netlink.FAMILY_V4, Dst: mustRoute11449(t, "10.9.0.0/16"), Gw: net.ParseIP("192.0.2.1"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_STATIC, Realm: mgmtStaticRouteRealm, Priority: 5},
			{Family: netlink.FAMILY_V4, Dst: mustRoute11449(t, "192.0.2.128/25"), Gw: net.ParseIP("192.0.2.9"), LinkIndex: 7, Table: mgmtVRFTableID, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_STATIC, Priority: 5},
		},
	}
	d := &Daemon{}
	if err := d.applyMgmtVRFStaticRoutesTo(fake, store.ActiveConfig(), map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got, want := sortedMgmtDst15163(fake.routes), []string{"192.0.2.128/25 via 192.0.2.9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4 controls = %v, want only operator %v", got, want)
	}
	if len(fake.deleted) != 1 {
		t.Fatalf("deleted = %+v, want exactly the legacy realm route", fake.deleted)
	}
}
