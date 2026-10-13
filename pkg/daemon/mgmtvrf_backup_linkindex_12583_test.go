package daemon

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #12583: the kernel lists a gateway route with the output link it chose.
// mgmtBackupRouterRoute leaves LinkIndex 0, so the desired backup-router key
// (...|0|...) never matched the listed key (...|9|...) and every management
// reconcile replaced the installed route again. The #11449 fake stores the
// requested route verbatim; seedKernelReadback12583 writes the kernel's choice
// into it.
//
// The backup-router now takes its gateway's management link like an
// interface-less static next-hop. An unresolved gateway keeps LinkIndex 0 and
// is replaced, so re-checked by the kernel, on every reconcile.

// backupRouterLink12583 returns the LinkIndex of the listed IPv4 backup-router
// route, and whether it is listed.
func backupRouterLink12583(fake *mgmtStaticRouteFake11449) (int, bool) {
	for _, route := range fake.routes {
		if route.Table == mgmtVRFTableID && route.Priority == 250 &&
			route.Protocol == unix.RTPROT_STATIC && route.Realm == mgmtStaticRouteRealm11449 &&
			route.Gw.Equal(net.ParseIP("192.0.2.1")) &&
			routeDst11449(route, netlink.FAMILY_V4) == "0.0.0.0/0" {
			return route.LinkIndex, true
		}
	}
	return 0, false
}

func seedKernelReadback12583(fake *mgmtStaticRouteFake11449, linkIndex int) {
	for i := range fake.routes {
		if fake.routes[i].Priority == 250 {
			fake.routes[i].LinkIndex = linkIndex
		}
	}
}

// moveConnected12583 moves the kernel's table-999 connected routes to
// linkIndex.
func moveConnected12583(fake *mgmtStaticRouteFake11449, linkIndex int) {
	for i := range fake.routes {
		if fake.routes[i].Protocol == unix.RTPROT_KERNEL {
			fake.routes[i].LinkIndex = linkIndex
		}
	}
}

func backupSetup12583(t *testing.T) (*Daemon, *mgmtStaticRouteFake11449, map[string]bool) {
	t.Helper()
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set system backup-router 192.0.2.1",
	})
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 9},
		routes: []netlink.Route{{
			Family:    netlink.FAMILY_V4,
			Dst:       mustRoute11449(t, "192.0.2.0/24"),
			LinkIndex: 9,
			Table:     mgmtVRFTableID,
			Type:      unix.RTN_UNICAST,
			Protocol:  unix.RTPROT_KERNEL,
			Scope:     netlink.SCOPE_LINK,
		}},
	}
	return &Daemon{store: store}, fake, map[string]bool{"fxp0": true}
}

// Two applies starting empty must leave the backup-router route present after
// both, with no redundant replace on apply 2 or apply 3.
func TestBackupRouterReconcileStableWithKernelLinkIndex12583(t *testing.T) {
	d, fake, mgmtSet := backupSetup12583(t)

	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	if _, ok := backupRouterLink12583(fake); !ok {
		t.Fatalf("after apply 1: backup-router route absent: %+v", fake.routes)
	}
	seedKernelReadback12583(fake, 9)

	replacedBefore := len(fake.replaced)
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if _, ok := backupRouterLink12583(fake); !ok {
		t.Fatalf("after apply 2: backup-router route absent: routes=%+v deleted=%+v", fake.routes, fake.deleted)
	}
	if len(fake.deleted) != 0 {
		t.Fatalf("apply 2 deleted routes, want none: %+v", fake.deleted)
	}
	if len(fake.replaced) != replacedBefore {
		t.Fatalf("apply 2 churned routes: RouteReplace count %d -> %d", replacedBefore, len(fake.replaced))
	}

	seedKernelReadback12583(fake, 9)
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 3: %v", err)
	}
	if _, ok := backupRouterLink12583(fake); !ok || len(fake.deleted) != 0 || len(fake.replaced) != replacedBefore {
		t.Fatalf("apply 3 churned: present=%v deleted=%+v replaced=%d want %d routes=%+v", ok, fake.deleted, len(fake.replaced), replacedBefore, fake.routes)
	}
}

// A backup-router listed on another link than its gateway's management link
// (ifindex 42 is not fxp0, e.g. a link the kernel chose before fxp0 was
// connected) is not the desired route: the reconcile moves it to fxp0 in place
// and deletes nothing.
func TestBackupRouterForeignKernelLinkIndexRepinned12583(t *testing.T) {
	d, fake, mgmtSet := backupSetup12583(t)
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	seedKernelReadback12583(fake, 42)
	replacedBefore := len(fake.replaced)
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if got := len(fake.replaced) - replacedBefore; got != 1 {
		t.Fatalf("apply 2 issued %d replaces for a backup-router listed on ifindex 42, want 1", got)
	}
	if link, ok := backupRouterLink12583(fake); !ok || link != 9 || len(fake.deleted) != 0 {
		t.Fatalf("after apply 2: backup-router link=%d present=%v deleted=%+v, want fxp0 (9) in place", link, ok, fake.deleted)
	}
}

// A stale route with a different gateway must still be replaced.
func TestBackupRouterStaleGatewayStillReplaced12583(t *testing.T) {
	d, fake, mgmtSet := backupSetup12583(t)
	fake.routes = append(fake.routes, netlink.Route{
		Family:    netlink.FAMILY_V4,
		Dst:       mustRoute11449(t, "0.0.0.0/0"),
		Gw:        net.ParseIP("192.0.2.99"),
		LinkIndex: 9,
		Table:     mgmtVRFTableID,
		Type:      unix.RTN_UNICAST,
		Protocol:  unix.RTPROT_STATIC,
		Realm:     mgmtStaticRouteRealm11449,
		Priority:  250,
	})
	fake.routes = append(fake.routes, netlink.Route{
		Family:    netlink.FAMILY_V4,
		Dst:       mustRoute11449(t, "203.0.113.0/24"),
		Gw:        net.ParseIP("192.0.2.1"),
		LinkIndex: 9,
		Table:     mgmtVRFTableID,
		Type:      unix.RTN_UNICAST,
		Protocol:  unix.RTPROT_STATIC,
		Realm:     mgmtStaticRouteRealm11449,
		Priority:  250,
	})
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := backupRouterLink12583(fake); !ok {
		t.Fatalf("correct backup-router not installed: %+v", fake.routes)
	}
	for _, r := range fake.routes {
		if r.Table == mgmtVRFTableID && r.Priority == 250 &&
			(r.Gw.Equal(net.ParseIP("192.0.2.99")) ||
				routeDst11449(r, netlink.FAMILY_V4) == "203.0.113.0/24") {
			t.Fatalf("stale gateway or prefix route survived: %+v", fake.routes)
		}
	}
}

// When the gateway's connected route moves from fxp0 (9) to fxp1 (11), the
// route listed on fxp0 no longer matches and the reconcile moves it to fxp1.
func TestBackupRouterFollowsGatewayMove12583(t *testing.T) {
	d, fake, mgmtSet := backupSetup12583(t)
	fake.links["fxp1"] = 11
	mgmtSet["fxp1"] = true
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	moveConnected12583(fake, 11)
	replacedBefore := len(fake.replaced)
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if link, ok := backupRouterLink12583(fake); !ok || link != 11 ||
		len(fake.replaced)-replacedBefore != 1 || len(fake.deleted) != 0 {
		t.Fatalf("after the gateway moved: backup-router link=%d present=%v replaces=%d deleted=%+v, want fxp1 (11) after one replace",
			link, ok, len(fake.replaced)-replacedBefore, fake.deleted)
	}
	replacedBefore = len(fake.replaced)
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 3: %v", err)
	}
	if len(fake.replaced) != replacedBefore {
		t.Fatalf("apply 3 churned: RouteReplace count %d -> %d", replacedBefore, len(fake.replaced))
	}
}

// Without a table-999 connected route for the gateway, the backup-router keeps
// LinkIndex 0 and matches no listed route, so every reconcile replaces it and
// the kernel re-checks the gateway. The overwritten copy is never deleted.
func TestBackupRouterUnresolvedGatewayRecheckedEveryReconcile12583(t *testing.T) {
	d, fake, mgmtSet := backupSetup12583(t)
	fake.routes = nil
	for pass := 1; pass <= 3; pass++ {
		replacedBefore := len(fake.replaced)
		if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
			t.Fatalf("apply %d: %v", pass, err)
		}
		if got := len(fake.replaced) - replacedBefore; got != 1 || fake.replaced[len(fake.replaced)-1].LinkIndex != 0 {
			t.Fatalf("apply %d issued %d replaces (%+v), want one unpinned re-check", pass, got, fake.replaced)
		}
		if len(fake.deleted) != 0 {
			t.Fatalf("apply %d deleted routes, want none: %+v", pass, fake.deleted)
		}
		seedKernelReadback12583(fake, 42) // the kernel resolved the gateway elsewhere
	}
}

// When the gateway's subnet is gone, the kernel still lists the old route on
// fxp0. The unresolved route is replaced, the kernel refuses the unreachable
// gateway, and the reconcile returns that error and deletes the stale route
// instead of acknowledging it (#5867).
func TestBackupRouterUnreachableGatewayFailsClosed12583(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{"set system backup-router 192.0.2.1"})
	fake := &fakeMgmtProgrammer{
		links:      map[string]int{"fxp0": 9},
		replaceErr: unix.ENETUNREACH,
		v4: []netlink.Route{{
			Family:    netlink.FAMILY_V4,
			Dst:       mustRoute11449(t, "0.0.0.0/0"),
			Gw:        net.ParseIP("192.0.2.1"),
			LinkIndex: 9,
			Table:     mgmtVRFTableID,
			Type:      unix.RTN_UNICAST,
			Protocol:  unix.RTPROT_STATIC,
			Realm:     mgmtStaticRouteRealm11449,
			Priority:  250,
		}},
	}
	err := (&Daemon{store: store}).applyMgmtVRFRoutesTo(fake, nil, map[string]bool{"fxp0": true})
	if !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("apply error = %v, want the replace's ENETUNREACH", err)
	}
	if len(fake.replaced) != 1 || fake.replaced[0].LinkIndex != 0 {
		t.Fatalf("replaces = %+v, want one unpinned backup-router re-check", fake.replaced)
	}
	if len(fake.deleted) != 1 || len(fake.v4) != 0 {
		t.Fatalf("stale backup-router kept: deleted=%v listed=%+v", fake.deleted, fake.v4)
	}
}

// An explicit next-hop interface stays part of the identity at the reconcile
// call site: an xpf-owned route in the same slot (destination, priority,
// gateway) on fxp1 is replaced in place by the configured fxp0 route.
func TestMgmtStaticExplicitInterfacePinReplacesSameSlot12583(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set routing-options static route 198.51.100.0/24 next-hop 192.0.2.1 interface fxp0",
	})
	fake := &mgmtStaticRouteFake11449{
		links: map[string]int{"fxp0": 9, "fxp1": 11},
		routes: []netlink.Route{{
			Family:    netlink.FAMILY_V4,
			Dst:       mustRoute11449(t, "198.51.100.0/24"),
			Gw:        net.ParseIP("192.0.2.1"),
			LinkIndex: 11,
			Table:     mgmtVRFTableID,
			Type:      unix.RTN_UNICAST,
			Protocol:  unix.RTPROT_STATIC,
			Realm:     mgmtStaticRouteRealm11449,
			Priority:  5,
		}},
	}
	d := &Daemon{store: store}
	mgmtSet := map[string]bool{"fxp0": true, "fxp1": true}
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(fake.replaced) != 1 || fake.replaced[0].LinkIndex != 9 || len(fake.deleted) != 0 ||
		len(fake.routes) != 1 || fake.routes[0].LinkIndex != 9 {
		t.Fatalf("fxp1 route not replaced in place by the fxp0 pin: replaced=%+v deleted=%+v routes=%+v",
			fake.replaced, fake.deleted, fake.routes)
	}
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if len(fake.replaced) != 1 {
		t.Fatalf("re-apply churned: RouteReplace count = %d, want 1", len(fake.replaced))
	}
}

// The kernel lists IPv6 connected routes with universe scope, so an IPv6
// backup-router gateway takes the static next-hop inference from the
// configured fxp0 prefix. The listed route then matches the desired one.
func TestBackupRouterIPv6InferredLinkStable12583(t *testing.T) {
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
			Scope:     netlink.SCOPE_UNIVERSE,
		}},
	}
	d := &Daemon{store: store}
	mgmtSet := map[string]bool{"fxp0": true}
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	if len(fake.replaced) != 1 || fake.replaced[0].LinkIndex != 7 {
		t.Fatalf("apply 1 replaced %+v, want one IPv6 backup-router pinned to fxp0 (7)", fake.replaced)
	}
	seedKernelReadback12583(fake, 7)
	if err := d.applyMgmtVRFRoutesTo(fake, nil, mgmtSet); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if len(fake.replaced) != 1 || len(fake.deleted) != 0 {
		t.Fatalf("apply 2 churned: replaced=%+v deleted=%+v", fake.replaced, fake.deleted)
	}
}
