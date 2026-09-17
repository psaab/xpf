package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeMgmtRouteHandle is an in-memory stand-in for the netlink surface
// reconcileMgmtVRFRouteDeletes uses. It holds the xpf-owned (RTPROT_DHCP)
// routes currently in the management VRF table, split by family, and records
// deletes so a test can assert exactly which routes were withdrawn.
type fakeMgmtRouteHandle struct {
	v4      []netlink.Route
	v6      []netlink.Route
	listErr error
	delErr  error
	deleted []string // dst keys passed to RouteDel, in order
}

func (f *fakeMgmtRouteHandle) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	// The reconcile MUST scope its list to table+protocol; if it ever stops
	// filtering on RTPROT_DHCP this fake returns nothing, and the empty-desired
	// test (which expects deletes) fails — guarding the ownership scope.
	if filter == nil || filter.Table != mgmtVRFTableID ||
		filter.Protocol != unix.RTPROT_DHCP ||
		mask&netlink.RT_FILTER_PROTOCOL == 0 ||
		mask&netlink.RT_FILTER_TABLE == 0 {
		return nil, nil
	}
	var routes []netlink.Route
	switch family {
	case netlink.FAMILY_V4:
		routes = f.v4
	case netlink.FAMILY_V6:
		routes = f.v6
	default:
		return nil, nil
	}
	out := make([]netlink.Route, 0, len(routes))
	for _, route := range routes {
		if route.Protocol == filter.Protocol {
			out = append(out, route)
		}
	}
	return append([]netlink.Route(nil), out...), nil
}

func (f *fakeMgmtRouteHandle) RouteDel(route *netlink.Route) error {
	if f.delErr != nil {
		return f.delErr
	}
	// Dispatch by Family: a default route has a nil Dst, so the family is the
	// only thing distinguishing the v4 default (0.0.0.0/0) from the v6 default
	// (::/0). Real netlink populates Route.Family on listed routes; the seeds
	// below set it, and the reconcile passes the listed route through unchanged.
	fam := route.Family
	if fam == netlink.FAMILY_V6 {
		f.v6 = removeRouteByDst(f.v6, route.Dst, netlink.FAMILY_V6)
	} else {
		fam = netlink.FAMILY_V4
		f.v4 = removeRouteByDst(f.v4, route.Dst, netlink.FAMILY_V4)
	}
	f.deleted = append(f.deleted, mgmtRouteDstKey(route.Dst, fam))
	return nil
}

func removeRouteByDst(routes []netlink.Route, dst *net.IPNet, family int) []netlink.Route {
	key := mgmtRouteDstKey(dst, family)
	out := make([]netlink.Route, 0, len(routes))
	for _, r := range routes {
		if mgmtRouteDstKey(r.Dst, family) == key {
			continue
		}
		out = append(out, r)
	}
	return out
}

func mustCIDRRoute(t *testing.T, cidr string) netlink.Route {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return netlink.Route{Dst: ipnet, Table: mgmtVRFTableID, Protocol: unix.RTPROT_DHCP, Family: netlink.FAMILY_V4}
}

// defaultV4Route mirrors how netlink returns a default route: a nil Dst.
func defaultV4Route() netlink.Route {
	return netlink.Route{Dst: nil, Table: mgmtVRFTableID, Protocol: unix.RTPROT_DHCP, Family: netlink.FAMILY_V4}
}

// desiredKeyV4Default / desiredKeyCIDR build a DESTINATION key (the identity the
// fake's RouteDel records) so a test can assert WHICH route was deleted.
func desiredKeyV4Default() string {
	return mgmtRouteDstKey(&net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, netlink.FAMILY_V4)
}

func desiredKeyCIDR(t *testing.T, cidr string) string {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return mgmtRouteDstKey(ipnet, netlink.FAMILY_V4)
}

// appliedKeyV4Default / appliedKeyCIDR build the FULL-identity protect-set key the
// same way applyMgmtVRFRoutesTo does (#5867). The seeded current routes in these
// reconcile tests carry no gateway/ifindex (Gw nil, LinkIndex 0), so the applied
// key matches with an empty gateway and index 0 — the reconcile keeps a desired
// route and deletes a withdrawn one exactly as before.
func appliedKeyV4Default() string {
	return mgmtRouteAppliedKey(&net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, netlink.FAMILY_V4, nil, 0)
}

func appliedKeyCIDR(t *testing.T, cidr string) string {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return mgmtRouteAppliedKey(ipnet, netlink.FAMILY_V4, nil, 0)
}

// TestReconcileMgmtVRFRoutes_WithdrawnClasslessDeleted proves that a withdrawn
// option-121 classless route (present in table 999 but absent from the desired
// set) is deleted, while the still-desired default and classless routes are
// retained. Fails (stale route remains) if the delete pass is reverted (#5108).
func TestReconcileMgmtVRFRoutes_WithdrawnClasslessDeleted(t *testing.T) {
	fake := &fakeMgmtRouteHandle{
		v4: []netlink.Route{
			defaultV4Route(),
			mustCIDRRoute(t, "10.20.0.0/16"),
			mustCIDRRoute(t, "192.0.2.0/24"), // withdrawn
		},
	}
	desired := map[string]struct{}{
		appliedKeyV4Default():             {},
		appliedKeyCIDR(t, "10.20.0.0/16"): {},
	}

	var d Daemon
	d.reconcileMgmtVRFRouteDeletes(fake, mgmtVRFTableID, desired)

	if len(fake.v4) != 2 {
		t.Fatalf("after reconcile want 2 routes remaining, got %d: %v", len(fake.v4), fake.v4)
	}
	// The withdrawn route (and only it) must be gone.
	for _, r := range fake.v4 {
		if mgmtRouteDstKey(r.Dst, netlink.FAMILY_V4) == desiredKeyCIDR(t, "192.0.2.0/24") {
			t.Fatalf("withdrawn route 192.0.2.0/24 still present after reconcile")
		}
	}
	if len(fake.deleted) != 1 || fake.deleted[0] != desiredKeyCIDR(t, "192.0.2.0/24") {
		t.Fatalf("want exactly one delete of 192.0.2.0/24, got %v", fake.deleted)
	}
}

// TestReconcileMgmtVRFRoutes_EmptyDesiredDeletesAll proves the disabled-lease
// case: when the desired set is EMPTY (management lease disabled or interface
// gone) EVERY xpf-owned route in table 999 is deleted. This is the core #5108
// fix — the pre-fix early-return on an empty desired set skipped cleanup.
func TestReconcileMgmtVRFRoutes_EmptyDesiredDeletesAll(t *testing.T) {
	fake := &fakeMgmtRouteHandle{
		v4: []netlink.Route{
			defaultV4Route(),
			mustCIDRRoute(t, "10.20.0.0/16"),
		},
		v6: []netlink.Route{
			{Dst: nil, Table: mgmtVRFTableID, Protocol: unix.RTPROT_DHCP, Family: netlink.FAMILY_V6}, // ::/0 default
		},
	}

	var d Daemon
	d.reconcileMgmtVRFRouteDeletes(fake, mgmtVRFTableID, map[string]struct{}{})

	if len(fake.v4) != 0 || len(fake.v6) != 0 {
		t.Fatalf("empty desired set must delete all xpf routes; got v4=%v v6=%v", fake.v4, fake.v6)
	}
	if len(fake.deleted) != 3 {
		t.Fatalf("want 3 deletes (2×v4 + 1×v6), got %d: %v", len(fake.deleted), fake.deleted)
	}
}

// TestReconcileMgmtVRFRoutes_ESRCHTolerated confirms a delete of an
// already-absent route (ESRCH) is not treated as fatal — the reconcile still
// processes the remaining routes.
func TestReconcileMgmtVRFRoutes_ESRCHTolerated(t *testing.T) {
	fake := &fakeMgmtRouteHandle{
		v4:     []netlink.Route{mustCIDRRoute(t, "192.0.2.0/24")},
		delErr: unix.ESRCH,
	}
	var d Daemon
	// Must not panic and must not surface ESRCH as a hard failure.
	d.reconcileMgmtVRFRouteDeletes(fake, mgmtVRFTableID, map[string]struct{}{})
}

// TestMgmtRouteDstKey covers the destination canonicalization: a nil Dst and an
// explicit all-zeros /0 collapse to the same family default key, and both a
// 4-byte and a 16-byte-encoded IPv4 prefix key identically.
func TestMgmtRouteDstKey(t *testing.T) {
	if got := mgmtRouteDstKey(nil, netlink.FAMILY_V4); got != "0.0.0.0/0" {
		t.Errorf("nil v4 Dst key = %q, want 0.0.0.0/0", got)
	}
	if got := mgmtRouteDstKey(nil, netlink.FAMILY_V6); got != "::/0" {
		t.Errorf("nil v6 Dst key = %q, want ::/0", got)
	}
	zeroV4 := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	if got := mgmtRouteDstKey(zeroV4, netlink.FAMILY_V4); got != "0.0.0.0/0" {
		t.Errorf("explicit 0.0.0.0/0 key = %q, want 0.0.0.0/0", got)
	}
	zeroV6 := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	if got := mgmtRouteDstKey(zeroV6, netlink.FAMILY_V6); got != "::/0" {
		t.Errorf("explicit ::/0 key = %q, want ::/0", got)
	}
	// A 16-byte-encoded IPv4 prefix and its 4-byte parse must key identically.
	_, parsed, _ := net.ParseCIDR("10.20.0.0/16")
	wide := &net.IPNet{IP: net.ParseIP("10.20.0.0"), Mask: net.CIDRMask(16, 32)}
	if a, b := mgmtRouteDstKey(parsed, netlink.FAMILY_V4), mgmtRouteDstKey(wide, netlink.FAMILY_V4); a != b {
		t.Errorf("4-byte vs 16-byte IPv4 keys diverge: %q != %q", a, b)
	}
}

// TestMgmtVRFRoutesToDelete exercises the pure diff directly, independent of any
// netlink handle.
func TestMgmtVRFRoutesToDelete(t *testing.T) {
	current := []netlink.Route{
		defaultV4Route(),
		mustCIDRRoute(t, "10.20.0.0/16"),
		mustCIDRRoute(t, "192.0.2.0/24"),
	}
	desired := map[string]struct{}{
		appliedKeyV4Default():             {},
		appliedKeyCIDR(t, "10.20.0.0/16"): {},
	}
	del := mgmtVRFRoutesToDelete(current, desired, netlink.FAMILY_V4)
	if len(del) != 1 {
		t.Fatalf("want 1 route to delete, got %d: %v", len(del), del)
	}
	if got := mgmtRouteDstKey(del[0].Dst, netlink.FAMILY_V4); got != desiredKeyCIDR(t, "192.0.2.0/24") {
		t.Fatalf("want 192.0.2.0/24 to delete, got %q", got)
	}

	// Empty desired => everything deleted.
	all := mgmtVRFRoutesToDelete(current, map[string]struct{}{}, netlink.FAMILY_V4)
	if len(all) != len(current) {
		t.Fatalf("empty desired must delete all %d, got %d", len(current), len(all))
	}
}
