package daemon

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #5867: a management-VRF route replacement that keeps the DESTINATION but
// changes GATEWAY / output interface and then FAILS must NOT leave the OLD
// (stale) route protected from cleanup — management traffic must not stay pinned
// to a stale/de-authorized gateway on a "successful" commit. applyMgmtVRFRoutesTo
// keys the reconcile protect-set on the FULL route identity and adds a route to
// it only AFTER RouteReplace succeeds, and returns the failure so the commit
// fails closed.

// fakeMgmtLink is a minimal netlink.Link exposing only an interface index.
type fakeMgmtLink struct{ idx int }

func (l fakeMgmtLink) Attrs() *netlink.LinkAttrs { return &netlink.LinkAttrs{Index: l.idx} }
func (l fakeMgmtLink) Type() string              { return "dummy" }

// fakeMgmtProgrammer implements mgmtRouteProgrammer: it holds the current kernel
// routes, resolves a fixed link index, and either fails or applies a
// RouteReplace (modelling the kernel's same-destination overwrite on success).
type fakeMgmtProgrammer struct {
	v4, v6     []netlink.Route
	linkIdx    int
	linkErr    error
	listErr    error
	replaceErr error
	replaced   []*netlink.Route
	deleted    []string
}

func (f *fakeMgmtProgrammer) LinkByName(name string) (netlink.Link, error) {
	if f.linkErr != nil {
		return nil, f.linkErr
	}
	return fakeMgmtLink{idx: f.linkIdx}, nil
}

func routeFamily(r *netlink.Route) int {
	if r.Gw != nil && r.Gw.To4() == nil {
		return netlink.FAMILY_V6
	}
	if r.Dst != nil && r.Dst.IP.To4() == nil {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

func (f *fakeMgmtProgrammer) RouteReplace(route *netlink.Route) error {
	f.replaced = append(f.replaced, route)
	if f.replaceErr != nil {
		return f.replaceErr // kernel unchanged: the stale route survives
	}
	// Model the kernel: RouteReplace overwrites any same-destination entry.
	cp := *route
	if routeFamily(route) == netlink.FAMILY_V6 {
		f.v6 = removeRouteByDst(f.v6, route.Dst, netlink.FAMILY_V6)
		f.v6 = append(f.v6, cp)
	} else {
		f.v4 = removeRouteByDst(f.v4, route.Dst, netlink.FAMILY_V4)
		f.v4 = append(f.v4, cp)
	}
	return nil
}

func (f *fakeMgmtProgrammer) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if filter == nil || filter.Table != mgmtVRFTableID || mask&netlink.RT_FILTER_TABLE == 0 {
		return nil, nil
	}
	var routes []netlink.Route
	if family == netlink.FAMILY_V6 {
		routes = f.v6
	} else {
		routes = f.v4
	}
	if mask&netlink.RT_FILTER_PROTOCOL != 0 {
		out := make([]netlink.Route, 0, len(routes))
		for _, route := range routes {
			if route.Protocol == filter.Protocol {
				out = append(out, route)
			}
		}
		routes = out
	}
	return append([]netlink.Route(nil), routes...), nil
}

func (f *fakeMgmtProgrammer) RouteDel(route *netlink.Route) error {
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

// staleDefaultV4 is the kernel's existing default route via the OLD gateway on
// the OLD interface index — what a same-destination replacement would supersede.
func staleDefaultV4(gw string, ifIndex int) netlink.Route {
	return netlink.Route{
		Dst: nil, Gw: net.ParseIP(gw), LinkIndex: ifIndex,
		Table: mgmtVRFTableID, Protocol: unix.RTPROT_DHCP, Family: netlink.FAMILY_V4,
	}
}

func gwLease(iface, gw string) *dhcp.Lease {
	return &dhcp.Lease{Interface: iface, Family: dhcp.AFInet, Gateway: netip.MustParseAddr(gw)}
}

// TestApplyMgmtVRFRoutes_FailedGatewayChangeCleansStaleRoute_5867 pins the fix: a
// same-destination default route whose gateway (and output interface) changed and
// whose RouteReplace FAILS must (a) surface the error so the commit fails closed
// and (b) leave the OLD stale route ELIGIBLE FOR CLEANUP (it is deleted), never
// protected.
//
// FAIL-ON-REVERT: revert the protect-set to the destination-only key (and inserted
// before RouteReplace), and the stale route's destination matches the desired
// destination, so it is PROTECTED and NOT deleted — the "stale route cleaned up"
// assertion goes RED.
func TestApplyMgmtVRFRoutes_FailedGatewayChangeCleansStaleRoute_5867(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		v4:         []netlink.Route{staleDefaultV4("10.99.0.1", 5)}, // OLD gw/ifindex, still in kernel
		linkIdx:    6,                                               // NEW interface index
		replaceErr: errors.New("nl: RTNETLINK route replace rejected"),
	}
	// The lease now points the default route at a NEW gateway; the replacement
	// fails (e.g. a de-authorized next hop the kernel rejects).
	err := (&Daemon{}).applyMgmtVRFRoutesTo(fake,
		[]*dhcp.Lease{gwLease("fxp0", "10.99.0.2")},
		map[string]bool{"fxp0": true})

	if err == nil {
		t.Fatal("a failed RouteReplace must be returned so the commit fails closed, not silently acknowledged with the stale route pinned")
	}
	// The stale default route must have been cleaned up (not protected).
	if len(fake.deleted) != 1 || fake.deleted[0] != mgmtRouteDstKey(nil, netlink.FAMILY_V4) {
		t.Fatalf("stale default route must be eligible for cleanup (deleted); got deleted=%v", fake.deleted)
	}
	if len(fake.v4) != 0 {
		t.Fatalf("stale route still present after reconcile (management pinned to stale gateway): %v", fake.v4)
	}
}

// TestApplyMgmtVRFRoutes_SuccessfulGatewayChange_5867 pins the happy path: a
// same-destination gateway change that SUCCEEDS replaces the old route cleanly,
// the NEW identity is protected from cleanup, no stale route survives, and no
// error is returned.
//
// FAIL-ON-REVERT: with the destination-only protect key the NEW route is still
// kept (same destination), so this test alone does not detect the revert — the
// failed-change test above is the load-bearing guard. This test guards against
// OVER-cleanup (the applied route must not be falsely deleted).
func TestApplyMgmtVRFRoutes_SuccessfulGatewayChange_5867(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		v4:      []netlink.Route{staleDefaultV4("10.99.0.1", 5)}, // old route to be superseded
		linkIdx: 6,                                               // new interface index
		// replaceErr nil => RouteReplace succeeds and overwrites the same-dest entry.
	}
	err := (&Daemon{}).applyMgmtVRFRoutesTo(fake,
		[]*dhcp.Lease{gwLease("fxp0", "10.99.0.2")},
		map[string]bool{"fxp0": true})

	if err != nil {
		t.Fatalf("a successful gateway change must not error: %v", err)
	}
	// Exactly one route remains: the NEW identity (10.99.0.2 dev if 6). The old
	// one was superseded by RouteReplace, and the applied route must NOT be deleted.
	if len(fake.deleted) != 0 {
		t.Fatalf("the freshly-applied route must not be cleaned up; deleted=%v", fake.deleted)
	}
	if len(fake.v4) != 1 {
		t.Fatalf("want exactly one default route after a successful replace, got %v", fake.v4)
	}
	got := fake.v4[0]
	if got.Gw.String() != "10.99.0.2" || got.LinkIndex != 6 {
		t.Fatalf("kernel route not updated to the new identity: gw=%s if=%d", got.Gw, got.LinkIndex)
	}
}
