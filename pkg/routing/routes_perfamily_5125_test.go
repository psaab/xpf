package routing

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// perFamilyFailLister is a routeLister double that succeeds for IPv4 and
// fails for IPv6 (or vice-versa), so a single address family's dump can be
// made to fail while the other returns real routes. It backs the #5125
// fail-on-revert tests: the route readers must surface the per-family
// failure (non-nil joined error) AND still return the family that
// succeeded — never swallow the error, never drop the partial.
type perFamilyFailLister struct {
	failFamily int // netlink.FAMILY_V6 => IPv6 dumps fail
	byIndex    map[int]string
}

// v4Routes / v6Routes are the canned per-family route sets. IPv4 carries a
// single default route so a successful IPv4 dump is observable in the
// rendered output; IPv6 would carry its own but is failed in these tests.
func (f *perFamilyFailLister) v4Routes() []netlink.Route {
	_, dst, _ := net.ParseCIDR("10.0.1.0/24")
	return []netlink.Route{{
		Dst:      dst,
		Gw:       net.ParseIP("10.0.1.1"),
		Protocol: netlink.RouteProtocol(unix.RTPROT_STATIC),
		Priority: 5,
	}}
}

func (f *perFamilyFailLister) v6Routes() []netlink.Route {
	_, dst, _ := net.ParseCIDR("2001:db8::/32")
	return []netlink.Route{{
		Dst:      dst,
		Gw:       net.ParseIP("2001:db8::1"),
		Protocol: netlink.RouteProtocol(unix.RTPROT_STATIC),
		Priority: 5,
	}}
}

func (f *perFamilyFailLister) routesFor(family int) ([]netlink.Route, error) {
	if family == f.failFamily {
		return nil, fmt.Errorf("simulated netlink dump failure for family %d", family)
	}
	if family == netlink.FAMILY_V6 {
		return f.v6Routes(), nil
	}
	return f.v4Routes(), nil
}

func (f *perFamilyFailLister) RouteListFiltered(family int, _ *netlink.Route, _ uint64) ([]netlink.Route, error) {
	return f.routesFor(family)
}

func (f *perFamilyFailLister) RouteList(_ netlink.Link, family int) ([]netlink.Route, error) {
	return f.routesFor(family)
}
func (f *perFamilyFailLister) RouteListFilteredIter(family int, _ *netlink.Route, _ uint64, fn func(netlink.Route) bool) error {
	routes, err := f.routesFor(family)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if !fn(route) {
			break
		}
	}
	return nil
}

func (f *perFamilyFailLister) LinkByIndex(index int) (netlink.Link, error) {
	name, ok := f.byIndex[index]
	if !ok {
		return nil, fmt.Errorf("index %d not found", index)
	}
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}, nil
}

func (f *perFamilyFailLister) LinkByName(name string) (netlink.Link, error) {
	for idx, n := range f.byIndex {
		if n == name {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: idx}}, nil
		}
	}
	return nil, fmt.Errorf("link %q not found", name)
}

func hasV4(entries []RouteEntry) bool {
	for _, e := range entries {
		if !strings.Contains(e.Destination, ":") {
			return true
		}
	}
	return false
}

// TestGetRoutesPerFamilyFailureSurfaces proves GetRoutes returns the
// successful (IPv4) family's routes AND a non-nil error when the IPv6 dump
// fails. RED against a revert to `if err != nil { continue }; return
// entries, nil` (it swallowed the error and returned nil).
func TestGetRoutesPerFamilyFailureSurfaces(t *testing.T) {
	rr := &routeReader{ops: &perFamilyFailLister{failFamily: netlink.FAMILY_V6}}

	entries, err := rr.GetRoutes()
	if err == nil {
		t.Fatal("got nil error on a partial IPv6 dump failure; a per-family failure must surface")
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Errorf("error should name the failing family (inet6); got %v", err)
	}
	if !hasV4(entries) {
		t.Errorf("the successful IPv4 family's routes must still be returned; got %+v", entries)
	}
}

// TestGetRoutesForTablePerFamilyFailureSurfaces is the GetRoutesForTable
// mirror of the above.
func TestGetRoutesForTablePerFamilyFailureSurfaces(t *testing.T) {
	rr := &routeReader{ops: &perFamilyFailLister{failFamily: netlink.FAMILY_V6}}

	entries, err := rr.GetRoutesForTable(100)
	if err == nil {
		t.Fatal("got nil error on a partial IPv6 dump failure; must surface")
	}
	if !strings.Contains(err.Error(), "inet6") || !strings.Contains(err.Error(), "table 100") {
		t.Errorf("error should name the failing family and table; got %v", err)
	}
	if !hasV4(entries) {
		t.Errorf("the successful IPv4 family's routes must still be returned; got %+v", entries)
	}
}

// TestGetAllTableRoutesPerFamilyFailureSurfaces proves the main-table
// partial failure is joined into the returned error while the successful
// family's inet.0 table is still rendered.
func TestGetAllTableRoutesPerFamilyFailureSurfaces(t *testing.T) {
	rr := &routeReader{ops: &perFamilyFailLister{failFamily: netlink.FAMILY_V6}}

	tables, err := rr.GetAllTableRoutes([]*config.RoutingInstanceConfig{
		{Name: "blue", TableID: 100},
	})
	if err == nil {
		t.Fatal("got nil error on a partial IPv6 dump failure; must surface")
	}
	// The successful IPv4 family still yields an inet.0 table (main) and a
	// blue.inet.0 table (per-instance).
	var sawMainV4, sawInstV4 bool
	for _, tbl := range tables {
		if tbl.Name == "inet.0" && len(tbl.Entries) > 0 {
			sawMainV4 = true
		}
		if tbl.Name == "blue.inet.0" && len(tbl.Entries) > 0 {
			sawInstV4 = true
		}
	}
	if !sawMainV4 {
		t.Errorf("main inet.0 table (successful IPv4 family) must still render; got %+v", tables)
	}
	if !sawInstV4 {
		t.Errorf("per-instance blue.inet.0 table must still render; got %+v", tables)
	}
}

// TestGetRoutesBothFamiliesOKNoError is the happy-path guard: when both
// families succeed, no error is returned and both families' routes render.
// It fails if the join logic wrongly reports an error on full success.
func TestGetRoutesBothFamiliesOKNoError(t *testing.T) {
	rr := &routeReader{ops: &perFamilyFailLister{failFamily: -1}} // no family fails

	entries, err := rr.GetRoutes()
	if err != nil {
		t.Fatalf("unexpected error when both families succeed: %v", err)
	}
	if !hasV4(entries) {
		t.Error("IPv4 routes missing on full success")
	}
	var sawV6 bool
	for _, e := range entries {
		if strings.Contains(e.Destination, ":") {
			sawV6 = true
		}
	}
	if !sawV6 {
		t.Error("IPv6 routes missing on full success")
	}

	tables, err := rr.GetAllTableRoutes(nil)
	if err != nil {
		t.Fatalf("unexpected GetAllTableRoutes error on full success: %v", err)
	}
	if len(tables) == 0 {
		t.Error("expected non-empty tables on full success")
	}
}

// TestFamilyNameTag documents the family label used in the joined error and
// asserts the failing family's underlying netlink error is preserved (the
// join uses %w, so errors.Is-style unwrapping reaches it).
func TestFamilyNameTag(t *testing.T) {
	if got := familyName(netlink.FAMILY_V4); got != "inet" {
		t.Errorf("familyName(V4) = %q, want inet", got)
	}
	if got := familyName(netlink.FAMILY_V6); got != "inet6" {
		t.Errorf("familyName(V6) = %q, want inet6", got)
	}
	rr := &routeReader{ops: &perFamilyFailLister{failFamily: netlink.FAMILY_V6}}
	_, err := rr.GetRoutes()
	if err == nil {
		t.Fatal("expected a joined error on a partial IPv6 failure")
	}
	if !strings.Contains(err.Error(), "simulated netlink dump failure") {
		t.Errorf("joined error should wrap the underlying netlink failure; got %v", err)
	}
}
