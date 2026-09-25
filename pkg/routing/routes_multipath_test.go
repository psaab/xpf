package routing

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fakeRouteLister is a minimal routeLister double whose only job is to
// resolve ifindex → name for routeToEntry's multipath/link lookups.
type fakeRouteLister struct {
	byIndex map[int]string
}

func (f *fakeRouteLister) RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error) {
	return nil, nil
}
func (f *fakeRouteLister) RouteList(netlink.Link, int) ([]netlink.Route, error) {
	return nil, nil
}
func (*fakeRouteLister) RouteListFilteredIter(int, *netlink.Route, uint64, func(netlink.Route) bool) error {
	return nil
}
func (f *fakeRouteLister) LinkByIndex(index int) (netlink.Link, error) {
	name, ok := f.byIndex[index]
	if !ok {
		return nil, fmt.Errorf("index %d not found", index)
	}
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}, nil
}
func (f *fakeRouteLister) LinkByName(name string) (netlink.Link, error) {
	for idx, n := range f.byIndex {
		if n == name {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: idx}}, nil
		}
	}
	return nil, fmt.Errorf("link %q not found", name)
}

// TestRouteToEntryMultiPath proves routeToEntry reads the netlink
// RTA_MULTIPATH next-hop list. Against pre-fix code (which only read the
// single route.Gw, nil for an ECMP route) the multipath case collapses
// to a bare "direct" route with an empty NextHops slice — this test then
// goes RED on both the count (want 2) and the rendered next-hop lines.
func TestRouteToEntryMultiPath(t *testing.T) {
	rr := &routeReader{ops: &fakeRouteLister{byIndex: map[int]string{
		11: "ge-0-0-0",
		12: "ge-0-0-1",
	}}}

	_, dst, _ := net.ParseCIDR("10.20.0.0/16")
	route := netlink.Route{
		Dst:      dst,
		Protocol: netlink.RouteProtocol(unix.RTPROT_BGP),
		Priority: 170,
		MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: 11, Gw: net.ParseIP("192.0.2.1"), Hops: 0},
			{LinkIndex: 12, Gw: net.ParseIP("192.0.2.2"), Hops: 0},
		},
	}

	entry := rr.routeToEntry(route, netlink.FAMILY_V4)

	if got := len(entry.NextHops); got != 2 {
		t.Fatalf("multipath route: got %d next-hops, want 2 (pre-fix code ignores route.MultiPath)", got)
	}
	if entry.NextHops[0].Gateway != "192.0.2.1" || entry.NextHops[0].Interface != "ge-0-0-0" {
		t.Errorf("leg 0 = %+v, want gw 192.0.2.1 via ge-0-0-0", entry.NextHops[0])
	}
	if entry.NextHops[1].Gateway != "192.0.2.2" || entry.NextHops[1].Interface != "ge-0-0-1" {
		t.Errorf("leg 1 = %+v, want gw 192.0.2.2 via ge-0-0-1", entry.NextHops[1])
	}
	if entry.NextHops[0].Weight != 1 || entry.NextHops[1].Weight != 1 {
		t.Errorf("weights = %d,%d, want 1,1 (Hops+1)", entry.NextHops[0].Weight, entry.NextHops[1].Weight)
	}
	// Single-field back-fill: the first leg, not a bare "direct".
	if entry.NextHop != "192.0.2.1" || entry.Interface != "ge-0-0-0" {
		t.Errorf("back-filled single next-hop = %q via %q, want 192.0.2.1 via ge-0-0-0", entry.NextHop, entry.Interface)
	}

	// The canonical `show route` render must list BOTH next-hop lines.
	out := FormatAllRoutes([]TableRoutes{{Name: "inet.0", Entries: []RouteEntry{entry}}})
	if strings.Count(out, ">  to ") != 2 {
		t.Errorf("FormatAllRoutes emitted %d next-hop lines, want 2:\n%s", strings.Count(out, ">  to "), out)
	}
	if !strings.Contains(out, "to 192.0.2.1 via ge-0-0-0") || !strings.Contains(out, "to 192.0.2.2 via ge-0-0-1") {
		t.Errorf("FormatAllRoutes missing an ECMP leg:\n%s", out)
	}
}

// TestRouteToEntrySingleGateway confirms a plain single-gateway route is
// unchanged: one next-hop in NextHop, empty NextHops slice, one rendered
// line.
func TestRouteToEntrySingleGateway(t *testing.T) {
	rr := &routeReader{ops: &fakeRouteLister{byIndex: map[int]string{7: "ge-0-0-2"}}}

	_, dst, _ := net.ParseCIDR("10.30.0.0/16")
	route := netlink.Route{
		Dst:       dst,
		Gw:        net.ParseIP("10.30.0.254"),
		LinkIndex: 7,
		Protocol:  netlink.RouteProtocol(unix.RTPROT_STATIC),
		Priority:  5,
	}

	entry := rr.routeToEntry(route, netlink.FAMILY_V4)

	if len(entry.NextHops) != 0 {
		t.Errorf("single-gateway route: NextHops = %+v, want empty", entry.NextHops)
	}
	if entry.NextHop != "10.30.0.254" || entry.Interface != "ge-0-0-2" {
		t.Errorf("single next-hop = %q via %q, want 10.30.0.254 via ge-0-0-2", entry.NextHop, entry.Interface)
	}
	out := FormatAllRoutes([]TableRoutes{{Name: "inet.0", Entries: []RouteEntry{entry}}})
	if strings.Count(out, ">  to ") != 1 {
		t.Errorf("single-gateway render emitted %d next-hop lines, want 1:\n%s", strings.Count(out, ">  to "), out)
	}
}

// TestRouteToEntryConnected confirms a connected/direct route (no gateway,
// no multipath) is unchanged: NextHop "direct", empty NextHops, a "via"
// line only.
func TestRouteToEntryConnected(t *testing.T) {
	rr := &routeReader{ops: &fakeRouteLister{byIndex: map[int]string{9: "ge-0-0-3"}}}

	_, dst, _ := net.ParseCIDR("10.40.0.0/24")
	route := netlink.Route{
		Dst:       dst,
		LinkIndex: 9,
		Protocol:  netlink.RouteProtocol(unix.RTPROT_KERNEL),
	}

	entry := rr.routeToEntry(route, netlink.FAMILY_V4)

	if len(entry.NextHops) != 0 {
		t.Errorf("connected route: NextHops = %+v, want empty", entry.NextHops)
	}
	if entry.NextHop != "direct" {
		t.Errorf("connected route NextHop = %q, want %q", entry.NextHop, "direct")
	}
	out := FormatAllRoutes([]TableRoutes{{Name: "inet.0", Entries: []RouteEntry{entry}}})
	if strings.Contains(out, ">  to ") {
		t.Errorf("connected route should not render a 'to' next-hop line:\n%s", out)
	}
	if !strings.Contains(out, ">  via ge-0-0-3") {
		t.Errorf("connected route should render 'via ge-0-0-3':\n%s", out)
	}
}
