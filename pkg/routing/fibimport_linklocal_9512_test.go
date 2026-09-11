package routing

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #9512: a kernel-learned IPv6 route whose next hop is link-local must carry
// its link, or the helper binds whichever interface comes first in the
// snapshot.

func withLinkNames9512(t *testing.T, names map[int]string) {
	t.Helper()
	prev := learnedRouteLinkNameFn
	learnedRouteLinkNameFn = func(index int) (string, error) {
		if n, ok := names[index]; ok {
			return n, nil
		}
		return "", errors.New("no such link")
	}
	t.Cleanup(func() { learnedRouteLinkNameFn = prev })
}

func v6Route9512(t *testing.T, dst, gw string, linkIndex int) netlink.Route {
	return netlink.Route{
		Dst: mustCIDR(t, dst), Gw: net.ParseIP(gw), LinkIndex: linkIndex,
		Type: unix.RTN_UNICAST, Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
	}
}

func ecmp9512(t *testing.T, dst string, legs ...*netlink.NexthopInfo) netlink.Route {
	return netlink.Route{
		Dst: mustCIDR(t, dst), MultiPath: legs,
		Type: unix.RTN_UNICAST, Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
	}
}

func importV6Main9512(t *testing.T, routes ...netlink.Route) map[string][]string {
	t.Helper()
	withRouteLister(t, staticLister(map[[2]int][]netlink.Route{{netlink.FAMILY_V6, mainTableID}: routes}))
	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	out := map[string][]string{}
	for _, lr := range got {
		out[lr.Destination] = lr.NextHops
	}
	return out
}

// Identical link-local gateways on different links bind their own link, for a
// single route and for every ECMP leg.
func TestLinkLocalNextHopsCarryTheirOwnInterface9512(t *testing.T) {
	withLinkNames9512(t, map[int]string{101: "ge-0-0-1", 102: "ge-0-0-2"})
	got := importV6Main9512(t,
		v6Route9512(t, "2001:db8:beef::/48", "fe80::254", 102),
		v6Route9512(t, "2001:db8:cafe::/48", "fe80::254", 101),
		ecmp9512(t, "2001:db8:ec::/48",
			&netlink.NexthopInfo{Gw: net.ParseIP("fe80::254"), LinkIndex: 101},
			&netlink.NexthopInfo{Gw: net.ParseIP("fe80::254"), LinkIndex: 102}),
	)
	want := map[string][]string{
		"2001:db8:beef::/48": {"fe80::254@ge-0-0-2"},
		"2001:db8:cafe::/48": {"fe80::254@ge-0-0-1"},
		"2001:db8:ec::/48":   {"fe80::254@ge-0-0-1", "fe80::254@ge-0-0-2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("next hops = %v\nwant       %v", got, want)
	}
}

// The property the fix exists for: the answer does not depend on dump order.
func TestLinkLocalScopeIsOrderIndependent9512(t *testing.T) {
	withLinkNames9512(t, map[int]string{101: "ge-0-0-1", 102: "ge-0-0-2"})
	a := v6Route9512(t, "2001:db8:beef::/48", "fe80::254", 102)
	b := v6Route9512(t, "2001:db8:cafe::/48", "fe80::254", 101)
	forward := importV6Main9512(t, a, b)
	reversed := importV6Main9512(t, b, a)
	if !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("dump order changed the binding: forward=%v reversed=%v", forward, reversed)
	}
}

// Negative control: a scope-less GLOBAL gateway, and an IPv4 gateway, stay
// scope-less. The helper's connected-prefix inference is correct for them and
// the fix must not tighten it.
func TestGlobalAndIPv4GatewaysStayScopeLess9512(t *testing.T) {
	withLinkNames9512(t, map[int]string{102: "ge-0-0-2"})
	got := importV6Main9512(t, v6Route9512(t, "2001:db8:beef::/48", "2001:db8:2::254", 102))
	if want := []string{"2001:db8:2::254"}; !reflect.DeepEqual(got["2001:db8:beef::/48"], want) {
		t.Errorf("global gateway = %v, want %v", got["2001:db8:beef::/48"], want)
	}
	withRouteLister(t, staticLister(v4Main(netlink.Route{
		Dst: mustCIDR(t, "10.20.0.0/16"), Gw: net.ParseIP("192.0.2.1"), LinkIndex: 102,
		Type: unix.RTN_UNICAST, Protocol: netlink.RouteProtocol(unix.RTPROT_BGP),
	})))
	v4, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil || len(v4) != 1 || !reflect.DeepEqual(v4[0].NextHops, []string{"192.0.2.1"}) {
		t.Errorf("IPv4 gateway = %+v (err %v), want next hops [192.0.2.1]", v4, err)
	}
}

// An unresolvable link-local leg refuses the whole route (ECMP stays
// all-or-nothing), with one diagnostic naming the route however many imports
// see it. A resolvable sibling route is unaffected.
func TestUnresolvableLinkLocalLegRefusesTheRoute9512(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	unscopedLinkLocalWarned.Range(func(k, _ any) bool { unscopedLinkLocalWarned.Delete(k); return true })

	withLinkNames9512(t, map[int]string{101: "ge-0-0-1"})
	routes := []netlink.Route{
		v6Route9512(t, "2001:db8:a::/48", "fe80::254", 0),   // no link at all
		v6Route9512(t, "2001:db8:b::/48", "fe80::254", 999), // link with no name
		ecmp9512(t, "2001:db8:c::/48",
			&netlink.NexthopInfo{Gw: net.ParseIP("fe80::254"), LinkIndex: 101},
			&netlink.NexthopInfo{Gw: net.ParseIP("fe80::253"), LinkIndex: 999}),
		v6Route9512(t, "2001:db8:f00d::/48", "fe80::254", 101),
	}
	for i := 0; i < 3; i++ {
		got := importV6Main9512(t, routes...)
		for _, dst := range []string{"2001:db8:a::/48", "2001:db8:b::/48", "2001:db8:c::/48"} {
			if nh, ok := got[dst]; ok {
				t.Fatalf("import %d: %s was imported with an unscoped link-local leg: %v", i, dst, nh)
			}
		}
		if want := []string{"fe80::254@ge-0-0-1"}; !reflect.DeepEqual(got["2001:db8:f00d::/48"], want) {
			t.Fatalf("import %d: the resolvable sibling = %v, want %v", i, got["2001:db8:f00d::/48"], want)
		}
	}
	out := buf.String()
	for _, dst := range []string{"2001:db8:a::/48", "2001:db8:b::/48", "2001:db8:c::/48"} {
		if n := strings.Count(out, "destination="+dst); n != 1 {
			t.Errorf("want one refusal diagnostic naming %s over three imports, got %d:\n%s", dst, n, out)
		}
	}
}
