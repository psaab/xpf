package routing

import (
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #14950 (D13-05): the kernel-learned route importer must not adopt
// DEAD/LINKDOWN nexthops, and must preserve an explicit gateway LinkIndex
// binding on IPv4 and global-IPv6 next-hops instead of stripping it and
// leaving the helper to re-infer the egress from connected prefixes.
//
// RED on revert, per mechanism:
//   - drop the DEAD/LINKDOWN exclusion and the dead/linkdown routes and
//     ECMP legs below are imported again;
//   - restore the pre-#14950 scopeLearnedGateway (bare gateway unless
//     link-local or ambiguous-ECMP) and the explicit-binding cells fail
//     with scope-less next-hops.

func withLinkNames14950(t *testing.T, names map[int]string) {
	t.Helper()
	prev := learnedRouteLinkNameFn
	learnedRouteLinkNameFn = func(index int) (string, error) {
		if name, ok := names[index]; ok {
			return name, nil
		}
		return "", errNoLink14950{}
	}
	t.Cleanup(func() { learnedRouteLinkNameFn = prev })
}

type errNoLink14950 struct{}

func (errNoLink14950) Error() string { return "no such link (test)" }

func importV4Main14950(t *testing.T, routes ...netlink.Route) []LearnedRoute {
	t.Helper()
	withRouteLister(t, staticLister(v4Main(routes...)))
	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return got
}

func importV6Main14950(t *testing.T, routes ...netlink.Route) []LearnedRoute {
	t.Helper()
	withRouteLister(t, staticLister(map[[2]int][]netlink.Route{{netlink.FAMILY_V6, mainTableID}: routes}))
	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return got
}

func singleV4_14950(t *testing.T, dst, gw string, linkIndex, flags int) netlink.Route {
	t.Helper()
	return netlink.Route{
		Dst: mustCIDR(t, dst), Gw: net.ParseIP(gw), LinkIndex: linkIndex, Flags: flags,
		Type: unix.RTN_UNICAST, Protocol: netlink.RouteProtocol(unix.RTPROT_BGP),
	}
}

// Single-path DEAD and LINKDOWN routes (route-level rtm_flags) are not
// imported, in either family; ONLINK alone is not an exclusion.
func TestSinglePathDeadLinkdownRoutesExcluded14950(t *testing.T) {
	withLinkNames14950(t, map[int]string{11: "wan-a"})
	for _, flags := range []int{unix.RTNH_F_DEAD, unix.RTNH_F_LINKDOWN, unix.RTNH_F_DEAD | unix.RTNH_F_LINKDOWN} {
		if got := importV4Main14950(t, singleV4_14950(t, "198.51.100.0/24", "192.0.2.1", 11, flags)); len(got) != 0 {
			t.Fatalf("flags %#x: dead/linkdown single-path route imported: %+v", flags, got)
		}
	}
	v6Dead := netlink.Route{
		Dst: mustCIDR(t, "2001:db8:1::/48"), Gw: net.ParseIP("2001:db8::1"), LinkIndex: 11,
		Flags: unix.RTNH_F_LINKDOWN, Type: unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
	}
	if got := importV6Main14950(t, v6Dead); len(got) != 0 {
		t.Fatalf("IPv6 linkdown single-path route imported: %+v", got)
	}
	// Control: ONLINK (and no dead/linkdown bit) still imports.
	got := importV4Main14950(t, singleV4_14950(t, "198.51.100.0/24", "192.0.2.1", 0, int(netlink.FLAG_ONLINK)))
	if len(got) != 1 || !reflect.DeepEqual(got[0].NextHops, []string{"192.0.2.1"}) {
		t.Fatalf("ONLINK control = %+v, want bare 192.0.2.1", got)
	}
}

// ECMP: dead/linkdown legs drop out; live legs survive with their weights
// and order. All-dead sets, and a gateway-less live leg beside a dead leg,
// behave per the all-or-nothing rule over live legs only.
func TestECMPDeadLinkdownLegsExcluded14950(t *testing.T) {
	withLinkNames14950(t, map[int]string{11: "wan-a", 12: "wan-b"})
	ecmp := netlink.Route{
		Dst: mustCIDR(t, "198.51.100.0/24"), Type: unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("192.0.2.1"), LinkIndex: 11, Hops: 0},
			{Gw: net.ParseIP("192.0.2.2"), LinkIndex: 12, Hops: 3, Flags: unix.RTNH_F_DEAD},
			{Gw: net.ParseIP("192.0.2.3"), LinkIndex: 12, Hops: 1, Flags: unix.RTNH_F_LINKDOWN},
		},
	}
	got := importV4Main14950(t, ecmp)
	if len(got) != 1 || !reflect.DeepEqual(got[0].NextHops, []string{"192.0.2.1@wan-a"}) ||
		!reflect.DeepEqual(got[0].NextHopWeights, []uint32{1}) {
		t.Fatalf("ECMP with dead legs = %+v, want only live leg 192.0.2.1@wan-a weight [1]", got)
	}

	allDead := netlink.Route{
		Dst: mustCIDR(t, "198.51.101.0/24"), Type: unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("192.0.2.1"), LinkIndex: 11, Flags: unix.RTNH_F_DEAD},
			{Gw: net.ParseIP("192.0.2.2"), LinkIndex: 12, Flags: unix.RTNH_F_LINKDOWN},
		},
	}
	if got := importV4Main14950(t, allDead); len(got) != 0 {
		t.Fatalf("all-dead ECMP imported: %+v", got)
	}

	// A gateway-less DEAD leg must not veto the live legs...
	deadGatewayless := netlink.Route{
		Dst: mustCIDR(t, "198.51.102.0/24"), Type: unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("192.0.2.1"), LinkIndex: 11},
			{Gw: nil, LinkIndex: 12, Flags: unix.RTNH_F_DEAD},
		},
	}
	if got := importV4Main14950(t, deadGatewayless); len(got) != 1 {
		t.Fatalf("ECMP with gateway-less dead leg = %+v, want the live leg imported", got)
	}
	// ...but a gateway-less LIVE leg still rejects the route whole.
	liveGatewayless := netlink.Route{
		Dst: mustCIDR(t, "198.51.103.0/24"), Type: unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("192.0.2.1"), LinkIndex: 11},
			{Gw: nil, LinkIndex: 12},
		},
	}
	if got := importV4Main14950(t, liveGatewayless); len(got) != 0 {
		t.Fatalf("ECMP with gateway-less live leg imported: %+v", got)
	}
}

// Explicit LinkIndex binding is preserved on IPv4 and global-IPv6 gateways,
// single-path and ECMP; no LinkIndex stays bare; an unresolvable binding on
// a non-link-local gateway falls back to bare instead of refusing the route.
func TestExplicitGatewayLinkIndexPreserved14950(t *testing.T) {
	withLinkNames14950(t, map[int]string{11: "wan-a", 12: "wan-b"})

	got := importV4Main14950(t, singleV4_14950(t, "198.51.100.0/24", "192.0.2.1", 12, 0))
	if len(got) != 1 || !reflect.DeepEqual(got[0].NextHops, []string{"192.0.2.1@wan-b"}) {
		t.Fatalf("IPv4 single-path = %+v, want [192.0.2.1@wan-b]", got)
	}

	v6 := netlink.Route{
		Dst: mustCIDR(t, "2001:db8:1::/48"), Gw: net.ParseIP("2001:db8::254"), LinkIndex: 11,
		Type: unix.RTN_UNICAST, Protocol: netlink.RouteProtocol(unix.RTPROT_OSPF),
	}
	if got := importV6Main14950(t, v6); len(got) != 1 || !reflect.DeepEqual(got[0].NextHops, []string{"2001:db8::254@wan-a"}) {
		t.Fatalf("global IPv6 single-path = %+v, want [2001:db8::254@wan-a]", got)
	}

	ecmp := netlink.Route{
		Dst: mustCIDR(t, "198.51.104.0/24"), Type: unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_BGP),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("192.0.2.1"), LinkIndex: 11},
			{Gw: net.ParseIP("192.0.2.2"), LinkIndex: 12},
			{Gw: net.ParseIP("192.0.2.3"), LinkIndex: 0}, // no binding: bare control
		},
	}
	got = importV4Main14950(t, ecmp)
	want := []string{"192.0.2.1@wan-a", "192.0.2.2@wan-b", "192.0.2.3"}
	if len(got) != 1 || !reflect.DeepEqual(got[0].NextHops, want) {
		t.Fatalf("ECMP bindings = %+v, want %v", got, want)
	}

	// Unresolvable LinkIndex on a global gateway: bare fallback, route kept.
	got = importV4Main14950(t, singleV4_14950(t, "198.51.105.0/24", "192.0.2.9", 999, 0))
	if len(got) != 1 || !reflect.DeepEqual(got[0].NextHops, []string{"192.0.2.9"}) {
		t.Fatalf("unresolvable binding = %+v, want bare [192.0.2.9]", got)
	}
}
