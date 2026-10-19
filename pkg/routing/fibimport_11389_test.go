package routing

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func withLinkNames11389(t *testing.T, names map[int]string) {
	t.Helper()
	previous := learnedRouteLinkNameFn
	learnedRouteLinkNameFn = func(index int) (string, error) {
		if name, ok := names[index]; ok {
			return name, nil
		}
		return "", errors.New("unknown link")
	}
	t.Cleanup(func() { learnedRouteLinkNameFn = previous })
}

func importLearnedV4Routes11389(t *testing.T, routes ...netlink.Route) []LearnedRoute {
	t.Helper()
	withRouteLister(t, staticLister(v4Main(routes...)))
	got, err := ImportLearnedRoutes([]int{mainTableID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return got
}

func TestLearnedSameGatewayECMPPreservesEachInterface11389(t *testing.T) {
	withLinkNames11389(t, map[int]string{11: "wan-a", 12: "wan-b"})
	got := importLearnedV4Routes11389(t, netlink.Route{
		Dst:      mustCIDR(t, "198.51.100.0/24"),
		Type:     unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_BGP),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("192.0.2.254"), LinkIndex: 11},
			{Gw: net.ParseIP("192.0.2.254"), LinkIndex: 12},
		},
	})
	if len(got) != 1 {
		t.Fatalf("want one imported route, got %+v", got)
	}
	want := []string{"192.0.2.254@wan-a", "192.0.2.254@wan-b"}
	if !reflect.DeepEqual(got[0].NextHops, want) {
		t.Fatalf("next-hops = %v, want %v", got[0].NextHops, want)
	}
}

// Control (#14950): distinct gateways each carrying an explicit LinkIndex
// now keep that binding, exactly as the same-gateway legs above do.
func TestLearnedDistinctGatewayECMPStaysInferable11389(t *testing.T) {
	withLinkNames11389(t, map[int]string{11: "wan-a", 12: "wan-b"})
	got := importLearnedV4Routes11389(t, netlink.Route{
		Dst:      mustCIDR(t, "198.51.100.0/24"),
		Type:     unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_BGP),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("192.0.2.1"), LinkIndex: 11},
			{Gw: net.ParseIP("192.0.2.2"), LinkIndex: 12},
		},
	})
	want := []string{"192.0.2.1@wan-a", "192.0.2.2@wan-b"}
	if len(got) != 1 || !reflect.DeepEqual(got[0].NextHops, want) {
		t.Fatalf("distinct gateways = %+v, want %v", got, want)
	}
}

// #14950 changed the unresolvable-binding rule for NON-link-local gateways:
// the leg falls back to the bare gateway instead of dropping the route (a
// scope-less link-local leg still refuses whole — see the 9512 cells).
// The resolvable leg keeps its binding; the unresolvable one goes bare.
func TestLearnedAmbiguousECMPWithoutNamedInterfaceIsDropped11389(t *testing.T) {
	withLinkNames11389(t, map[int]string{11: "wan-a"})
	got := importLearnedV4Routes11389(t, netlink.Route{
		Dst:      mustCIDR(t, "198.51.100.0/24"),
		Type:     unix.RTN_UNICAST,
		Protocol: netlink.RouteProtocol(unix.RTPROT_BGP),
		MultiPath: []*netlink.NexthopInfo{
			{Gw: net.ParseIP("192.0.2.254"), LinkIndex: 11},
			{Gw: net.ParseIP("192.0.2.254"), LinkIndex: 12},
		},
	})
	want := []string{"192.0.2.254@wan-a", "192.0.2.254"}
	if len(got) != 1 || !reflect.DeepEqual(got[0].NextHops, want) {
		t.Fatalf("ambiguous ECMP with one unnamed interface = %+v, want %v (bare fallback, #14950)", got, want)
	}
}
