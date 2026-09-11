package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #9512 at the publish boundary: a scoped link-local learned next hop reaches
// the helper snapshot verbatim, in the `gateway@interface` form the helper
// parses, and two routes with the same gateway on different links keep their
// own scope.
func TestScopedLinkLocalLearnedNextHopReachesTheSnapshot9512(t *testing.T) {
	withLearnedRoutes(t, fixedLearned(
		routing.LearnedRoute{TableID: 254, Family: netlink.FAMILY_V6,
			Destination: "2001:db8:beef::/48", NextHops: []string{"fe80::254@ge-0-0-2"}, Protocol: "ospf"},
		routing.LearnedRoute{TableID: 254, Family: netlink.FAMILY_V6,
			Destination: "2001:db8:cafe::/48", NextHops: []string{"fe80::254@ge-0-0-1"}, Protocol: "ospf"},
	))
	out, _, err := buildRouteSnapshots(&config.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for dst, want := range map[string][]string{
		"2001:db8:beef::/48": {"fe80::254@ge-0-0-2"},
		"2001:db8:cafe::/48": {"fe80::254@ge-0-0-1"},
	} {
		hits := snapshotFor(t, "inet6.0", "inet6", dst, out)
		if len(hits) != 1 || !reflect.DeepEqual(hits[0].NextHops, want) {
			t.Errorf("%s: snapshots %+v, want one with next hops %v", dst, hits, want)
		}
	}
}
