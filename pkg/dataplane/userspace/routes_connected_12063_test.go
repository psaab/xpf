package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

func TestBuildRouteSnapshotsDoesNotCoverPrefixWithoutIfindex12063(t *testing.T) {
	oldRules, oldImport := ruleListFn, learnedRouteImportFn
	t.Cleanup(func() {
		ruleListFn, learnedRouteImportFn = oldRules, oldImport
	})
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	learnedRouteImportFn = func([]int) ([]routing.LearnedRoute, error) {
		return []routing.LearnedRoute{{
			TableID:     learnedRouteMainTableID,
			Family:      netlink.FAMILY_V4,
			Destination: "10.77.0.0/24",
			NextHops:    []string{"192.0.2.1"},
		}}, nil
	}
	linkDown := false

	routes, _, err := buildRouteSnapshots(&config.Config{}, []InterfaceSnapshot{
		{
			Name:    "ge-0/0/77",
			Ifindex: 0,
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "10.77.0.1/24",
				Scope:   int(netlink.SCOPE_UNIVERSE),
			}},
		},
		{
			Name:    "ge-0/0/78",
			Ifindex: 78,
			LinkUp:  &linkDown,
			Addresses: []InterfaceAddressSnapshot{{
				Family:  "inet",
				Address: "10.78.0.1/24",
				Scope:   int(netlink.SCOPE_UNIVERSE),
			}},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	var learnedGap, presentLinkConnected bool
	for _, route := range routes {
		switch route.Destination {
		case "10.77.0.0/24":
			learnedGap = len(route.NextHops) == 1 && route.NextHops[0] == "192.0.2.1"
		case "10.78.0.0/24":
			presentLinkConnected = !route.Discard && len(route.NextHops) == 0
		}
	}
	if !learnedGap {
		t.Fatalf("routes = %+v, want learned 10.77.0.0/24 route with next-hop 192.0.2.1; absent interface must not cover the prefix", routes)
	}
	if !presentLinkConnected {
		t.Fatalf("routes = %+v, want the connected route for present but link-down 10.78.0.0/24", routes)
	}
}
