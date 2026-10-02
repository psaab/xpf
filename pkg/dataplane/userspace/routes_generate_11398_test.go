package userspace

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

func TestGenerateRouteDiscardBeatsDefault11398(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0",
		NextHops:    []config.NextHopEntry{{Address: "198.51.100.1"}},
	}}
	cfg.RoutingOptions.GenerateRoutes = []*config.GenerateRoute{{Prefix: "10.0.0.0/8"}}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	assertGeneratedLPM11398(t, routes)
}

func TestLearnedBlackholeDiscardBeatsDefault11398(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned(routing.LearnedRoute{
		TableID:     254,
		Family:      netlink.FAMILY_V4,
		Destination: "10.0.0.0/8",
		Protocol:    "static",
		Discard:     true,
	}))

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0",
		NextHops:    []config.NextHopEntry{{Address: "198.51.100.1"}},
	}}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	assertGeneratedLPM11398(t, routes)
}

func assertGeneratedLPM11398(t *testing.T, routes []RouteSnapshot) {
	t.Helper()
	inside := lookupIPv4Snapshot11398(t, routes, "10.9.9.9")
	if inside.Destination != "10.0.0.0/8" || !inside.Discard || len(inside.NextHops) != 0 {
		t.Fatalf("10.9.9.9 selected %+v; want the /8 discard", inside)
	}
	outside := lookupIPv4Snapshot11398(t, routes, "192.0.2.9")
	if outside.Destination != "0.0.0.0/0" || outside.Discard || len(outside.NextHops) != 1 ||
		outside.NextHops[0] != "198.51.100.1" {
		t.Fatalf("192.0.2.9 selected %+v; want the forwarding default", outside)
	}
}

func lookupIPv4Snapshot11398(t *testing.T, routes []RouteSnapshot, destination string) RouteSnapshot {
	t.Helper()
	ip := net.ParseIP(destination).To4()
	if ip == nil {
		t.Fatalf("invalid test IPv4 destination %q", destination)
	}
	bestPrefix := -1
	var best RouteSnapshot
	for _, route := range routes {
		if route.Table != "inet.0" || route.Family != "inet" || route.NextTable != "" {
			continue
		}
		_, network, err := net.ParseCIDR(route.Destination)
		if err != nil {
			t.Fatalf("invalid snapshot destination %q: %v", route.Destination, err)
		}
		if !network.Contains(ip) {
			continue
		}
		prefix, _ := network.Mask.Size()
		if prefix > bestPrefix {
			bestPrefix = prefix
			best = route
		}
	}
	if bestPrefix < 0 {
		t.Fatalf("no route selected for %s from %+v", destination, routes)
	}
	return best
}
