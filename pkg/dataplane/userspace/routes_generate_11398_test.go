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

// #15742: the split-RG shape. The config default (pref 5, via the WAN
// gateway) stays in the snapshot on BOTH nodes — buildRouteSnapshots
// does not HA-filter — and the cluster-mode unreachable default arrives
// only via the kernel import (RTN_UNREACHABLE metric 20, imported at
// the fixed preference 200). The helper FIB must carry BOTH rows for
// the default prefix, forwarding (5) ahead of reject (200), so the
// Rust preference tie-break forwards when the egress RG is locally
// owned and terminates on the reject when HA enforcement demotes the
// forwarding row. Before the fix the reject row never existed and the
// demoted lookup had no terminal default at all.
// FAIL-ON-REVERT: drop the Reject mapping in addLearnedRouteSnapshots
// (or the RTN_UNREACHABLE adoption in the importer) and the reject row
// vanishes.
func TestLearnedClusterRejectCoexistsWithConfigDefault15742(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned(routing.LearnedRoute{
		TableID:     254,
		Family:      netlink.FAMILY_V4,
		Destination: "0.0.0.0/0",
		Protocol:    "static",
		Reject:      true,
	}))

	cfg := &config.Config{}
	// Preference 5 is the compiler's static default (compiler_routing.go);
	// the raw fixture must carry it explicitly or it reads as 0 — the
	// most-preferred value — and suppresses the imported row.
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "0.0.0.0/0",
		Preference:  5,
		NextHops:    []config.NextHopEntry{{Address: "198.51.100.1"}},
	}}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var defaults []RouteSnapshot
	for _, r := range routes {
		if r.Table == "inet.0" && r.Family == "inet" && r.Destination == "0.0.0.0/0" && r.NextTable == "" {
			defaults = append(defaults, r)
		}
	}
	if len(defaults) != 2 {
		t.Fatalf("want config default + imported cluster reject, got %d defaults: %+v (all routes %+v)", len(defaults), defaults, routes)
	}
	// Sorted by preference: forwarding default (5) first, reject (200) last.
	fwd, rej := defaults[0], defaults[1]
	if fwd.Reject || fwd.Discard || len(fwd.NextHops) != 1 || fwd.NextHops[0] != "198.51.100.1" {
		t.Fatalf("first default = %+v, want the forwarding config default", fwd)
	}
	if !rej.Reject || rej.Discard || len(rej.NextHops) != 0 {
		t.Fatalf("second default = %+v, want the imported cluster reject with no next hops", rej)
	}
	if !(fwd.Preference < rej.Preference) {
		t.Fatalf("preferences fwd=%d rej=%d, want forwarding strictly preferred so the reject only terminates a demoted lookup", fwd.Preference, rej.Preference)
	}
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

func TestGenerateRoutePolicyNotSnapshotted11456(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	cfg := &config.Config{}
	cfg.RoutingOptions.GenerateRoutes = []*config.GenerateRoute{
		{Prefix: "10.0.0.0/8"},
		{Prefix: "198.51.100.0/24", Policy: "contributors"},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}

	var unconditionalFound, policyFound bool
	for _, route := range routes {
		if route.Table != "inet.0" {
			continue
		}
		switch route.Destination {
		case "10.0.0.0/8":
			unconditionalFound = route.Discard
		case "198.51.100.0/24":
			policyFound = true
		}
	}
	if !unconditionalFound {
		t.Fatal("policy-less generate route must retain its established discard snapshot")
	}
	if policyFound {
		t.Fatal("policy-bearing generate route must not be installed without a verified contributor")
	}
}
