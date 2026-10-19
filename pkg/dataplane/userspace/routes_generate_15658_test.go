package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #15658: the userspace mirror of the FRR blackhole for a valid merged
// generate route — exactly one Discard snapshot for the prefix, matching
// the single `ip route <p> blackhole` line renderGenerateRoutes emits.
func TestGenerateRouteMergedSingleDiscard15658(t *testing.T) {
	origRules := ruleListFn
	t.Cleanup(func() { ruleListFn = origRules })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	withLearnedRoutes(t, fixedLearned())

	cfg := &config.Config{}
	cfg.RoutingOptions.GenerateRoutes = []*config.GenerateRoute{
		{Prefix: "10.0.0.0/8", Discard: true},
		{Prefix: "2001:db8::/32", Discard: true},
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	counts := map[string]int{}
	for _, route := range routes {
		if route.Discard && (route.Destination == "10.0.0.0/8" || route.Destination == "2001:db8::/32") {
			counts[route.Destination]++
		}
	}
	if counts["10.0.0.0/8"] != 1 || counts["2001:db8::/32"] != 1 {
		t.Fatalf("generate discard snapshots = %v, want exactly one per prefix from %+v", counts, routes)
	}
}
