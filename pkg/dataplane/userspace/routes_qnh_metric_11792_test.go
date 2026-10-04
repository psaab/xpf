package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// Equal-preference statics lower into ordered metric rows. Equal-metric
// next-hops stay together in one ECMP row, and a distinct authored preference
// remains unchanged. RED-on-revert: ignoring Metric collapses the first two
// tiers into one ECMP row.
func TestQualifiedNextHopMetricOrdersEqualPreference_11792(t *testing.T) {
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "198.51.100.0/24",
		Preference:  5,
		NextHops: []config.NextHopEntry{
			{Address: "192.0.2.1"}, // Unqualified default metric 0: primary.
			{Address: "192.0.2.2", Metric: 10, HasMetric: true},
			{Address: "192.0.2.3", Metric: 10, HasMetric: true},
			{Address: "192.0.2.4", Preference: 6, HasPreference: true},
		},
	}}

	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var matches []RouteSnapshot
	for _, route := range routes {
		if route.Destination == "198.51.100.0/24" {
			matches = append(matches, route)
		}
	}
	if len(matches) != 3 {
		t.Fatalf("route tiers = %+v, want two preference-5 metric rows and one preference-6 row", matches)
	}
	want := []struct {
		preference int
		nextHops   []string
	}{
		{5, []string{"192.0.2.1"}},
		{5, []string{"192.0.2.2", "192.0.2.3"}},
		{6, []string{"192.0.2.4"}},
	}
	for i, route := range matches {
		if route.Preference != want[i].preference {
			t.Errorf("tier %d preference = %d, want %d", i, route.Preference, want[i].preference)
		}
		if len(route.NextHops) != len(want[i].nextHops) {
			t.Errorf("tier %d next-hops = %v, want %v", i, route.NextHops, want[i].nextHops)
			continue
		}
		for j := range route.NextHops {
			if route.NextHops[j] != want[i].nextHops[j] {
				t.Errorf("tier %d next-hops = %v, want %v", i, route.NextHops, want[i].nextHops)
				break
			}
		}
	}
}
