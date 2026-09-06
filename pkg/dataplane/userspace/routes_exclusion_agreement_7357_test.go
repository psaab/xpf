package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7357: the builder and the show surfaces must not disagree about which static
// routes are installed.
//
// This is the assertion the single-sourcing exists to make true, and it is
// stronger than testing either side alone: a route
// config.StaticRouteExclusions marks excluded must be ABSENT from
// buildRouteSnapshots' output, and a route it does not mark must be PRESENT.
// Both directions, because either alone is satisfiable by a degenerate
// implementation — always-exclude passes the first, always-publish the second.
func TestStaticRouteExclusionsAgreeWithTheBuilder_7357(t *testing.T) {
	installed := &config.StaticRoute{Destination: "10.1.0.0/16", NextTable: "vrf-a"}
	undefinedTarget := &config.StaticRoute{Destination: "10.2.0.0/16", NextTable: "ghost"}
	badCIDR := &config.StaticRoute{Destination: "not-a-cidr", NextTable: "vrf-a"}
	plain := &config.StaticRoute{
		Destination: "10.3.0.0/16",
		NextHops:    []config.NextHopEntry{{Address: "10.0.0.1"}},
	}
	perInstance := &config.StaticRoute{Destination: "10.4.0.0/16", NextTable: "vrf-a"}

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{installed, undefinedTarget, badCIDR, plain}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "vrf-a", StaticRoutes: []*config.StaticRoute{perInstance}},
	}

	excl := config.StaticRouteExclusions(cfg)

	// Fixture premise: the population must contain BOTH excluded and installed
	// routes, or one of the two directions below is vacuous.
	if len(excl) == 0 {
		t.Fatal("no route was excluded; this cell cannot see a disagreement")
	}
	if excl[installed] != "" || excl[plain] != "" {
		t.Fatalf("the control routes are excluded (installed=%q plain=%q); with nothing "+
			"installed the present-direction assertion below proves nothing",
			excl[installed], excl[plain])
	}

	snaps, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots() error = %v", err)
	}
	published := make(map[string]bool, len(snaps))
	for _, s := range snaps {
		published[s.Table+"|"+s.Destination] = true
	}

	for _, tc := range []struct {
		name  string
		sr    *config.StaticRoute
		table string
	}{
		{"installed global next-table", installed, "inet.0"},
		{"plain next-hop", plain, "inet.0"},
		{"undefined target", undefinedTarget, "inet.0"},
		{"unparseable destination", badCIDR, "inet.0"},
		{"per-instance next-table", perInstance, "vrf-a.inet.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.table + "|" + tc.sr.Destination
			reason := excl[tc.sr]
			switch {
			case reason != "" && published[key]:
				t.Errorf("the predicate says NOT INSTALLED (%q) but the builder PUBLISHED %s — "+
					"the renderer would annotate a route that is live", reason, key)
			case reason == "" && !published[key]:
				t.Errorf("the predicate says installed but the builder DROPPED %s — the "+
					"renderer would print it as live when it is not, which is the whole "+
					"defect #7357 is about", key)
			}
		})
	}
}

// The window half of the same agreement, kept separate because it needs a
// 100+-route fixture and its failure mode is different: an off-by-one here
// makes exactly one route disagree.
func TestStaticRouteWindowExclusionsAgreeWithTheBuilder_7357(t *testing.T) {
	var global []*config.StaticRoute
	for i := 0; i <= config.NextTableRuleWindow; i++ {
		// Distinct destinations so the published-set lookup is per route.
		global = append(global, &config.StaticRoute{
			Destination: destForIndex7357(i),
			NextTable:   "vrf-a",
		})
	}
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = global
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "vrf-a"}}

	excl := config.StaticRouteExclusions(cfg)
	snaps, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots() error = %v", err)
	}
	published := make(map[string]bool, len(snaps))
	for _, s := range snaps {
		published[s.Destination] = true
	}

	var disagreements []string
	for i, sr := range global {
		reason := excl[sr]
		if (reason != "") == published[sr.Destination] {
			disagreements = append(disagreements,
				sr.Destination+" (index "+itoa7357(i)+", reason="+reason+")")
		}
	}
	if len(disagreements) > 0 {
		t.Errorf("%d route(s) where the window predicate and the builder disagree:\n  %s",
			len(disagreements), strings.Join(disagreements, "\n  "))
	}
	// Non-vacuity: the fixture must actually cross the window, or every route
	// agrees trivially by being published.
	if !published[global[0].Destination] {
		t.Fatal("the first route was not published; the fixture never exercised the window")
	}
	if published[global[len(global)-1].Destination] {
		t.Fatalf("the route past the %d-entry window was published; the fixture did not "+
			"cross the boundary this cell exists to check", config.NextTableRuleWindow)
	}
}

func destForIndex7357(i int) string {
	return "10." + itoa7357(i/256) + "." + itoa7357(i%256) + ".0/24"
}

func itoa7357(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
