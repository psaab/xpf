package config

import (
	"strings"
	"testing"
)

// #7357 items 3-5: the SUBSTANCE tests for the shared static-route drop
// predicate. The builder (buildRouteSnapshots) and the `show routing-options` /
// `show routing-instances` renderers both consult this, so what it decides is
// the contract between them.

func srExclCfg7357(global, globalV6 []*StaticRoute, instances []*RoutingInstanceConfig) *Config {
	cfg := &Config{}
	// #9810: one unclaimed unit (N=1) so each leak costs one slot, as the window boundary below assumes.
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingOptions.StaticRoutes = global
	cfg.RoutingOptions.Inet6StaticRoutes = globalV6
	cfg.RoutingInstances = instances
	return cfg
}

func TestStaticRouteExcludedReasonPerRouteCauses_7357(t *testing.T) {
	defined := map[string]struct{}{"vrf-a": {}}

	for _, tc := range []struct {
		name        string
		sr          *StaticRoute
		perInstance bool
		wantSubstr  string // "" means MUST NOT be excluded
	}{
		{
			name:       "eligible global next-table is NOT excluded",
			sr:         &StaticRoute{Destination: "10.0.0.0/8", NextTable: "vrf-a"},
			wantSubstr: "",
		},
		{
			// The control that stops an unconditional "excluded" from passing
			// every other row: an ordinary next-hop route has no next-table and
			// is never this predicate's business.
			name:       "plain next-hop route is NOT excluded",
			sr:         &StaticRoute{Destination: "10.1.0.0/16", NextHops: []NextHopEntry{{Address: "10.0.0.1"}}},
			wantSubstr: "",
		},
		{
			name:       "undefined target instance",
			sr:         &StaticRoute{Destination: "10.0.0.0/8", NextTable: "nope"},
			wantSubstr: "not defined",
		},
		{
			name:       "unparseable destination",
			sr:         &StaticRoute{Destination: "not-a-cidr", NextTable: "vrf-a"},
			wantSubstr: "does not parse",
		},
		{
			name:        "per-instance next-table is never programmed",
			sr:          &StaticRoute{Destination: "10.0.0.0/8", NextTable: "vrf-a"},
			perInstance: true,
			wantSubstr:  "not supported under a routing-instance",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := StaticRouteExcludedReason(tc.sr, tc.perInstance, defined)
			if tc.wantSubstr == "" {
				if got != "" {
					t.Fatalf("StaticRouteExcludedReason = %q, want \"\" — this route IS installed, "+
						"and annotating it would tell the operator a live route is dead", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSubstr) {
				t.Fatalf("StaticRouteExcludedReason = %q, want a reason containing %q", got, tc.wantSubstr)
			}
		})
	}
}

// The ORDER-DEPENDENT row. NextTableRuleWindow eligible global leaks fit; the
// next one does not, and the verdict depends on how many preceded it — which is
// exactly why this cannot be a per-route call.
func TestStaticRouteExclusionsBoundsTheNextTableWindow_7357(t *testing.T) {
	var global []*StaticRoute
	for i := 0; i < NextTableRuleWindow+2; i++ {
		global = append(global, &StaticRoute{
			Destination: "10.0.0.0/8",
			NextTable:   "vrf-a",
		})
	}
	cfg := srExclCfg7357(global, nil, []*RoutingInstanceConfig{{Name: "vrf-a"}})

	excl := StaticRouteExclusions(cfg)

	// The first NextTableRuleWindow are installed...
	for i := 0; i < NextTableRuleWindow; i++ {
		if reason := excl[global[i]]; reason != "" {
			t.Fatalf("route %d of %d is within the window but was excluded: %q",
				i, NextTableRuleWindow, reason)
		}
	}
	// ...and everything past it is not. Two beyond, not one, so an off-by-one
	// that excluded only the last would still red.
	for i := NextTableRuleWindow; i < len(global); i++ {
		if reason := excl[global[i]]; !strings.Contains(reason, "window") {
			t.Errorf("route %d is beyond the %d-entry window but reason = %q, want a window reason",
				i, NextTableRuleWindow, reason)
		}
	}
}

// The window counter must advance ONLY on the global path. A per-instance
// next-table consumes no ip-rule slot, so it must not push a global route out
// of the window — if it did, the renderer and the builder would still agree
// (both use this), but both would be wrong about the kernel.
func TestStaticRouteExclusionsWindowIgnoresPerInstanceRoutes_7357(t *testing.T) {
	var global []*StaticRoute
	for i := 0; i < NextTableRuleWindow; i++ {
		global = append(global, &StaticRoute{Destination: "10.0.0.0/8", NextTable: "vrf-a"})
	}
	var perInst []*StaticRoute
	for i := 0; i < 10; i++ {
		perInst = append(perInst, &StaticRoute{Destination: "10.0.0.0/8", NextTable: "vrf-a"})
	}
	cfg := srExclCfg7357(global, nil, []*RoutingInstanceConfig{
		{Name: "vrf-a", StaticRoutes: perInst},
	})

	excl := StaticRouteExclusions(cfg)

	for i, sr := range global {
		if reason := excl[sr]; reason != "" {
			t.Fatalf("global route %d was excluded (%q) — the %d per-instance next-table "+
				"routes must consume no ip-rule window slots", i, reason, len(perInst))
		}
	}
	// And every per-instance one is excluded for its own reason, not the window.
	for i, sr := range perInst {
		if reason := excl[sr]; !strings.Contains(reason, "not supported under a routing-instance") {
			t.Errorf("per-instance route %d reason = %q, want the per-instance reason", i, reason)
		}
	}
}
