package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10000: the builder-agreement half for ordinary routes. A route
// config.StaticRouteExclusions marks excluded must be ABSENT from
// buildRouteSnapshots' output, and a route it does not mark must be PRESENT —
// the same both-directions contract as
// TestStaticRouteExclusionsAgreeWithTheBuilder_7357, extended to unusable
// ordinary destinations.
//
// FAIL-ON-REVERT: restore the blanket `if sr.NextTable == "" { return "" }`
// in StaticRouteExcludedReason and the excluded population below is empty,
// tripping the fixture premise.
func TestStaticRouteOrdinaryExclusionsAgreeWithTheBuilder_10000(t *testing.T) {
	unusableDefault := &config.StaticRoute{Destination: "default", Discard: true}
	unusableGarbage := &config.StaticRoute{
		Destination: "not-a-prefix",
		NextHops:    []config.NextHopEntry{{Address: "10.0.0.1"}},
	}
	usableCIDR := &config.StaticRoute{Destination: "10.9.0.0/16", Discard: true}
	usableBare := &config.StaticRoute{Destination: "10.0.0.1", Discard: true}
	instanceDefault := &config.StaticRoute{Destination: "default", Discard: true}

	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{unusableDefault, unusableGarbage, usableCIDR, usableBare}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "vrf-a", StaticRoutes: []*config.StaticRoute{instanceDefault}},
	}

	excl := config.StaticRouteExclusions(cfg)

	// Fixture premise: the population must contain BOTH excluded and installed
	// routes, or one of the two directions below is vacuous.
	excluded := []*config.StaticRoute{unusableDefault, unusableGarbage, instanceDefault}
	installed := map[*config.StaticRoute]string{
		usableCIDR: "inet.0|10.9.0.0/16",
		// A bare host is normalised to its /32 host prefix on the wire (#6568).
		usableBare: "inet.0|10.0.0.1/32",
	}
	for _, sr := range excluded {
		if excl[sr] == "" {
			t.Fatalf("fixture premise: %q must be excluded, got no reason", sr.Destination)
		}
	}
	for sr := range installed {
		if reason := excl[sr]; reason != "" {
			t.Fatalf("fixture premise: %q must be installed, got reason %q", sr.Destination, reason)
		}
	}

	snaps, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots() error = %v", err)
	}
	published := make(map[string]bool, len(snaps))
	for _, s := range snaps {
		published[s.Table+"|"+s.Destination] = true
	}

	// Excluded, in exactly the verdict's sense: the raw unusable destination
	// must not appear on the wire in ANY table.
	for _, sr := range excluded {
		for _, s := range snaps {
			if s.Destination == sr.Destination {
				t.Errorf("excluded route %q reached the wire: %+v", sr.Destination, s)
			}
		}
	}
	for sr, wantKey := range installed {
		if !published[wantKey] {
			t.Errorf("installed route %q missing from the wire (want key %q): %+v",
				sr.Destination, wantKey, snaps)
		}
	}
}
