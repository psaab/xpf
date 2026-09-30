package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11327: the helper FIB must omit a static route that FRR cannot install, so
// the valid less-specific route remains eligible under either default policy.
func TestZeroDispositionStaticFallsThroughUnderBothDefaultPolicies_11327(t *testing.T) {
	for _, tc := range []struct {
		name          string
		defaultPolicy config.PolicyAction
	}{
		{name: "deny-default", defaultPolicy: config.PolicyDeny},
		{name: "permit-default", defaultPolicy: config.PolicyPermit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zero := &config.StaticRoute{Destination: "10.1.0.0/24", NextHops: []config.NextHopEntry{{}}}
			fallback := &config.StaticRoute{
				Destination: "0.0.0.0/0",
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.1"}},
			}
			cfg := &config.Config{}
			cfg.Security.DefaultPolicy = tc.defaultPolicy
			cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{zero, fallback}

			if got := config.StaticRouteExclusions(cfg)[zero]; got == "" {
				t.Fatal("zero-disposition /24 has no exclusion reason; it would shadow the /0 in the helper FIB")
			}
			if got := config.StaticRouteExclusions(cfg)[fallback]; got != "" {
				t.Fatalf("installable /0 excluded: %q", got)
			}

			snapshots, _, err := buildRouteSnapshots(cfg, nil, nil)
			if err != nil {
				t.Fatalf("buildRouteSnapshots: %v", err)
			}
			var sawZero, sawFallback bool
			for _, route := range snapshots {
				if route.Destination == zero.Destination && route.Table == "inet.0" {
					sawZero = true
				}
				if route.Destination == fallback.Destination && route.Table == "inet.0" {
					sawFallback = true
					if len(route.NextHops) != 1 || route.NextHops[0] != "192.0.2.1" {
						t.Errorf("fallback snapshot next-hops = %v, want [192.0.2.1]", route.NextHops)
					}
				}
			}
			if sawZero {
				t.Errorf("zero-disposition /24 was published and would shadow FRR's /0 under %s", tc.name)
			}
			if !sawFallback {
				t.Errorf("valid less-specific /0 was not published under %s", tc.name)
			}
		})
	}
}
