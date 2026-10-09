package config

import (
	"strings"
	"testing"
)

func compiledRouteIn(t *testing.T, routes []*StaticRoute, destination string) *StaticRoute {
	t.Helper()
	for _, route := range routes {
		if route != nil && route.Destination == destination {
			return route
		}
	}
	t.Fatalf("route %q not found in %+v", destination, routes)
	return nil
}

func TestStaticRouteFoldPreservesPreferenceTiers_12084(t *testing.T) {
	for _, tc := range []struct {
		name        string
		sets        []string
		destination string
		inet6       bool
		gateways    []string
	}{
		{
			name: "cross-rib-floating-static",
			sets: []string{
				"set routing-options static route 2001:db8:1::/48 next-hop 2001:db8::1",
				"set routing-options static route 2001:db8:1::/48 preference 5",
				"set routing-options rib inet6.0 static route 2001:db8:1::/48 next-hop 2001:db8::2",
				"set routing-options rib inet6.0 static route 2001:db8:1::/48 preference 200",
			},
			destination: "2001:db8:1::/48",
			inet6:       true,
			gateways:    []string{"2001:db8::1", "2001:db8::2"},
		},
		{
			name: "same-list-alias-floating-static",
			sets: []string{
				"set routing-options static route 10.2.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.2.0.0/16 preference 5",
				"set routing-options static route 10.2.0.1/16 next-hop 10.0.0.2",
				"set routing-options static route 10.2.0.1/16 preference 200",
			},
			destination: "10.2.0.0/16",
			gateways:    []string{"10.0.0.1", "10.0.0.2"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := assertCommitAccepts(t, flatTreeFromSets(t, tc.sets...))
			routes := cfg.RoutingOptions.StaticRoutes
			if tc.inet6 {
				if len(routes) != 0 || len(cfg.RoutingOptions.Inet6StaticRoutes) != 1 {
					t.Fatalf("cross-family collection sizes = static %d, inet6 %d; want 0, 1",
						len(routes), len(cfg.RoutingOptions.Inet6StaticRoutes))
				}
				routes = cfg.RoutingOptions.Inet6StaticRoutes
			}
			route := compiledRouteIn(t, routes, tc.destination)
			if len(route.NextHops) != 2 {
				t.Fatalf("next-hops = %+v, want two independently preferred paths", route.NextHops)
			}
			for i, wantPreference := range []int{5, 200} {
				if route.NextHops[i].Address != tc.gateways[i] ||
					!route.NextHops[i].HasPreference || route.NextHops[i].Preference != wantPreference {
					t.Fatalf("next-hop[%d] = %+v, want %s at preference %d",
						i, route.NextHops[i], tc.gateways[i], wantPreference)
				}
			}
			tiers := StaticRouteNextHopTiers(route)
			if len(tiers) != 2 || tiers[0].Preference != 5 || tiers[1].Preference != 200 {
				t.Fatalf("next-hop tiers = %+v, want separate preference tiers 5 and 200", tiers)
			}
		})
	}
}

func TestStaticRouteNoInstallDisagreementRejectsAndKeepsInstalledTolerant_12084(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route 2001:db8:2::/48 next-hop 2001:db8::1",
		"set routing-options rib inet6.0 static route 2001:db8:2::/48 next-hop 2001:db8::1 no-install",
	)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "install and no-install") {
		t.Fatalf("strict compile error = %v, want install/no-install conflict", err)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		foundWarning = foundWarning || strings.Contains(warning, "install and no-install")
	}
	if !foundWarning {
		t.Fatalf("tolerant compile did not warn about conflicting install intent: %v", cfg.Warnings)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 0 || len(cfg.RoutingOptions.Inet6StaticRoutes) != 1 {
		t.Fatalf("route collection sizes = static %d, inet6 %d; want installed v6 survivor",
			len(cfg.RoutingOptions.StaticRoutes), len(cfg.RoutingOptions.Inet6StaticRoutes))
	}
	route := cfg.RoutingOptions.Inet6StaticRoutes[0]
	if route.NoInstall || len(route.NextHops) == 0 {
		t.Fatalf("tolerant route silently withdrew installed intent: %+v", route)
	}
	if reason := StaticRouteExcludedReason(route, false, nil); reason != "" {
		t.Fatalf("tolerant installed route excluded: %q", reason)
	}
}

func TestStaticRouteCompetingNextTableTargetsRejectAcrossFoldShapes_12084(t *testing.T) {
	cases := []struct {
		name string
		sets []string
	}{
		{
			name: "masked-aliases-reversed-order",
			sets: []string{
				"set routing-instances aaa instance-type virtual-router",
				"set routing-instances zzz instance-type virtual-router",
				"set interfaces ge-0/0/0 unit 0",
				"set routing-options static route 172.16.9.9/12 next-table zzz.inet.0",
				"set routing-options static route 172.16.0.0/12 next-table aaa.inet.0",
			},
		},
		{
			name: "masked-aliases-with-cross-rib-middle",
			sets: []string{
				"set routing-instances aaa instance-type virtual-router",
				"set routing-instances zzz instance-type virtual-router",
				"set interfaces ge-0/0/0 unit 0",
				"set routing-options static route 2001:db8::/32 next-table aaa.inet6.0",
				"set routing-options static route 2001:DB8::/32 next-table zzz.inet6.0",
				"set routing-options rib inet6.0 static route 2001:db8:0::/32 next-table zzz.inet6.0",
			},
		},
		{
			name: "masked-aliases-without-middle",
			sets: []string{
				"set routing-instances aaa instance-type virtual-router",
				"set routing-instances zzz instance-type virtual-router",
				"set interfaces ge-0/0/0 unit 0",
				"set routing-options static route 2001:db8::/32 next-table aaa.inet6.0",
				"set routing-options rib inet6.0 static route 2001:db8:0::/32 next-table zzz.inet6.0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.sets...)
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), "competing next-table targets") {
				t.Fatalf("strict compile error = %v, want competing-target rejection", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				foundWarning = foundWarning || strings.Contains(warning, "competing next-table targets")
			}
			if !foundWarning {
				t.Fatalf("tolerant compile did not warn about competing targets: %v", cfg.Warnings)
			}
		})
	}
}

func TestStaticRouteIdentityZeroPaddedMaskStillFolds_12084(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-options static route 10.9.0.0/016 discard",
		"set routing-options static route 10.9.3.1/16 next-hop 10.0.0.1",
	)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "contradictory dispositions") {
		t.Fatalf("zero-padded alias error = %v, want folded disposition conflict", err)
	}
}
