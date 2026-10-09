package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestStaticRouteSameSpellingBlocksKeepBasePreferenceSemantics_12084(t *testing.T) {
	cases := []struct {
		name        string
		hier        string
		sets        []string
		destination string
		preference  int
		gateways    []string
	}{
		{
			name: "9125-explicit-default-last",
			hier: `routing-options { static {
				route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
				route 10.0.0.0/8 { preference 5; }
			} }`,
			destination: "10.0.0.0/8", preference: 5,
			gateways: []string{"192.0.2.1"},
		},
		{
			name: "9125-later-next-hop-inherits-prior-preference",
			hier: `routing-options { static {
				route 10.1.0.0/16 { next-hop 192.0.2.1; preference 10; }
				route 10.1.0.0/16 { next-hop 192.0.2.2; }
			} }`,
			destination: "10.1.0.0/16", preference: 10,
			gateways: []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			name: "preference-block-before-next-hop",
			hier: `routing-options { static {
				route 10.2.0.0/16 { preference 200; }
				route 10.2.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			destination: "10.2.0.0/16", preference: 200,
			gateways: []string{"192.0.2.1"},
		},
		{
			name: "preference-block-after-next-hop",
			hier: `routing-options { static {
				route 10.3.0.0/16 { next-hop 192.0.2.1; }
				route 10.3.0.0/16 { preference 200; }
			} }`,
			destination: "10.3.0.0/16", preference: 200,
			gateways: []string{"192.0.2.1"},
		},
		{
			name: "rib-inet0-plus-bare-preference",
			sets: []string{
				"set routing-options rib inet.0 static route 10.5.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.5.0.0/16 preference 200",
			},
			destination: "10.5.0.0/16", preference: 200,
			gateways: []string{"10.0.0.1"},
		},
		{
			name: "rib-inet0-plus-bare-ecmp",
			sets: []string{
				"set routing-options rib inet.0 static route 10.6.0.0/16 next-hop 10.0.0.1",
				"set routing-options rib inet.0 static route 10.6.0.0/16 preference 200",
				"set routing-options static route 10.6.0.0/16 next-hop 10.0.0.2",
			},
			destination: "10.6.0.0/16", preference: 200,
			gateways: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name: "inet6-split-block",
			hier: `routing-options { rib inet6.0 { static {
				route 2001:db8:1::/48 { next-hop 2001:db8::1; preference 200; }
				route 2001:db8:1::/48 { next-hop 2001:db8::2; }
			} } }`,
			destination: "2001:db8:1::/48", preference: 200,
			gateways: []string{"2001:db8::1", "2001:db8::2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tree *ConfigTree
			if tc.hier != "" {
				tree = hierTree(t, tc.hier)
			} else {
				tree = flatTreeFromSets(t, tc.sets...)
			}
			cfg := assertCommitAccepts(t, tree)
			routes := append(append([]*StaticRoute(nil), cfg.RoutingOptions.StaticRoutes...),
				cfg.RoutingOptions.Inet6StaticRoutes...)
			route := compiledRouteIn(t, routes, tc.destination)
			if route.Preference != tc.preference {
				t.Fatalf("route preference = %d, want base block preference %d", route.Preference, tc.preference)
			}
			if len(route.NextHops) != len(tc.gateways) {
				t.Fatalf("next-hops = %+v, want gateways %v", route.NextHops, tc.gateways)
			}
			for i, gateway := range tc.gateways {
				if route.NextHops[i].Address != gateway || route.NextHops[i].HasPreference {
					t.Fatalf("next-hop[%d] = %+v, want unqualified %s", i, route.NextHops[i], gateway)
				}
			}
			tiers := StaticRouteNextHopTiers(route)
			if len(tiers) != 1 || tiers[0].Preference != tc.preference {
				t.Fatalf("next-hop tiers = %+v, want one ECMP tier at %d", tiers, tc.preference)
			}
			var tierGateways []string
			for _, hop := range tiers[0].NextHops {
				tierGateways = append(tierGateways, hop.Address)
			}
			if !reflect.DeepEqual(tierGateways, tc.gateways) {
				t.Fatalf("tier gateways = %v, want %v", tierGateways, tc.gateways)
			}
		})
	}
}

func TestStaticRouteAliasInterleaveGroupsSameSpellingBeforeStamping_12084(t *testing.T) {
	cfg := assertCommitAccepts(t, hierTree(t, `routing-options { static {
		route 10.9.0.0/16 { next-hop 192.0.2.1; preference 10; }
		route 10.9.0.1/16 { next-hop 192.0.2.2; preference 200; }
		route 10.9.0.0/16 { next-hop 192.0.2.3; }
	} }`))
	route := compiledRouteIn(t, cfg.RoutingOptions.StaticRoutes, "10.9.0.0/16")
	if route.Preference != 200 {
		t.Fatalf("route-level preference = %d, want later distinct alias preference 200", route.Preference)
	}
	if len(route.NextHops) != 3 {
		t.Fatalf("next-hops = %+v, want all three source paths", route.NextHops)
	}
	wantHops := []struct {
		address    string
		preference int
	}{
		{"192.0.2.1", 10},
		{"192.0.2.3", 10},
		{"192.0.2.2", 200},
	}
	for i, want := range wantHops {
		if route.NextHops[i].Address != want.address ||
			!route.NextHops[i].HasPreference ||
			route.NextHops[i].Preference != want.preference {
			t.Fatalf("next-hop[%d] = %+v, want %s at %d", i, route.NextHops[i], want.address, want.preference)
		}
	}
	tiers := StaticRouteNextHopTiers(route)
	if len(tiers) != 2 || tiers[0].Preference != 10 || tiers[1].Preference != 200 {
		t.Fatalf("next-hop tiers = %+v, want source preferences 10 and 200", tiers)
	}
	var firstTier, secondTier []string
	for _, hop := range tiers[0].NextHops {
		firstTier = append(firstTier, hop.Address)
	}
	for _, hop := range tiers[1].NextHops {
		secondTier = append(secondTier, hop.Address)
	}
	if !reflect.DeepEqual(firstTier, []string{"192.0.2.1", "192.0.2.3"}) ||
		!reflect.DeepEqual(secondTier, []string{"192.0.2.2"}) {
		t.Fatalf("tier members = %v / %v, want [192.0.2.1 192.0.2.3] / [192.0.2.2]",
			firstTier, secondTier)
	}
}

func TestStaticRouteSameSpellingNoInstallStaysExcluded_12084(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
	}{
		{
			name: "hierarchical",
			tree: hierTree(t, `routing-options { static {
				route 10.0.0.0/8 { next-hop 192.0.2.1; }
				route 10.0.0.0/8 { no-install; }
			} }`),
		},
		{
			name: "rib-inet0-plus-bare",
			tree: flatTreeFromSets(t,
				"set routing-options rib inet.0 static route 10.6.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.6.0.0/16 no-install",
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := assertCommitAccepts(t, tc.tree)
			routes := append(append([]*StaticRoute(nil), cfg.RoutingOptions.StaticRoutes...),
				cfg.RoutingOptions.Inet6StaticRoutes...)
			destination := "10.0.0.0/8"
			if tc.name == "rib-inet0-plus-bare" {
				destination = "10.6.0.0/16"
			}
			route := compiledRouteIn(t, routes, destination)
			if !route.NoInstall || route.noInstallConflict {
				t.Fatalf("same-spelling no-install merge = %+v, want sticky no-install without conflict", route)
			}
			if reason := StaticRouteExclusions(cfg)[route]; reason != "route has the `no-install` option set" {
				t.Fatalf("strict no-install exclusion = %q, want explicit exclusion", reason)
			}

			lenient, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			lenientRoutes := append(append([]*StaticRoute(nil), lenient.RoutingOptions.StaticRoutes...),
				lenient.RoutingOptions.Inet6StaticRoutes...)
			lenientRoute := compiledRouteIn(t, lenientRoutes, destination)
			if !lenientRoute.NoInstall {
				t.Fatalf("tolerant no-install route became installable: %+v", lenientRoute)
			}
			if reason := StaticRouteExclusions(lenient)[lenientRoute]; reason != "route has the `no-install` option set" {
				t.Fatalf("tolerant no-install exclusion = %q, want explicit exclusion", reason)
			}
			for _, warning := range lenient.Warnings {
				if strings.Contains(warning, "install and no-install") {
					t.Fatalf("same-spelling blocks produced an install conflict warning: %v", lenient.Warnings)
				}
			}
		})
	}
}

func TestStaticRouteNextHoplessAliasKeepsMinimumPreference_12084(t *testing.T) {
	cases := []struct {
		name        string
		text        string
		destination string
	}{
		{
			name:        "minimum-first",
			destination: "10.8.0.0/16",
			text: `routing-options { static {
				route 10.8.0.0/16 { discard; preference 5; }
				route 10.8.0.1/16 { discard; preference 250; }
			} }`,
		},
		{
			name:        "minimum-last",
			destination: "10.8.0.1/16",
			text: `routing-options { static {
				route 10.8.0.1/16 { discard; preference 250; }
				route 10.8.0.0/16 { discard; preference 5; }
			} }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := assertCommitAccepts(t, hierTree(t, tc.text))
			route := compiledRouteIn(t, cfg.RoutingOptions.StaticRoutes, tc.destination)
			if !route.Discard || route.Preference != 5 || !route.HasPreference {
				t.Fatalf("merged discard route = %+v, want explicit minimum preference 5", route)
			}
		})
	}
}
