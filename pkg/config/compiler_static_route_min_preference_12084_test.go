package config

import "testing"

func assertFoldedActionPreference12084(t *testing.T, cfg *Config, destination string, want int, action func(*StaticRoute) bool) *StaticRoute {
	t.Helper()
	routes := append(append([]*StaticRoute(nil), cfg.RoutingOptions.StaticRoutes...), cfg.RoutingOptions.Inet6StaticRoutes...)
	route := compiledRouteIn(t, routes, destination)
	if route.Preference != want || !action(route) {
		t.Fatalf("folded route = %+v, want action at preference %d", route, want)
	}
	return route
}

func TestStaticRouteNextHoplessMinPreferenceRequiresForwardingAction12084(t *testing.T) {
	cases := []struct {
		name        string
		tree        *ConfigTree
		destination string
		want        int
		action      func(*StaticRoute) bool
	}{
		{
			name: "v4-discard-action-first",
			tree: hierTree(t, `routing-options { static {
				route 10.8.0.0/16 { discard; preference 250; }
				route 10.8.0.1/16 { preference 5; }
			} }`),
			destination: "10.8.0.0/16", want: 250,
			action: func(route *StaticRoute) bool { return route.Discard },
		},
		{
			name: "v4-discard-action-last",
			tree: hierTree(t, `routing-options { static {
				route 10.8.0.1/16 { preference 5; }
				route 10.8.0.0/16 { discard; preference 250; }
			} }`),
			destination: "10.8.0.1/16", want: 250,
			action: func(route *StaticRoute) bool { return route.Discard },
		},
		{
			name: "v6-bare-action-rib-preference",
			tree: hierTree(t, `routing-options {
				static { route 2001:db8:8::/48 { discard; preference 250; } }
				rib inet6.0 { static { route 2001:db8:8::/48 { preference 5; } } }
			}`),
			destination: "2001:db8:8::/48", want: 250,
			action: func(route *StaticRoute) bool { return route.Discard },
		},
		{
			name: "v6-rib-action-bare-preference",
			tree: hierTree(t, `routing-options {
				static { route 2001:db8:9::/48 { preference 5; } }
				rib inet6.0 { static { route 2001:db8:9::/48 { discard; preference 250; } } }
			}`),
			destination: "2001:db8:9::/48", want: 250,
			action: func(route *StaticRoute) bool { return route.Discard },
		},
		{
			name: "reject",
			tree: hierTree(t, `routing-options { static {
				route 10.11.0.0/16 { reject; preference 250; }
				route 10.11.0.1/16 { preference 5; }
			} }`),
			destination: "10.11.0.0/16", want: 250,
			action: func(route *StaticRoute) bool { return route.Reject },
		},
		{
			name: "next-table-helper-route-distance",
			tree: hierTree(t, `interfaces { ge-0/0/0 { unit 0; } }
			routing-instances { blue { instance-type virtual-router; } }
			routing-options { static {
				route 10.12.0.0/16 { next-table blue.inet.0; preference 250; }
				route 10.12.0.1/16 { preference 5; }
			} }`),
			destination: "10.12.0.0/16", want: 250,
			action: func(route *StaticRoute) bool { return route.NextTable == "blue" },
		},
		{
			name: "discard-keeps-action-default-over-preference-two",
			tree: hierTree(t, `routing-options { static {
				route 10.13.0.0/16 { preference 2; }
				route 10.13.0.1/16 { discard; }
			} }`),
			destination: "10.13.0.0/16", want: 5,
			action: func(route *StaticRoute) bool { return route.Discard },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := assertCommitAccepts(t, tc.tree)
			assertFoldedActionPreference12084(t, cfg, tc.destination, tc.want, tc.action)
			if !hasWarningContaining(cfg.Warnings, "#11327") {
				t.Fatalf("actionless alias warning (#11327) missing: %v", cfg.Warnings)
			}
		})
	}
}

func TestStaticRouteTolerantNoInstallOnlyAliasKeepsActionPreference12084(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "action-first",
			text: `routing-options { static { route 2001:db8:14::/48 { discard; preference 250; } }
				rib inet6.0 { static { route 2001:db8:14::/48 { no-install; } } } }`,
		},
		{
			name: "no-install-first",
			text: `routing-options { static { route 2001:db8:15::/48 { no-install; } }
				rib inet6.0 { static { route 2001:db8:15::/48 { discard; preference 250; } } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(hierTree(t, tc.text))
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			destination := "2001:db8:14::/48"
			if tc.name == "no-install-first" {
				destination = "2001:db8:15::/48"
			}
			route := assertFoldedActionPreference12084(t, cfg, destination, 250,
				func(route *StaticRoute) bool { return route.Discard && !route.NoInstall && route.noInstallConflict })
			if reason := StaticRouteExclusions(cfg)[route]; reason != "" {
				t.Fatalf("tolerant discard unexpectedly excluded: %q", reason)
			}
			if !hasWarningContaining(cfg.Warnings, "#11327") {
				t.Fatalf("no-install-only alias warning (#11327) missing: %v", cfg.Warnings)
			}
		})
	}
}
