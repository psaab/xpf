package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileFoldConfig(t *testing.T, lenient bool, sets ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, set := range sets {
		path, err := config.ParseSetCommand(set)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", set, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", set, err)
		}
	}
	var (
		cfg *config.Config
		err error
	)
	if lenient {
		cfg, err = config.CompileConfigLenient(tree)
	} else {
		cfg, err = config.CompileConfig(tree)
	}
	if err != nil {
		t.Fatalf("compile static-route fixture: %v", err)
	}
	return cfg
}

func routeFromFoldConfig(t *testing.T, cfg *config.Config, destination string) *config.StaticRoute {
	t.Helper()
	for _, routes := range [][]*config.StaticRoute{
		cfg.RoutingOptions.StaticRoutes,
		cfg.RoutingOptions.Inet6StaticRoutes,
	} {
		for _, route := range routes {
			if route != nil && route.Destination == destination {
				return route
			}
		}
	}
	t.Fatalf("route %q not found", destination)
	return nil
}

func TestFRRStaticRouteFoldKeepsPerSourcePreference_12084(t *testing.T) {
	cases := []struct {
		name        string
		sets        []string
		destination string
		want        []string
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
			want: []string{
				"ipv6 route 2001:db8:1::/48 2001:db8::1 5\n",
				"ipv6 route 2001:db8:1::/48 2001:db8::2 200\n",
			},
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
			want: []string{
				"ip route 10.2.0.0/16 10.0.0.1 5\n",
				"ip route 10.2.0.0/16 10.0.0.2 200\n",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileFoldConfig(t, false, tc.sets...)
			got := New().generateStaticRoute(routeFromFoldConfig(t, cfg, tc.destination), "", nil, nil, nil)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("rendered route %q missing expected distance row %q", got, want)
				}
			}
		})
	}
}

func TestFRRNoInstallConflictTolerantFoldKeepsInstalledRoute_12084(t *testing.T) {
	cfg := compileFoldConfig(t, true,
		"set routing-options static route 2001:db8:2::/48 next-hop 2001:db8::1",
		"set routing-options rib inet6.0 static route 2001:db8:2::/48 next-hop 2001:db8::1 no-install",
	)
	route := routeFromFoldConfig(t, cfg, "2001:db8:2::/48")
	if route.NoInstall {
		t.Fatalf("tolerant merged route retained sticky no-install: %+v", route)
	}
	got := New().generateStaticRoute(route, "", nil, nil, nil)
	if !strings.Contains(got, "ipv6 route 2001:db8:2::/48 2001:db8::1 5\n") {
		t.Fatalf("installed source route disappeared from FRR output: %q", got)
	}
}

func TestFRRCrossRIBFoldRestoresDHCPv6Suppression_12084(t *testing.T) {
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "")
	classlessCfg := compileFoldConfig(t, false,
		"set routing-options static route 2602:ffd3::/40 next-hop 2602:ffd3:ffff::1",
		"set routing-options rib inet6.0 static route 2602:ffd3::/40 next-hop 2602:ffd3:ffff::1",
	)
	classlessRoute := DHCPRoute{
		Destination: "2602:ffd3:1::/48",
		Gateway:     "fe80::1",
		Interface:   "ge-0-0-2",
		IsIPv6:      true,
	}
	classless := &FullConfig{
		StaticRoutes:      classlessCfg.RoutingOptions.StaticRoutes,
		Inet6StaticRoutes: classlessCfg.RoutingOptions.Inet6StaticRoutes,
		DHCPRoutes:        []DHCPRoute{classlessRoute},
	}
	if got := dhcpClasslessCoveredByStatic(classless, classlessRoute); got != "2602:ffd3::/40" {
		t.Fatalf("covered static prefix = %q, want 2602:ffd3::/40", got)
	}
	var classlessRendered strings.Builder
	renderDHCPDefaults(&classlessRendered, classless)
	if got := strings.TrimSpace(classlessRendered.String()); got != "" {
		t.Fatalf("covered DHCPv6 classless route was not suppressed: %q", got)
	}

	defaultCfg := compileFoldConfig(t, false,
		"set routing-options static route ::/0 next-hop 2001:db8::1",
		"set routing-options rib inet6.0 static route ::/0 next-hop 2001:db8::1",
	)
	defaultRoute := &FullConfig{
		StaticRoutes:      defaultCfg.RoutingOptions.StaticRoutes,
		Inet6StaticRoutes: defaultCfg.RoutingOptions.Inet6StaticRoutes,
		DHCPRoutes: []DHCPRoute{{
			Gateway: "fe80::1", Interface: "ge-0-0-2", IsIPv6: true,
		}},
	}
	var defaultRendered strings.Builder
	renderDHCPDefaults(&defaultRendered, defaultRoute)
	if got := strings.TrimSpace(defaultRendered.String()); got != "" {
		t.Fatalf("covered DHCPv6 default was not suppressed: %q", got)
	}
}
