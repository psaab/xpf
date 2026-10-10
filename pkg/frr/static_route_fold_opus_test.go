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
func compileFoldText(t *testing.T, lenient bool, text string) *config.Config {
	t.Helper()
	root, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse static-route fixture: %v", parseErrs)
	}
	tree := &config.ConfigTree{Children: root.Children}
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
func TestFRRSameSpellingSplitBlocksKeepBaseDistance_12084(t *testing.T) {
	cases := []struct {
		name        string
		text        string
		sets        []string
		destination string
		want        string
	}{
		{
			name: "9125-explicit-default-last",
			text: `routing-options { static {
				route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
				route 10.0.0.0/8 { preference 5; }
			} }`,
			destination: "10.0.0.0/8",
			want:        "ip route 10.0.0.0/8 192.0.2.1 5\n",
		},
		{
			name: "9125-later-next-hop-inherits-prior-preference",
			text: `routing-options { static {
				route 10.1.0.0/16 { next-hop 192.0.2.1; preference 10; }
				route 10.1.0.0/16 { next-hop 192.0.2.2; }
			} }`,
			destination: "10.1.0.0/16",
			want:        "ip route 10.1.0.0/16 192.0.2.1 10\nip route 10.1.0.0/16 192.0.2.2 10\n",
		},
		{
			name: "preference-block-before-next-hop",
			text: `routing-options { static {
				route 10.2.0.0/16 { preference 200; }
				route 10.2.0.0/16 { next-hop 192.0.2.1; }
			} }`,
			destination: "10.2.0.0/16",
			want:        "ip route 10.2.0.0/16 192.0.2.1 200\n",
		},
		{
			name: "preference-block-after-next-hop",
			text: `routing-options { static {
				route 10.3.0.0/16 { next-hop 192.0.2.1; }
				route 10.3.0.0/16 { preference 200; }
			} }`,
			destination: "10.3.0.0/16",
			want:        "ip route 10.3.0.0/16 192.0.2.1 200\n",
		},
		{
			name: "rib-inet0-plus-bare-preference",
			sets: []string{
				"set routing-options rib inet.0 static route 10.5.0.0/16 next-hop 10.0.0.1",
				"set routing-options static route 10.5.0.0/16 preference 200",
			},
			destination: "10.5.0.0/16",
			want:        "ip route 10.5.0.0/16 10.0.0.1 200\n",
		},
		{
			name: "rib-inet0-plus-bare-ecmp",
			sets: []string{
				"set routing-options rib inet.0 static route 10.6.0.0/16 next-hop 10.0.0.1",
				"set routing-options rib inet.0 static route 10.6.0.0/16 preference 200",
				"set routing-options static route 10.6.0.0/16 next-hop 10.0.0.2",
			},
			destination: "10.6.0.0/16",
			want:        "ip route 10.6.0.0/16 10.0.0.1 200\nip route 10.6.0.0/16 10.0.0.2 200\n",
		},
		{
			name: "inet6-split-block",
			text: `routing-options { rib inet6.0 { static {
				route 2001:db8:1::/48 { next-hop 2001:db8::1; preference 200; }
				route 2001:db8:1::/48 { next-hop 2001:db8::2; }
			} } }`,
			destination: "2001:db8:1::/48",
			want:        "ipv6 route 2001:db8:1::/48 2001:db8::1 200\nipv6 route 2001:db8:1::/48 2001:db8::2 200\n",
		},
		{
			name: "same-spelling-alias-interleave",
			text: `routing-options { static {
				route 10.9.0.0/16 { next-hop 192.0.2.1; preference 10; }
				route 10.9.0.1/16 { next-hop 192.0.2.2; preference 200; }
				route 10.9.0.0/16 { next-hop 192.0.2.3; }
			} }`,
			destination: "10.9.0.0/16",
			want: "ip route 10.9.0.0/16 192.0.2.1 10\n" +
				"ip route 10.9.0.0/16 192.0.2.3 10\n" +
				"ip route 10.9.0.0/16 192.0.2.2 200\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *config.Config
			if tc.text != "" {
				cfg = compileFoldText(t, false, tc.text)
			} else {
				cfg = compileFoldConfig(t, false, tc.sets...)
			}
			got := New().generateStaticRoute(
				routeFromFoldConfig(t, cfg, tc.destination), "", nil, nil, nil)
			if got != tc.want {
				t.Fatalf("FRR output = %q, want exact per-source distances %q", got, tc.want)
			}
		})
	}
}

func TestFRRSameSpellingNoInstallRemainsExcluded_12084(t *testing.T) {
	cfg := compileFoldText(t, true, `routing-options { static {
		route 10.0.0.0/8 { next-hop 192.0.2.1; }
		route 10.0.0.0/8 { no-install; }
	} }`)
	route := routeFromFoldConfig(t, cfg, "10.0.0.0/8")
	if !route.NoInstall {
		t.Fatalf("tolerant same-spelling route lost no-install: %+v", route)
	}
	if got := New().generateStaticRoute(route, "", nil, nil, nil); got != "" {
		t.Fatalf("tolerant no-install route rendered into FRR: %q", got)
	}
	if got := config.StaticRouteExclusions(cfg)[route]; got != "route has the `no-install` option set" {
		t.Fatalf("tolerant no-install exclusion = %q", got)
	}
}
