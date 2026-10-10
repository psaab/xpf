package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestMappedPrefixIdentityPreservedInRouteSnapshots12332(t *testing.T) {
	oldRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = oldRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	mapped := "set routing-options static route ::ffff:192.0.2.0/120 discard"
	ipv4 := "set routing-options static route 192.0.2.0/24 next-hop 192.0.2.254"
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{name: "mapped-first", sets: []string{mapped, ipv4}},
		{name: "ipv4-first", sets: []string{ipv4, mapped}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			for _, set := range tc.sets {
				path, err := config.ParseSetCommand(set)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", set, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", set, err)
				}
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			routes, _, err := buildRouteSnapshots(cfg, nil, nil)
			if err != nil {
				t.Fatalf("buildRouteSnapshots: %v", err)
			}
			if len(routes) != 2 {
				t.Fatalf("snapshot routes = %+v, want both family-specific routes", routes)
			}

			var mappedRoute, ipv4Route *RouteSnapshot
			for i := range routes {
				route := &routes[i]
				switch route.Destination {
				case "::ffff:192.0.2.0/120":
					mappedRoute = route
				case "192.0.2.0/24":
					ipv4Route = route
				}
			}
			if mappedRoute == nil || mappedRoute.Table != "inet6.0" ||
				mappedRoute.Family != "inet6" || !mappedRoute.Discard {
				t.Errorf("mapped-IPv6 snapshot route = %+v, want inet6.0 discard", mappedRoute)
			}
			if ipv4Route == nil || ipv4Route.Table != "inet.0" ||
				ipv4Route.Family != "inet" || ipv4Route.Discard ||
				len(ipv4Route.NextHops) != 1 || ipv4Route.NextHops[0] != "192.0.2.254" {
				t.Errorf("native-IPv4 snapshot route = %+v, want inet.0 next-hop 192.0.2.254", ipv4Route)
			}
		})
	}
}

func TestCrossRIBNextTableAliasPublishesSingleSnapshot12332(t *testing.T) {
	oldRuleList := ruleListFn
	t.Cleanup(func() { ruleListFn = oldRuleList })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }

	tree := &config.ConfigTree{}
	for _, set := range []string{
		"set routing-instances aaa instance-type virtual-router",
		"set routing-instances zzz instance-type virtual-router",
		"set interfaces ge-0/0/0 unit 0",
		"set routing-options static route 2001:db8::/32 next-table aaa.inet6.0",
		"set routing-options rib inet6.0 static route 2001:DB8:0:0:0:0:0:0/32 next-table zzz.inet6.0",
	} {
		path, err := config.ParseSetCommand(set)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", set, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", set, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	var leaks []RouteSnapshot
	for _, route := range routes {
		if route.NextTable != "" {
			leaks = append(leaks, route)
		}
	}
	if len(leaks) != 1 || leaks[0].Table != "inet6.0" ||
		leaks[0].Family != "inet6" || leaks[0].NextTable != "zzz" {
		t.Fatalf("cross-RIB leak snapshots = %+v, want one inet6.0 leak to zzz", leaks)
	}
}
