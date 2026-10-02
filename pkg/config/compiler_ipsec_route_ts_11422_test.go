package config

import (
	"strings"
	"testing"
)

func routeTrafficSelectorTree11422(t *testing.T, route string, remoteSelectors ...string) *ConfigTree {
	t.Helper()
	commands := []string{
		"set security ike gateway gw address 198.51.100.1",
		"set security ipsec vpn site ike gateway gw",
		"set security ipsec vpn site bind-interface st0.0",
		"set routing-options static route " + route + " next-hop 192.0.2.1 interface st0.0",
	}
	for i, remote := range remoteSelectors {
		name := "to-peer-" + string(rune('a'+i))
		commands = append(commands, selectorCommands11380("site", name, "10.1.0.0/24", remote)...)
	}
	return buildBindIfaceTree(t, commands...)
}

func TestRouteViaBindInterfaceMustFitRenderedRemoteSelectorUnion11422(t *testing.T) {
	t.Run("reject wider route with actionable destination", func(t *testing.T) {
		_, err := CompileConfig(routeTrafficSelectorTree11422(t, "10.3.0.0/24", "10.2.0.0/24"))
		if err == nil {
			t.Fatal("strict commit accepted route 10.3.0.0/24 via st0.0 outside the rendered remote traffic-selector union")
		}
		for _, want := range []string{"#11422", "10.3.0.0/24", "st0.0", "site"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("route/selector rejection %q does not identify %q", err, want)
			}
		}
	})

	t.Run("selector union covers complete route prefix", func(t *testing.T) {
		_, err := CompileConfig(routeTrafficSelectorTree11422(t, "10.2.0.0/24", "10.2.0.0/25", "10.2.0.128/25"))
		if err != nil {
			t.Fatalf("strict commit rejected a route fully covered by the union of rendered remote selectors: %v", err)
		}
	})
	t.Run("explicit empty remote side uses route-based default", func(t *testing.T) {
		_, err := CompileConfig(routeTrafficSelectorTree11422(t, "10.3.0.0/24", ""))
		if err != nil {
			t.Fatalf("strict commit rejected a route covered by the rendered default remote selector: %v", err)
		}
	})
}

func TestRouteViaBindInterfaceWarnsOnLenientLoad11422(t *testing.T) {
	cfg, err := CompileConfigLenient(routeTrafficSelectorTree11422(t, "10.3.0.0/24", "10.2.0.0/24"))
	if err != nil {
		t.Fatalf("lenient compile rejected an existing route/selector mismatch: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 ||
		len(cfg.RoutingOptions.StaticRoutes[0].NextHops) != 1 ||
		cfg.RoutingOptions.StaticRoutes[0].NextHops[0].Interface != "st0.0" {
		t.Fatalf("route fixture did not compile to an interface next-hop on st0.0: route=%+v next-hops=%+v",
			cfg.RoutingOptions.StaticRoutes[0], cfg.RoutingOptions.StaticRoutes[0].NextHops)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#11422") && strings.Contains(warning, "10.3.0.0/24") {
			return
		}
	}
	t.Fatalf("lenient compile did not warn about the uncovered tunnel route: %v", cfg.Warnings)
}
