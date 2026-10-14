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

// sharedBindRouteTree11422 builds two VPNs sharing one bind-interface with
// provably disjoint selectors (#11380), plus a static route over that bind.
func sharedBindRouteTree11422(t *testing.T, route, aRemote, bRemote string) *ConfigTree {
	t.Helper()
	commands := []string{
		"set security ike gateway gw-a address 198.51.100.1",
		"set security ike gateway gw-b address 198.51.100.2",
		"set security ipsec vpn site-a ike gateway gw-a",
		"set security ipsec vpn site-a bind-interface st0.0",
		"set security ipsec vpn site-b ike gateway gw-b",
		"set security ipsec vpn site-b bind-interface st0.0",
		"set routing-options static route " + route,
	}
	commands = append(commands, selectorCommands11380("site-a", "to-a", "10.0.0.0/24", aRemote)...)
	commands = append(commands, selectorCommands11380("site-b", "to-b", "10.0.0.0/24", bRemote)...)
	return buildBindIfaceTree(t, commands...)
}

// #12909: VPNs sharing a bind-interface each contribute their remote ranges
// to the XFRM policies on that device, so a routed destination is coverable
// by their UNION. Requiring one single VPN to cover the whole destination
// falsely rejected aggregates split across complementary VPNs (#11380).
func TestSharedBindSelectorUnionCoversAggregateRoute12909(t *testing.T) {
	t.Run("complementary VPN halves cover the aggregate route", func(t *testing.T) {
		_, err := CompileConfig(sharedBindRouteTree11422(t,
			"10.2.0.0/24 next-hop 192.0.2.1 interface st0.0", "10.2.0.0/25", "10.2.0.128/25"))
		if err != nil {
			t.Fatalf("strict commit rejected a route covered by the union of two shared-bind VPNs: %v", err)
		}
	})

	t.Run("aggregate outside the union still rejected naming both VPNs", func(t *testing.T) {
		_, err := CompileConfig(sharedBindRouteTree11422(t,
			"10.2.0.0/23 next-hop 192.0.2.1 interface st0.0", "10.2.0.0/25", "10.2.0.128/25"))
		if err == nil {
			t.Fatal("strict commit accepted a route outside the shared-bind remote selector union")
		}
		for _, want := range []string{"#11422", "10.2.0.0/23", "st0.0", "site-a", "site-b"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("shared-bind rejection %q does not identify %q", err, want)
			}
		}
	})
}
