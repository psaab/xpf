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

// sharedBindRouteTree11422 builds the disjoint-selector shape formerly
// permitted by #11380; #17779 now rejects it because runtime capture keys
// are owned by VPN name and two claimants on one if_id quarantine the plan.
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

// A route could previously be covered by the union of remote selectors from
// multiple VPNs sharing one bind-interface (#12909). The runtime capture plan
// cannot represent multiple owners on one if_id, so strict commit now rejects
// that shape regardless of selector coverage.
func TestSharedBindSelectorUnionRejectedByCaptureOwner17779(t *testing.T) {
	_, err := CompileConfig(sharedBindRouteTree11422(t,
		"10.2.0.0/24 next-hop 192.0.2.1 interface st0.0",
		"10.2.0.0/25",
		"10.2.0.128/25"))
	if err == nil || !strings.Contains(err.Error(), "#17779") ||
		!strings.Contains(err.Error(), "OwnerContested") ||
		!strings.Contains(err.Error(), "site-a") ||
		!strings.Contains(err.Error(), "site-b") {
		t.Fatalf("strict commit error = %v, want #17779 capture-owner rejection for the shared-bind route", err)
	}
}
