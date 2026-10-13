package config

import (
	"strings"
	"testing"
)

// A static route with no next-hop, next-table, discard, or reject has no
// forwarding disposition. It must warn at compile time and be excluded from
// the shared install verdict used by the helper-FIB builder and route displays.
func TestZeroDispositionStaticWarnsAndIsExcluded_11327(t *testing.T) {
	for _, policy := range []struct {
		name string
		set  string
		want PolicyAction
	}{
		{name: "deny-default", set: "deny-all", want: PolicyDeny},
		{name: "permit-default", set: "permit-all", want: PolicyPermit},
	} {
		for _, routeForm := range []struct {
			name string
			// buildRoute constructs the zero-disposition vehicle. Text forms
			// go through strict compile; the typed form carries the shape
			// strict compile now rejects at parse (#12818: a valueless
			// qualified-next-hop compiles to an empty placeholder hop).
			buildRoute func(t *testing.T, policyLine string) *Config
		}{
			{name: "bare route", buildRoute: func(t *testing.T, policyLine string) *Config {
				return compileSetLinesT(t, []string{
					"set routing-options static route 10.1.0.0/24",
					policyLine,
				})
			}},
			{name: "receive action", buildRoute: func(t *testing.T, policyLine string) *Config {
				return compileSetLinesT(t, []string{
					"set routing-options static route 10.1.0.0/24 receive",
					policyLine,
				})
			}},
			{
				name: "empty qualified next-hop",
				buildRoute: func(t *testing.T, policyLine string) *Config {
					// Typed vehicle (same style as
					// TestZeroDispositionStaticWarningCoversAllRouteScopes_11327):
					// the empty-placeholder hop #12818 removed from strict
					// compile, constructed directly so the zero-disposition
					// contract (empty hop is not a forwarding target) is
					// still pinned where that shape can exist.
					cfg := compileSetLinesT(t, []string{
						"set routing-options static route 10.1.0.0/24",
						policyLine,
					})
					route := cfg.RoutingOptions.StaticRoutes[0]
					route.NextHops = []NextHopEntry{{Address: "", Interface: ""}}
					cfg.Warnings = append(cfg.Warnings, ValidateConfig(cfg)...)
					return cfg
				},
			},
		} {
			t.Run(policy.name+"/"+routeForm.name, func(t *testing.T) {
				cfg := routeForm.buildRoute(t, "set security policies default-policy "+policy.set)
				if cfg.Security.DefaultPolicy != policy.want {
					t.Fatalf("default policy = %v, want %v", cfg.Security.DefaultPolicy, policy.want)
				}
				if len(cfg.RoutingOptions.StaticRoutes) != 1 {
					t.Fatalf("compiled statics = %d, want one", len(cfg.RoutingOptions.StaticRoutes))
				}
				route := cfg.RoutingOptions.StaticRoutes[0]
				if routeForm.name == "empty qualified next-hop" {
					if len(route.NextHops) != 1 || route.NextHops[0].Address != "" || route.NextHops[0].Interface != "" {
						t.Fatalf("fixture is not an empty qualified next-hop: %+v", route.NextHops)
					}
				} else if len(route.NextHops) != 0 {
					t.Fatalf("fixture unexpectedly has next-hops: %+v", route.NextHops)
				}
				if route.NextTable != "" || route.Discard || route.Reject {
					t.Fatalf("fixture has another forwarding disposition: %+v", route)
				}
				if reason := StaticRouteExcludedReason(route, false, nil); !strings.Contains(reason, "no forwarding disposition") {
					t.Fatalf("StaticRouteExcludedReason = %q, want no-forwarding-disposition reason", reason)
				}
				if reason := StaticRouteExclusions(cfg)[route]; !strings.Contains(reason, "no forwarding disposition") {
					t.Fatalf("StaticRouteExclusions reason = %q, want no-forwarding-disposition reason", reason)
				}
				var warning string
				for _, got := range cfg.Warnings {
					if strings.Contains(got, "no forwarding disposition") && strings.Contains(got, route.Destination) {
						warning = got
						break
					}
				}
				if warning == "" {
					t.Fatalf("compile warnings do not identify the zero-disposition route: %v", cfg.Warnings)
				}
			})
		}
	}
}

func TestZeroDispositionStaticWarningCoversAllRouteScopes_11327(t *testing.T) {
	globalV4 := &StaticRoute{Destination: "10.1.0.0/24"}
	globalV6 := &StaticRoute{Destination: "2001:db8:1::/48"}
	instanceV4 := &StaticRoute{Destination: "10.2.0.0/24"}
	instanceV6 := &StaticRoute{Destination: "2001:db8:2::/48"}
	cfg := &Config{}
	cfg.RoutingOptions.StaticRoutes = []*StaticRoute{globalV4}
	cfg.RoutingOptions.Inet6StaticRoutes = []*StaticRoute{globalV6}
	cfg.RoutingInstances = []*RoutingInstanceConfig{{
		Name: "blue", StaticRoutes: []*StaticRoute{instanceV4},
		Inet6StaticRoutes: []*StaticRoute{instanceV6},
	}}

	excluded := StaticRouteExclusions(cfg)
	warnings := ValidateConfig(cfg)
	for _, route := range []*StaticRoute{globalV4, globalV6, instanceV4, instanceV6} {
		if reason := excluded[route]; !strings.Contains(reason, "no forwarding disposition") {
			t.Errorf("route %q exclusion reason = %q, want no-forwarding-disposition reason", route.Destination, reason)
		}
		foundWarning := false
		for _, warning := range warnings {
			if strings.Contains(warning, "no forwarding disposition") &&
				strings.Contains(warning, route.Destination) {
				foundWarning = true
				break
			}
		}
		if !foundWarning {
			t.Errorf("ValidateConfig did not warn about zero-disposition route %q", route.Destination)
		}
	}
}

func TestStaticRouteDispositionExclusionsPreserveInstallableRoutes_11327(t *testing.T) {
	for _, route := range []*StaticRoute{
		{Destination: "10.1.0.0/24", NextHops: []NextHopEntry{{Address: "192.0.2.1"}}},
		{Destination: "10.1.0.0/24", NextTable: "vrf-a"},
		{Destination: "10.1.0.0/24", Discard: true},
		{Destination: "10.1.0.0/24", Reject: true},
	} {
		if reason := StaticRouteExcludedReason(route, false, map[string]struct{}{"vrf-a": {}}); reason != "" {
			t.Errorf("installable route %+v unexpectedly excluded: %q", route, reason)
		}
	}
}
