package config

import (
	"strings"
	"testing"
)

func TestStaticRouteTolerantNoInstallConflictKeepsInstallableSourceWholesale12084(t *testing.T) {
	cases := []struct {
		name             string
		text             string
		destination      string
		wantDiscard      bool
		wantReject       bool
		wantNextTable    string
		wantNextTableRaw string
		wantHop          string
		wantPref         int
		wantHasPref      bool
	}{
		{
			name: "noinstall-first-replaced-by-installable-hop",
			text: `routing-options { static {
				route 10.30.0.1/16 { discard; no-install; preference 2; }
				route 10.30.0.0/16 { next-hop 192.0.2.1; preference 250; }
			} }`,
			destination: "10.30.0.1/16", wantHop: "192.0.2.1", wantPref: 250, wantHasPref: true,
		},
		{
			name: "nexttable-noinstall-ignored-after-installable-hop",
			text: `interfaces { ge-0/0/0 { unit 0; } }
				routing-instances { blue { instance-type virtual-router; } }
				routing-options { static {
				route 10.31.0.0/16 { next-hop 192.0.2.1; preference 250; }
				route 10.31.0.1/16 { next-table blue.inet.0; no-install; preference 2; }
			} }`,
			destination: "10.31.0.0/16", wantHop: "192.0.2.1", wantPref: 250, wantHasPref: true,
		},
		{
			name: "noinstall-action-does-not-lower-preference",
			text: `routing-options { static {
				route 10.32.0.0/16 { discard; preference 250; }
				route 10.32.0.1/16 { discard; no-install; preference 5; }
			} }`,
			destination: "10.32.0.0/16", wantDiscard: true, wantPref: 250, wantHasPref: true,
		},
		{
			name: "installable-nexttable-replaces-noinstall-action",
			text: `interfaces { ge-0/0/0 { unit 0; } }
				routing-instances { blue { instance-type virtual-router; } }
				routing-options { static {
				route 10.33.0.1/16 { discard; no-install; preference 2; }
				route 10.33.0.0/16 { next-table blue.inet.0; preference 250; }
			} }`,
			destination: "10.33.0.1/16", wantNextTable: "blue", wantNextTableRaw: "blue.inet.0",
			wantPref: 250, wantHasPref: true,
		},
		{
			name: "installable-reject-replaces-noinstall-discard",
			text: `routing-options { static {
				route 10.34.0.1/16 { discard; no-install; preference 2; }
				route 10.34.0.0/16 { reject; preference 250; }
			} }`,
			destination: "10.34.0.1/16", wantReject: true, wantPref: 250, wantHasPref: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, parseErrs := NewParser(tc.text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse static-route fixture: %v", parseErrs)
			}
			tree := &ConfigTree{Children: root.Children}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "install and no-install") {
				t.Fatalf("strict compile error = %v, want install/no-install conflict", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			routes := append(append([]*StaticRoute(nil), cfg.RoutingOptions.StaticRoutes...), cfg.RoutingOptions.Inet6StaticRoutes...)
			route := compiledRouteIn(t, routes, tc.destination)
			if route.NoInstall || route.Discard != tc.wantDiscard || route.Reject != tc.wantReject ||
				route.NextTable != tc.wantNextTable || route.NextTableRaw != tc.wantNextTableRaw ||
				route.Preference != tc.wantPref || route.HasPreference != tc.wantHasPref {
				t.Fatalf("tolerant folded route = %+v, want installable action/pref state", route)
			}
			if tc.wantHop == "" {
				if len(route.NextHops) != 0 {
					t.Fatalf("tolerant folded hops = %+v, want none", route.NextHops)
				}
			} else if len(route.NextHops) != 1 || route.NextHops[0].Address != tc.wantHop {
				t.Fatalf("tolerant folded hops = %+v, want only %q", route.NextHops, tc.wantHop)
			}
		})
	}
}
