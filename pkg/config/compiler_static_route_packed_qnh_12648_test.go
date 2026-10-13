package config

import (
	"reflect"
	"testing"
)

// A fully packed static-route line must not let the multi-value next-hop leaf
// consume a following qualified-next-hop statement as more ECMP gateways.
// Before #12648, commit succeeded but `qualified-next-hop`, its gateway, and
// its preference were all compiled as plain next-hop addresses.
func TestPackedStaticRouteNextHopAndQualifiedNextHop_12648(t *testing.T) {
	packed := hierTree(t, `routing-options { static { route 10.5.0.0/16 next-hop 10.0.0.1 qualified-next-hop 10.0.0.2 preference 250; } }`)
	unpacked := hierTree(t, `routing-options { static { route 10.5.0.0/16 { next-hop 10.0.0.1; qualified-next-hop 10.0.0.2 { preference 250; } } } }`)

	want := []NextHopEntry{
		{Address: "10.0.0.1"},
		{Address: "10.0.0.2", Preference: 250, HasPreference: true},
	}
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{name: "packed one-liner", tree: packed},
		{name: "unpacked control", tree: unpacked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			route := findStaticRoute3871(t, cfg.RoutingOptions.StaticRoutes, "10.5.0.0/16")
			if !reflect.DeepEqual(route.NextHops, want) {
				t.Fatalf("NextHops = %+v, want %+v", route.NextHops, want)
			}
		})
	}
}
