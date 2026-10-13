package config

import (
	"reflect"
	"strings"
	"testing"
)

// A fully packed static-route line must not let the multi-value next-hop leaf
// consume a following qualified-next-hop statement as more ECMP gateways.
// Before #12648, compilation succeeded but `qualified-next-hop`, its gateway,
// and its preference were all compiled as plain next-hop addresses.
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
			if err := SchemaValidate(tc.tree, nil); err != nil {
				t.Fatalf("SchemaValidate: %v", err)
			}
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

func TestPackedStaticRouteRejectsIncompleteQualifiedNextHop_12648(t *testing.T) {
	for name, config := range map[string]string{
		"missing gateway": `routing-options { static { route 10.5.0.0/16 next-hop 10.0.0.1 qualified-next-hop; } }`,
		"route keyword as gateway": `routing-options { static { route 10.5.0.0/16 next-hop 10.0.0.1 qualified-next-hop no-install; } }`,
		"unsupported trailing clause": `routing-options { static { route 10.5.0.0/16 next-hop 10.0.0.1 qualified-next-hop 10.0.0.2 preference 250 next-table blue.inet.0; } }`,
	} {
		t.Run(name, func(t *testing.T) {
			err := SchemaValidate(hierTree(t, config), nil)
			if err == nil || !strings.Contains(err.Error(), "qualified-next-hop") {
				t.Fatalf("SchemaValidate error = %v, want explicit qualified-next-hop rejection", err)
			}
		})
	}
}

func TestPackedRouteQualifiedNextHopNormalizerStaysInStaticRoutingScope_12648(t *testing.T) {
	nextHop := &Node{Keys: []string{"next-hop", "10.0.0.1", "qualified-next-hop", "10.0.0.2"}}
	route := &Node{Keys: []string{"route", "route-name"}, Children: []*Node{nextHop}}
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"policy-options"}, Children: []*Node{route}},
	}}

	if changed := normalizePackedStaticRouteQualifiedNextHop(tree); changed != 0 {
		t.Fatalf("normalizer changed %d non-static route nodes, want 0", changed)
	}
	if len(route.Children) != 1 || len(nextHop.Keys) != 4 {
		t.Fatalf("non-static route was rewritten: route=%+v next-hop=%+v", route, nextHop)
	}
}
