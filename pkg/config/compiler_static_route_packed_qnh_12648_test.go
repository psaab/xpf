package config

import (
	"reflect"
	"strings"
	"testing"
)

// A packed static-route next-hop tail must not consume a following
// qualified-next-hop statement as more ECMP gateways. This covers multiple
// gateways and repeated packed next-hop children as well as the one-liner.
// Before #12648, compilation succeeded but the QNH clause's tokens were
// compiled as plain next-hop addresses.
func TestPackedStaticRouteNextHopAndQualifiedNextHop_12648(t *testing.T) {
	packed := hierTree(t, `routing-options { static { route 10.5.0.0/16 next-hop 10.0.0.1 qualified-next-hop 10.0.0.2 preference 250; } }`)
	unpacked := hierTree(t, `routing-options { static { route 10.5.0.0/16 { next-hop 10.0.0.1; qualified-next-hop 10.0.0.2 { preference 250; } } } }`)
	packedMulti := hierTree(t, `routing-options { static { route 10.5.0.0/16 next-hop 10.0.0.1 10.0.0.3 qualified-next-hop 10.0.0.2 preference 250; } }`)
	packedRepeated := hierTree(t, `routing-options { static { route 10.5.0.0/16 { next-hop 10.0.0.1 qualified-next-hop 10.0.0.2 preference 250; next-hop 10.0.0.3 qualified-next-hop 10.0.0.4 preference 200; } } }`)

	for _, tc := range []struct {
		name string
		tree *ConfigTree
		want []NextHopEntry
	}{
		{
			name: "packed one-liner",
			tree: packed,
			want: []NextHopEntry{
				{Address: "10.0.0.1"},
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
			},
		},
		{
			name: "unpacked control",
			tree: unpacked,
			want: []NextHopEntry{
				{Address: "10.0.0.1"},
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
			},
		},
		{
			name: "packed multi-gateway next-hop",
			tree: packedMulti,
			want: []NextHopEntry{
				{Address: "10.0.0.1"},
				{Address: "10.0.0.3"},
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
			},
		},
		{
			name: "repeated packed next-hop children",
			tree: packedRepeated,
			want: []NextHopEntry{
				{Address: "10.0.0.1"},
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
				{Address: "10.0.0.3"},
				{Address: "10.0.0.4", Preference: 200, HasPreference: true},
			},
		},
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
			if !reflect.DeepEqual(route.NextHops, tc.want) {
				t.Fatalf("NextHops = %+v, want %+v", route.NextHops, tc.want)
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
