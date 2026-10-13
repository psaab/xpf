package config

import (
	"reflect"
	"testing"
)

func TestPackedStaticRouteNextHopInterfaceChildKeepsQNH_12755(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []NextHopEntry
	}{
		{
			name: "issue repro packed interface child then QNH",
			src:  `routing-options { static { route 10.20.0.0/16 next-hop 10.0.0.1 interface ge-0/0/1.0 qualified-next-hop 10.0.0.2 preference 250; } }`,
			want: []NextHopEntry{
				{Address: "10.0.0.1", Interface: "ge-0/0/1.0"},
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
			},
		},
		{
			name: "expanded control next-hop interface child plus QNH sibling",
			src:  `routing-options { static { route 10.20.0.0/16 { next-hop 10.0.0.1 { interface ge-0/0/1.0; } qualified-next-hop 10.0.0.2 { preference 250; } } } }`,
			want: []NextHopEntry{
				{Address: "10.0.0.1", Interface: "ge-0/0/1.0"},
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
			},
		},
		{
			name: "issue example route next-hop gw interface if QNH gw2 preference n",
			src:  `routing-options { static { route 10.20.0.0/16 next-hop 192.0.2.1 interface ge-0/0/0.0 qualified-next-hop 192.0.2.2 preference 200; } }`,
			want: []NextHopEntry{
				{Address: "192.0.2.1", Interface: "ge-0/0/0.0"},
				{Address: "192.0.2.2", Preference: 200, HasPreference: true},
			},
		},
		{
			name: "clause order QNH before interface-child next-hop packed",
			src:  `routing-options { static { route 10.20.0.0/16 { qualified-next-hop 10.0.0.2 preference 250; next-hop 10.0.0.1 interface ge-0/0/1.0; } } }`,
			want: []NextHopEntry{
				{Address: "10.0.0.2", Preference: 250, HasPreference: true},
				{Address: "10.0.0.1", Interface: "ge-0/0/1.0"},
			},
		},
		{
			name: "interface child only preservation no QNH",
			src:  `routing-options { static { route 10.20.0.0/16 next-hop 10.0.0.1 interface ge-0/0/1.0; } }`,
			want: []NextHopEntry{
				{Address: "10.0.0.1", Interface: "ge-0/0/1.0"},
			},
		},
		{
			name: "QNH only preservation via interface-child shape",
			src:  `routing-options { static { route 10.20.0.0/16 { next-hop 10.0.0.1 { interface ge-0/0/1.0; } qualified-next-hop 10.0.0.2 { interface ge-0/0/2.0; preference 250; metric 7; } } } }`,
			want: []NextHopEntry{
				{Address: "10.0.0.1", Interface: "ge-0/0/1.0"},
				{Address: "10.0.0.2", Interface: "ge-0/0/2.0", Preference: 250, HasPreference: true, Metric: 7, HasMetric: true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree(t, tc.src)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			route := findStaticRoute3871(t, cfg.RoutingOptions.StaticRoutes, "10.20.0.0/16")
			if !reflect.DeepEqual(route.NextHops, tc.want) {
				t.Fatalf("NextHops = %+v, want %+v; tree:\n%s", route.NextHops, tc.want, tree.Format())
			}
		})
	}
}
