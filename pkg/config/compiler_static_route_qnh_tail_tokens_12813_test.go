package config

import (
	"reflect"
	"strings"
	"testing"
)

// #12813: a QNH tail relocated off the next-hop interface child by the
// #12648 splitter keeps following tokens (preference, or an unknown
// keyword). When the tail is not a complete clause the splitter leaves
// it fused, the #12790 interface gate must reject it on the strict
// CompileConfig path instead of compiling garbage hops named after the
// tail keywords.
func TestStaticRouteQNHTailWithFollowingTokens12813(t *testing.T) {
	invalid := []struct {
		name string
		src  string
	}{
		{
			name: "interface child QNH tail with following preference",
			src:  `routing-options { static { route 10.20.0.0/16 next-hop 10.0.0.1 interface ge-0/0/1.0 qualified-next-hop preference 250; } }`,
		},
		{
			name: "QNH gateway with unknown following token",
			src:  `routing-options { static { route 10.20.0.0/16 { next-hop 10.0.0.1; qualified-next-hop 10.0.0.2 bogus 5; } } }`,
		},
		{
			name: "interface child QNH gateway with unknown following token",
			src:  `routing-options { static { route 10.20.0.0/16 next-hop 10.0.0.1 interface ge-0/0/1.0 qualified-next-hop 10.0.0.2 bogus 5; } }`,
		},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			tree := hierTree(t, tc.src)
			cfg, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict CompileConfig accepted garbage QNH tail; hops=%+v tree:\n%s", routeHops12813(t, cfg), tree.Format())
			}
			if !strings.Contains(err.Error(), "#12813") && !strings.Contains(err.Error(), "#12790") {
				t.Fatalf("strict CompileConfig error = %v, want QNH tail rejection", err)
			}
			if err := SchemaValidate(hierTree(t, tc.src), nil); err == nil {
				t.Fatalf("strict SchemaValidate accepted garbage QNH tail")
			}
		})
	}

	t.Run("valid QNH tail hops unchanged", func(t *testing.T) {
		src := `routing-options { static { route 10.20.0.0/16 next-hop 10.0.0.1 interface ge-0/0/1.0 qualified-next-hop 10.0.0.2 preference 250; } }`
		cfg, err := CompileConfig(hierTree(t, src))
		if err != nil {
			t.Fatalf("strict CompileConfig: %v", err)
		}
		want := []NextHopEntry{
			{Address: "10.0.0.1", Interface: "ge-0/0/1.0"},
			{Address: "10.0.0.2", Preference: 250, HasPreference: true},
		}
		if got := routeHops12813(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("NextHops = %+v, want %+v", got, want)
		}
	})
}

func routeHops12813(t *testing.T, cfg *Config) []NextHopEntry {
	t.Helper()
	if cfg == nil {
		return nil
	}
	return findStaticRoute3871(t, cfg.RoutingOptions.StaticRoutes, "10.20.0.0/16").NextHops
}
