package config

import (
	"strings"
	"testing"
)

// #12818: an expanded valueless `qualified-next-hop;` (no gateway) was
// accepted by strict CompileConfig — it compiled to an empty-address
// placeholder NextHopEntry that staticRouteHasDisposition then skipped —
// while SchemaValidate rejected it as a declared value given none. The two
// paths must agree: strict compile rejects, with an error naming the leaf.
func TestValuelessQualifiedNextHopCompileConfig12818(t *testing.T) {
	invalid := []struct {
		name     string
		build    func(t *testing.T) *ConfigTree
		wantPath string
	}{
		{
			name: "hierarchical valueless beside primary",
			build: func(t *testing.T) *ConfigTree {
				return hierTree(t, `routing-options { static { route 10.20.0.0/16 { next-hop 10.0.0.1; qualified-next-hop; } } }`)
			},
		},
		{
			name: "hierarchical valueless only hop",
			build: func(t *testing.T) *ConfigTree {
				return hierTree(t, `routing-options { static { route 10.20.0.0/16 { qualified-next-hop; } } }`)
			},
		},
		{
			name: "flat set valueless beside primary",
			build: func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t,
					"set routing-options static route 10.20.0.0/16 next-hop 10.0.0.1",
					"set routing-options static route 10.20.0.0/16 qualified-next-hop")
			},
		},
		{
			name: "flat set valueless only hop",
			build: func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t,
					"set routing-options static route ::/0 qualified-next-hop")
			},
		},
		{
			name: "hierarchical route-key inline valueless",
			build: func(t *testing.T) *ConfigTree {
				return hierTree(t, `routing-options { static { route 10.20.0.0/16 qualified-next-hop; } }`)
			},
			wantPath: "routing-options static route 10.20.0.0/16",
		},
		{
			name: "routing-instance valueless identity",
			build: func(t *testing.T) *ConfigTree {
				return hierTree(t, `routing-instances { blue { routing-options { static { route 10.20.0.0/16 { qualified-next-hop; } } } } }`)
			},
			wantPath: "routing-instances blue routing-options static route 10.20.0.0/16",
		},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(tc.build(t)); err == nil {
				t.Fatalf("strict CompileConfig accepted valueless qualified-next-hop")
			} else {
				if !strings.Contains(err.Error(), "qualified-next-hop") {
					t.Fatalf("error = %v, want it to name qualified-next-hop", err)
				}
				if !strings.Contains(err.Error(), "#12818") {
					t.Fatalf("error = %v, want #12818 tag", err)
				}
				if tc.wantPath != "" && !strings.Contains(err.Error(), tc.wantPath) {
					t.Fatalf("error = %v, want parent-chain path %q", err, tc.wantPath)
				}
			}
			if err := SchemaValidate(tc.build(t), nil); err == nil {
				t.Fatalf("SchemaValidate accepted valueless qualified-next-hop (parity broken the other way)")
			}
		})
	}

	t.Run("qualified-next-hop children without gateway accepted by both paths", func(t *testing.T) {
		const source = `routing-options { static { route 10.20.0.0/16 { qualified-next-hop { preference 5; } } } }`
		if _, err := CompileConfig(hierTree(t, source)); err != nil {
			t.Fatalf("strict CompileConfig rejected child-bearing QNH: %v", err)
		}
		if err := SchemaValidate(hierTree(t, source), nil); err != nil {
			t.Fatalf("SchemaValidate rejected child-bearing QNH: %v", err)
		}
	})

	// Mutant guard: a threshold check that only compares "no error" would
	// pass if the gate fired on EVERY qualified-next-hop. Valid gateways
	// and a route with only a plain next-hop must still compile to the same
	// hops.
	t.Run("valid qualified-next-hops unchanged", func(t *testing.T) {
		const v4 = `routing-options { static { route 10.20.0.0/16 { next-hop 10.0.0.1; qualified-next-hop 10.0.0.2 preference 250; } } }`
		cfg, err := CompileConfig(hierTree(t, v4))
		if err != nil {
			t.Fatalf("strict CompileConfig rejected valid IPv4 QNH: %v", err)
		}
		if err := SchemaValidate(hierTree(t, v4), nil); err != nil {
			t.Fatalf("SchemaValidate rejected valid IPv4 QNH: %v", err)
		}
		got := routeHops12813(t, cfg)
		if len(got) != 2 || got[0].Address != "10.0.0.1" || got[1].Address != "10.0.0.2" || got[1].Preference != 250 || !got[1].HasPreference {
			t.Fatalf("IPv4 NextHops = %+v, want primary 10.0.0.1 and backup 10.0.0.2 preference 250", got)
		}

		const v6 = `routing-options { static { route 2001:db8:1::/64 { qualified-next-hop 2001:db8:2::2; } } }`
		v6cfg, err := CompileConfig(hierTree(t, v6))
		if err != nil {
			t.Fatalf("strict CompileConfig rejected valid IPv6 QNH: %v", err)
		}
		if err := SchemaValidate(hierTree(t, v6), nil); err != nil {
			t.Fatalf("SchemaValidate rejected valid IPv6 QNH: %v", err)
		}
		if hops := findStaticRoute3871(t, v6cfg.RoutingOptions.StaticRoutes, "2001:db8:1::/64").NextHops; len(hops) != 1 || hops[0].Address != "2001:db8:2::2" {
			t.Fatalf("IPv6 NextHops = %+v, want gateway 2001:db8:2::2", hops)
		}

		const linkLocal = `routing-options { static { route 2001:db8:1::/64 { qualified-next-hop fe80::2 { interface ge-0/0/1.0; } } } }`
		if _, err := CompileConfig(hierTree(t, linkLocal)); err != nil {
			t.Fatalf("strict CompileConfig rejected valid interface-qualified link-local QNH: %v", err)
		}

		const plain = `routing-options { static { route 10.21.0.0/16 { next-hop 10.1.0.1; } } }`
		plainCfg, err := CompileConfig(hierTree(t, plain))
		if err != nil {
			t.Fatalf("strict CompileConfig rejected plain next-hop: %v", err)
		}
		plainHops := findStaticRoute3871(t, plainCfg.RoutingOptions.StaticRoutes, "10.21.0.0/16").NextHops
		if len(plainHops) != 1 || plainHops[0].Address != "10.1.0.1" {
			t.Fatalf("plain NextHops = %+v, want 10.1.0.1", plainHops)
		}
	})

	// Tolerant path keeps its established load semantics: it must not turn
	// an already-persisted valueless statement into a hard load failure.
	t.Run("lenient path does not hard-fail", func(t *testing.T) {
		tree := hierTree(t, `routing-options { static { route 10.20.0.0/16 { next-hop 10.0.0.1; qualified-next-hop; } } }`)
		if _, err := CompileConfigLenient(tree); err != nil {
			t.Fatalf("lenient CompileConfig hard-failed on valueless QNH: %v", err)
		}
	})
}
