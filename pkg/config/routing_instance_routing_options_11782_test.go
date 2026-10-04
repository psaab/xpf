package config

import (
	"reflect"
	"testing"
)

// These cells fail if compileRoutingInstances stops carrying any of the
// routing-options fields it parses into its local RoutingOptionsConfig.
func TestRoutingInstanceRoutingOptionsCarryAllCompiledFields11782(t *testing.T) {
	cases := []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{
			name: "hierarchical",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `policy-options {
					policy-statement export-policy { term t { then accept; } }
				}
				routing-instances {
					edge {
						instance-type virtual-router;
						routing-options {
							generate { route 198.51.100.0/24 discard; }
							rib-groups { leak { import-rib inet.0; } }
							forwarding-table { export export-policy; }
						}
					}
				}`)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.tree(t))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0] == nil {
				t.Fatalf("compiled routing instances = %+v, want one edge instance", cfg.RoutingInstances)
			}
			ri := cfg.RoutingInstances[0]
			if len(ri.GenerateRoutes) != 1 || ri.GenerateRoutes[0] == nil {
				t.Errorf("per-instance GenerateRoutes = %+v, want one generated route", ri.GenerateRoutes)
			} else if got := *ri.GenerateRoutes[0]; got != (GenerateRoute{Prefix: "198.51.100.0/24", Discard: true}) {
				t.Errorf("per-instance generate route = %+v, want prefix and discard preserved", got)
			}
			if got, want := ri.RibGroups["leak"], (&RibGroup{Name: "leak", ImportRibs: []string{"inet.0"}}); !reflect.DeepEqual(got, want) {
				t.Errorf("per-instance rib-group = %+v, want %+v", got, want)
			}
			if got, want := ri.ForwardingTableExport, "export-policy"; got != want {
				t.Errorf("per-instance ForwardingTableExport = %q, want %q", got, want)
			}
			if got, want := ri.ForwardingTableExports, []string{"export-policy"}; !reflect.DeepEqual(got, want) {
				t.Errorf("per-instance ForwardingTableExports = %q, want %q", got, want)
			}
			if len(cfg.RoutingOptions.GenerateRoutes) != 0 || len(cfg.RoutingOptions.RibGroups) != 0 ||
				cfg.RoutingOptions.ForwardingTableExport != "" || len(cfg.RoutingOptions.ForwardingTableExports) != 0 {
				t.Errorf("instance routing-options leaked into global config: %+v", cfg.RoutingOptions)
			}
		})
	}
}
