package config

import (
	"reflect"
	"testing"
)

// #13217 (D3-11): compact/container spellings silently dropped authored values.
//
//   - `community { COMM1 members 65000:100; }` compiled with Members == []
//     because compilePolicyOptions checked Keys[0] == "members" on an
//     instance node whose Keys are ["COMM1", "members", "65000:100"].
//   - `rib-groups { rg1 import-rib [ inet.0 ]; }` compiled with
//     ImportRibs == [] because compileRoutingOptions reached rib-groups only
//     through a dead FindChildren("") arm plus a direct-child arm whose
//     compileRibGroup never read the instance node's own packed tail.

func compile13217(t *testing.T, input string) *Config {
	t.Helper()
	tree, parseErrs := NewParser(input).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse error: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func TestPolicyOptionsCommunityContainerInlineMembers13217(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"one-key container packed", `policy-options { community { COMM1 members 65000:100; } }`},
		{"direct packed", `policy-options { community COMM1 members 65000:100; }`},
		{"container block control", `policy-options { community { COMM1 { members 65000:100; } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compile13217(t, tc.input)
			cd := cfg.PolicyOptions.Communities["COMM1"]
			if cd == nil {
				t.Fatalf("COMM1 community not compiled")
			}
			if want := []string{"65000:100"}; !reflect.DeepEqual(cd.Members, want) {
				t.Fatalf("COMM1.Members = %v, want %v", cd.Members, want)
			}
		})
	}
}

func TestRibGroupContainerInlineImportRib13217(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"one-key container packed bracket", `routing-options { rib-groups { rg1 import-rib [ inet.0 ]; } }`},
		{"one-key container packed single", `routing-options { rib-groups { rg1 import-rib inet.0; } }`},
		{"direct packed", `routing-options { rib-groups rg1 import-rib [ inet.0 ]; }`},
		{"block control", `routing-options { rib-groups { rg1 { import-rib inet.0; } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compile13217(t, tc.input)
			rg := cfg.RoutingOptions.RibGroups["rg1"]
			if rg == nil {
				t.Fatalf("rg1 rib-group not compiled")
			}
			if want := []string{"inet.0"}; !reflect.DeepEqual(rg.ImportRibs, want) {
				t.Fatalf("rg1.ImportRibs = %v, want %v", rg.ImportRibs, want)
			}
		})
	}
}

// Guard for replacing the duplicate per-instance interface-routes walk with a
// copy from the already-compiled routing-options: the value must survive.
func TestRoutingInstanceInterfaceRoutesFromRoutingOptions13217(t *testing.T) {
	cfg := compile13217(t, `routing-options {
		rib-groups { rg1 { import-rib inet.0; } }
	}
	routing-instances {
		blue {
			instance-type virtual-router;
			routing-options {
				interface-routes { rib-group { inet rg1; } }
			}
		}
	}`)
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("RoutingInstances = %d, want 1", len(cfg.RoutingInstances))
	}
	if got := cfg.RoutingInstances[0].InterfaceRoutesRibGroup; got != "rg1" {
		t.Fatalf("InterfaceRoutesRibGroup = %q, want rg1", got)
	}
}
