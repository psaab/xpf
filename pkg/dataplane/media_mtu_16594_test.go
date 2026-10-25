package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16594 acceptance at the actuator: a compiled config with authored
// `mtu 1514` (already translated to L3 1500 by pkg/config) plans
// netdev 1500 in planPhysDesired — the value LinkSetMTU writes — and
// the networkd model carries 1500 (MTUBytes=1500). Tagged: 1496.
// These cells build the config through the real compiler so a revert
// of the compile-time translation reddens them end to end.

func compile16594(t *testing.T, sets ...string) *config.Config {
	t.Helper()
	// Reuse pkg/config's exported strict compile via a tiny tree built
	// from hierarchical text is not available here; construct through
	// config's parser the same way production does.
	tree, errs := config.NewParser(joinSets16594(sets)).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func joinSets16594(sets []string) string {
	out := ""
	for _, s := range sets {
		out += s + "\n"
	}
	return out
}

func TestPlanPhysDesiredMediaMTU1514Yields1500_16594(t *testing.T) {
	cfg := compile16594(t,
		"interfaces { ge-0/0/1 { mtu 1514; unit 0 { family inet { address 10.0.1.1/24; } } } }",
		"security { zones { security-zone trust { interfaces { ge-0/0/1.0; } } } }",
	)
	if got := cfg.Interfaces.Interfaces["ge-0/0/1"].MTU; got != 1500 {
		t.Fatalf("compiled MTU = %d, want 1500", got)
	}
	pd := planPhysDesired(cfg)["ge-0-0-1"]
	if pd == nil || pd.mtu != 1500 || !pd.mtuExplicit {
		t.Fatalf("plan = %+v, want mtu 1500 explicit", pd)
	}
}

func TestPlanPhysDesiredMediaMTUTaggedYields1496_16594(t *testing.T) {
	cfg := compile16594(t,
		"interfaces { ge-0/0/1 { vlan-tagging; mtu 1514; unit 50 { vlan-id 50; family inet { address 10.0.50.1/24; } } } }",
		"security { zones { security-zone trust { interfaces { ge-0/0/1.50; } } } }",
	)
	pd := planPhysDesired(cfg)["ge-0-0-1"]
	if pd == nil || pd.mtu != 1496 {
		t.Fatalf("tagged plan = %+v, want parent mtu 1496 (1514-18)", pd)
	}
	// The VLAN child's own MTU still belongs to the child; a family
	// mtu 1500 on the child does not raise the parent.
	cfg2 := compile16594(t,
		"interfaces { ge-0/0/1 { vlan-tagging; mtu 1514; unit 50 { vlan-id 50; family inet { address 10.0.50.1/24; mtu 1400; } } } }",
		"security { zones { security-zone trust { interfaces { ge-0/0/1.50; } } } }",
	)
	if pd := planPhysDesired(cfg2)["ge-0-0-1"]; pd == nil || pd.mtu != 1496 {
		t.Fatalf("tagged plan with child family mtu = %+v, want 1496", pd)
	}
}

func TestNetworkdModelMediaMTU1514Yields1500_16594(t *testing.T) {
	cfg := compile16594(t,
		"interfaces { ge-0/0/1 { mtu 1514; unit 0 { family inet { address 10.0.1.1/24; } } } }",
		"security { zones { security-zone trust { interfaces { ge-0/0/1.0; } } } }",
	)
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"ge-0-0-1": {Index: 7, Name: "ge-0-0-1", HardwareAddr: net.HardwareAddr{0x52, 0x54, 0, 0, 0, 7}},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	found := false
	for _, m := range result.ManagedInterfaces {
		if m.Name == "ge-0-0-1" {
			found = true
			if m.MTU != 1500 {
				t.Fatalf("networkd model MTU = %d, want 1500 (MTUBytes=1500)", m.MTU)
			}
		}
		if m.MTU == 1514 {
			t.Fatalf("model %s carries untranslated 1514", m.Name)
		}
	}
	if !found {
		t.Fatalf("no networkd model for ge-0-0-1: %+v", result.ManagedInterfaces)
	}
}

func TestNetworkdModelTaggedParentAndChild_16594(t *testing.T) {
	cfg := compile16594(t,
		"interfaces { ge-0/0/1 { vlan-tagging; mtu 1518; unit 50 { vlan-id 50; family inet { address 10.0.50.1/24; mtu 1400; } } } }",
		"security { zones { security-zone trust { interfaces { ge-0/0/1.50; } } } }",
	)
	result := &CompileResult{ifCache: map[string]*net.Interface{
		"ge-0-0-1": {Index: 7, Name: "ge-0-0-1", HardwareAddr: net.HardwareAddr{0x52, 0x54, 0, 0, 0, 7}},
	}}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	byName := map[string]int{}
	for _, m := range result.ManagedInterfaces {
		byName[m.Name] = m.MTU
	}
	if got := byName["ge-0-0-1"]; got != 1500 {
		t.Fatalf("tagged parent model MTU = %d, want 1500 (1518-18)", got)
	}
	if got := byName["ge-0-0-1.50"]; got != 1400 {
		t.Fatalf("VLAN child model MTU = %d, want family 1400 untranslated", got)
	}
}

// Direct-construction control: the dataplane trusts the compiled L3
// value verbatim (no second translation at the actuator). A hand-built
// MTU 1500 plans 1500 — pinning that translation happens once, at
// compile, not per writer.
func TestPlanPhysDesiredDoesNotRetranslate_16594(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.0"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1", MTU: 1500,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.0.1.1/24"}},
				},
			},
		}},
	}
	if pd := planPhysDesired(cfg)["ge-0-0-1"]; pd == nil || pd.mtu != 1500 {
		t.Fatalf("plan = %+v, want 1500 (no actuator retranslation)", pd)
	}
}
