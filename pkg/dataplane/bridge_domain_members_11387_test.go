package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

func TestBridgeDomainBridgeMasterUsesExplicitInterfaceVIDMembers11387(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {VlanTagging: true, Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, VlanID: 100},
				1: {Number: 1, VlanID: 200},
			}},
			"ge-0/0/1": {VlanTagging: true, Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, VlanID: 100},
			}},
		}},
		BridgeDomains: []*config.BridgeDomainConfig{{
			Name: "bd0", VlanIDs: []int{100}, Members: []string{"ge-0/0/0.0"},
		}},
	}
	result := &CompileResult{ManagedInterfaces: []networkd.InterfaceConfig{
		{Name: "ge-0-0-0.100"}, {Name: "ge-0-0-0.200"}, {Name: "ge-0-0-1.100"},
	}}
	buildBridgeDomainModels(cfg, result, map[string]bool{})

	got := map[string]string{}
	for _, iface := range result.ManagedInterfaces {
		if iface.BridgeMaster != "" {
			got[iface.Name] = iface.BridgeMaster
		}
	}
	if len(got) != 1 || got["ge-0-0-0.100"] != "br-bd0" {
		t.Fatalf("BridgeMaster map = %v; only explicitly declared logical unit ge-0/0/0.0 (VLAN 100) may join br-bd0", got)
	}
}

func TestBridgeDomainDuplicateVIDQuarantinesBridgePortsOnTolerantInput11387(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {VlanTagging: true, Units: map[int]*config.InterfaceUnit{0: {Number: 0, VlanID: 100}}},
		}},
		BridgeDomains: []*config.BridgeDomainConfig{
			{Name: "bd0", VlanIDs: []int{100}, Members: []string{"ge-0/0/0.0"}},
			{Name: "bd1", VlanIDs: []int{100}, Members: []string{"ge-0/0/0.0"}},
		},
	}
	result := &CompileResult{ManagedInterfaces: []networkd.InterfaceConfig{{Name: "ge-0-0-0.100"}}}
	buildBridgeDomainModels(cfg, result, map[string]bool{})
	for _, iface := range result.ManagedInterfaces {
		if iface.Name == "ge-0-0-0.100" && iface.BridgeMaster != "" {
			t.Fatalf("ambiguous VID was attached to %s", iface.BridgeMaster)
		}
	}
}
