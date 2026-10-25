package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16590: CollectRethInstances (VRRP-backed mode) must agree with
// RethVIPsForRG (direct mode) on disabled units/interfaces — otherwise a
// mode toggle resurrects a disabled address as a VRRP VIP.

func rethCfg16590(tagged, disableIfc, disable80 bool) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name: "reth0", RedundancyGroup: 1, Disable: disableIfc, VlanTagging: tagged,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
				80: {Number: 80, VlanID: 80, Disable: disable80, Addresses: []string{"172.16.80.8/24"}},
			},
		},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
	}
	if !tagged {
		cfg.Interfaces.Interfaces["reth0"].Units = map[int]*config.InterfaceUnit{
			0: {Number: 0, Disable: disable80, Addresses: []string{"10.0.1.1/24"}},
		}
	}
	return cfg
}

func TestCollectRethInstancesDisabled16590(t *testing.T) {
	// Tagged, unit 80 disabled: only .50 instance.
	insts := CollectRethInstances(rethCfg16590(true, false, true), map[int]int{1: 100})
	if len(insts) != 1 || insts[0].Interface != "ge-0-0-2.50" {
		t.Fatalf("tagged disabled unit: got %+v", insts)
	}
	// Tagged control: both.
	insts = CollectRethInstances(rethCfg16590(true, false, false), map[int]int{1: 100})
	if len(insts) != 2 {
		t.Fatalf("tagged control: got %d instances %+v", len(insts), insts)
	}
	// Interface disabled: none.
	if insts := CollectRethInstances(rethCfg16590(true, true, false), map[int]int{1: 100}); len(insts) != 0 {
		t.Fatalf("interface disabled: got %+v", insts)
	}
	// Untagged disabled unit: none; control: one.
	if insts := CollectRethInstances(rethCfg16590(false, false, true), map[int]int{1: 100}); len(insts) != 0 {
		t.Fatalf("untagged disabled unit: got %+v", insts)
	}
	if insts := CollectRethInstances(rethCfg16590(false, false, false), map[int]int{1: 100}); len(insts) != 1 {
		t.Fatalf("untagged control: got %+v", insts)
	}
}
