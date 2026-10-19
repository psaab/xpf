package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15215 A28-03: a flexible-vlan-tagging RETH must collect one VRRP
// instance per tagged sub-interface, like the vlan-tagging control —
// not fold every unit's VIPs onto the untagged parent device.

func TestFlexibleCollectRethInstances15215(t *testing.T) {
	mk := func(vlanTagging, flexible bool) *config.Config {
		return &config.Config{
			Interfaces: config.InterfacesConfig{
				Interfaces: map[string]*config.InterfaceConfig{
					"reth0": {
						Name:            "reth0",
						RedundancyGroup: 1,
						VlanTagging:     vlanTagging, FlexibleVlanTagging: flexible,
						Units: map[int]*config.InterfaceUnit{
							50: {VlanID: 50, Addresses: []string{"172.16.50.6/24"}},
						},
					},
					"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				},
			},
		}
	}
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"vlan-tagging control", mk(true, false)},
		{"flexible-vlan-tagging", mk(false, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instances := CollectRethInstances(tc.cfg, map[int]int{1: 200})
			if len(instances) != 1 {
				t.Fatalf("instances = %d (%s), want 1: %+v", len(instances), tc.name, instances)
			}
			if instances[0].Interface != "ge-0-0-0.50" {
				t.Errorf("Interface = %q (%s), want ge-0-0-0.50 — VIP folded onto untagged parent", instances[0].Interface, tc.name)
			}
		})
	}
}
