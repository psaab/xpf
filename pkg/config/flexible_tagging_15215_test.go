package config

import (
	"testing"
)

// #15215 A28-03: flexible-vlan-tagging passes the #14574 gate, so every
// writer keyed on tagging must treat it like vlan-tagging. These cells
// pin the config-side writers (bridge-domain validator, RethVIPsForRG)
// against the vlan-tagging control; they fail if the writer keys only
// on VlanTagging.

func TestTaggingEnabledHelper15215(t *testing.T) {
	if (*InterfaceConfig)(nil).TaggingEnabled() {
		t.Error("nil interface must not report tagging enabled")
	}
	if (&InterfaceConfig{}).TaggingEnabled() {
		t.Error("untagged interface must not report tagging enabled")
	}
	if !(&InterfaceConfig{VlanTagging: true}).TaggingEnabled() {
		t.Error("vlan-tagging must report tagging enabled")
	}
	if !(&InterfaceConfig{FlexibleVlanTagging: true}).TaggingEnabled() {
		t.Error("flexible-vlan-tagging must report tagging enabled")
	}
}

func TestFlexibleBridgeDomainMemberAccepted15215(t *testing.T) {
	mk := func(vlanTagging, flexible bool) *Config {
		return &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {VlanTagging: vlanTagging, FlexibleVlanTagging: flexible, Units: map[int]*InterfaceUnit{
					0: {Number: 0, VlanID: 100, Addresses: []string{"192.0.2.1/24"}},
				}},
			}},
			BridgeDomains: []*BridgeDomainConfig{{Name: "bd0", VlanIDs: []int{100}, Members: []string{"ge-0/0/0.0"}}},
			Security: SecurityConfig{Zones: map[string]*ZoneConfig{
				"trust": {Interfaces: []string{"ge-0/0/0.0"}},
			}},
		}
	}
	for _, tc := range []struct {
		name string
		cfg  *Config
	}{
		{"vlan-tagging control", mk(true, false)},
		{"flexible-vlan-tagging", mk(false, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateBridgeDomainMembership11387(tc.cfg); err != nil {
				t.Fatalf("bridge-domain member rejected (%s): %v", tc.name, err)
			}
		})
	}
}

func TestFlexibleRethVIPsOnSubInterface15215(t *testing.T) {
	mk := func(vlanTagging, flexible bool) *Config {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"reth0": {
				Name: "reth0", RedundancyGroup: 1,
				VlanTagging: vlanTagging, FlexibleVlanTagging: flexible,
				Units: map[int]*InterfaceUnit{
					50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.6/24"}},
				},
			},
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		}
		return cfg
	}
	for _, tc := range []struct {
		name string
		cfg  *Config
	}{
		{"vlan-tagging control", mk(true, false)},
		{"flexible-vlan-tagging", mk(false, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.RethVIPsForRG(1)
			vips, ok := got["ge-0-0-0.50"]
			if !ok || len(vips) != 1 || vips[0] != "172.16.50.6/24" {
				t.Fatalf("RethVIPsForRG = %v (%s), want VIP on ge-0-0-0.50 sub-interface, not folded onto the untagged parent", got, tc.name)
			}
		})
	}
}
