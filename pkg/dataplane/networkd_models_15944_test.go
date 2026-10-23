package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// #15944 H4-04 (networkd arm): buildBridgeDomainModels emitted only
// {Name, IsBridge, Addresses} for `br-<bd>`, and buildFabricBondModels
// only the interface-level MTU — the IRB/fab units' MTU,
// primary/preferred (and DHCP/disable) never reached the emitted
// ManagedInterfaces entries, unlike sibling networkd paths.
//
// FAIL-ON-REVERT: restoring the address-only bridge emit (or the
// interface-only bond MTU) zeroes the asserted fields below.

func TestBridgeDomainModelCarriesIRBUnitSettings15944(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"irb": {Name: "irb", MTU: 9000, Units: map[int]*config.InterfaceUnit{
				10: {Number: 10, MTU: 1400,
					Addresses:        []string{"10.10.0.2/24", "10.10.0.3/24", "2001:db8:10::2/64"},
					PrimaryAddress:   "10.10.0.2/24",
					PreferredAddress: "10.10.0.3/24",
					PrimaryAddressV6: "2001:db8:10::2/64",
					DADDisable:       true},
			}},
		}},
		BridgeDomains: []*config.BridgeDomainConfig{{
			Name: "bd0", RoutingInterface: "irb.10",
		}},
	}
	result := &CompileResult{}
	buildBridgeDomainModels(cfg, result, map[string]bool{})
	var br *networkd.InterfaceConfig
	for i := range result.ManagedInterfaces {
		if result.ManagedInterfaces[i].Name == "br-bd0" {
			br = &result.ManagedInterfaces[i]
		}
	}
	if br == nil {
		t.Fatalf("no br-bd0 model emitted: %+v", result.ManagedInterfaces)
	}
	if br.MTU != 1400 {
		t.Errorf("br-bd0 MTU = %d, want 1400 (unit MTU wins over interface 9000)", br.MTU)
	}
	if br.PrimaryAddress != "10.10.0.2/24" || br.PreferredAddress != "10.10.0.3/24" {
		t.Errorf("br-bd0 primary/preferred = %q/%q, want 10.10.0.2/24 / 10.10.0.3/24", br.PrimaryAddress, br.PreferredAddress)
	}
	if br.PrimaryAddressV6 != "2001:db8:10::2/64" {
		t.Errorf("br-bd0 primaryV6 = %q, want 2001:db8:10::2/64", br.PrimaryAddressV6)
	}
	if !br.DADDisable {
		t.Error("br-bd0 DADDisable = false, want true from the IRB unit")
	}
	if len(br.Addresses) != 3 {
		t.Errorf("br-bd0 Addresses = %v, want the unit's 3 addresses", br.Addresses)
	}
}

func TestFabricBondModelCarriesUnitSettings15944(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fab0": {
			Name:          "fab0",
			MTU:           9000,
			FabricMembers: []string{"ge-0/0/1", "ge-0/0/2"},
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, MTU: 1400,
					Addresses:        []string{"10.99.0.2/24", "10.99.0.3/24"},
					PrimaryAddress:   "10.99.0.2/24",
					PreferredAddress: "10.99.0.3/24"},
			},
		},
	}
	result2 := &CompileResult{}
	buildFabricBondModels(cfg, result2, map[string]bool{})
	var bond *networkd.InterfaceConfig
	for i := range result2.ManagedInterfaces {
		if result2.ManagedInterfaces[i].IsBond {
			bond = &result2.ManagedInterfaces[i]
		}
	}
	if bond == nil {
		t.Fatalf("no bond model emitted: %+v", result2.ManagedInterfaces)
	}
	if bond.MTU != 1400 {
		t.Errorf("bond MTU = %d, want 1400 (unit MTU min-fold wins over interface 9000)", bond.MTU)
	}
	if bond.PrimaryAddress != "10.99.0.2/24" || bond.PreferredAddress != "10.99.0.3/24" {
		t.Errorf("bond primary/preferred = %q/%q, want 10.99.0.2/24 / 10.99.0.3/24", bond.PrimaryAddress, bond.PreferredAddress)
	}
}
