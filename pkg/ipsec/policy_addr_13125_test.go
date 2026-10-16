package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13125 (D10-08): interfaceRefIsDHCP split on the first dot and never
// resolved RETH, so gateways on reth0.0 (DHCP physical member) or on a
// #9821 declared dotted name (wan.ext.0) never triggered the #2884 DHCP
// rebind, and selectUnitAddress ignored VRRP VirtualAddresses so a
// VIP-only reth gateway resolved no local_addrs and was skipped.
func TestPolicyAddr13125RethDottedAndVRRP(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name:            "ge-0/0/0",
					RedundantParent: "reth0",
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0, DHCP: true},
					},
				},
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							Number: 0,
							VRRPGroups: map[string]*config.VRRPGroup{
								"1": {ID: 1, VirtualAddresses: []string{"198.51.100.254/24"}},
							},
						},
					},
				},
				"wan.ext": {
					Name: "wan.ext",
					Units: map[int]*config.InterfaceUnit{
						0: {Number: 0, DHCP: true, Addresses: []string{"192.0.2.20/24"}},
					},
				},
			},
		},
		Security: config.SecurityConfig{IPsec: config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"gw-reth":   {Name: "gw-reth", Address: "203.0.113.1", ExternalIface: "reth0.0"},
				"gw-dotted": {Name: "gw-dotted", Address: "203.0.113.2", ExternalIface: "wan.ext.0"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"vpn-reth": {PSK: "fixture-secret", Gateway: "gw-reth", LocalID: "10.0.1.0/24", RemoteID: "10.0.2.0/24"},
			},
		}},
	}

	if !HasDHCPBoundGateway(cfg) {
		t.Errorf("HasDHCPBoundGateway = false, want true: reth0.0 member and wan.ext.0 are DHCP-managed")
	}
	if !interfaceRefIsDHCP(cfg, "reth0.0") {
		t.Errorf("interfaceRefIsDHCP(reth0.0) = false, want true via ResolveReth physical member")
	}
	if !interfaceRefIsDHCP(cfg, "wan.ext.0") {
		t.Errorf("interfaceRefIsDHCP(wan.ext.0) = false, want true for declared dotted interface wan.ext unit 0")
	}
	if got := resolveConfiguredInterfaceAddress(cfg, "wan.ext.0", 4); got != "192.0.2.20" {
		t.Errorf("resolveConfiguredInterfaceAddress(wan.ext.0, 4) = %q, want %q", got, "192.0.2.20")
	}
	if got := resolveConfiguredInterfaceAddress(cfg, "reth0.0", 4); got != "198.51.100.254" {
		t.Errorf("resolveConfiguredInterfaceAddress(reth0.0, 4) = %q, want VRRP VIP %q", got, "198.51.100.254")
	}

	prepared := PrepareConfig(cfg)
	if prepared == nil {
		t.Fatal("PrepareConfig returned nil")
	}
	if got := prepared.Gateways["gw-reth"].LocalAddress; got != "198.51.100.254" {
		t.Errorf("gw-reth LocalAddress = %q, want VRRP VIP %q", got, "198.51.100.254")
	}
	if got := prepared.Gateways["gw-dotted"].LocalAddress; got != "192.0.2.20" {
		t.Errorf("gw-dotted LocalAddress = %q, want %q", got, "192.0.2.20")
	}
	_, rendered, err := (&Manager{}).renderConfig(prepared)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if !rendered["vpn-reth"] {
		t.Error("renderConfig skipped vpn-reth despite its resolved VRRP VIP local address")
	}

	// Control: a non-DHCP, non-VIP interface stays non-DHCP.
	plain := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"192.0.2.30/24"}},
				}},
			},
		},
	}
	if interfaceRefIsDHCP(plain, "ge-0/0/1.0") {
		t.Errorf("interfaceRefIsDHCP(ge-0/0/1.0) = true, want false for static unit")
	}
}
