package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13549: on a VRRP-backed RETH with vlan-tagging, the VLAN branch in
// buildInterfaceNetworkdModels replaces a tagged unit's VIP addresses with
// the 169.254.<rg>.<node+1>/32 link-local advert source (as the non-VLAN
// branch does) but forwarded unit.PrimaryAddress / unit.PreferredAddress
// uncleared. The non-VLAN branch zeroes both on replacement; the VLAN
// branch leaked the stale VIP metadata, so networkd's orderAddresses /
// PreferredLifetime rendering was told the primary/preferred address is
// 192.0.2.1/24 while Addresses contains only 169.254.1.1/32.
//
// Cells:
//   - ge-0-0-2.80 (VRRP RETH, tagged, primary+preferred VIP): Addresses
//     replaced, Primary/Preferred must be cleared.
//   - ge-0-0-3.30 (plain VLAN, tagged, primary+preferred): no replacement,
//     metadata must survive untouched (control against blanket clearing).
//
// FAIL-ON-REVERT: forwarding unit.PrimaryAddress/PreferredAddress in the
// VLAN branch makes the first cell fail with the stale 192.0.2.1/24.

const staleProbe13549 = "192.0.2.1/24"
const llSource13549 = "169.254.1.1/32" // redundancy-group 1, node 0 -> .1

func rethVLANStalePrimaryCfg13549(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-13549",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 1",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		// VRRP-backed RETH, tagged unit whose VIP is primary+preferred.
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 80 vlan-id 80",
		"set interfaces reth0 unit 80 family inet address " + staleProbe13549 + " primary",
		"set interfaces reth0 unit 80 family inet address " + staleProbe13549 + " preferred",
		// Control: plain (non-RETH) VLAN interface, same metadata shape.
		"set interfaces ge-0/0/3 vlan-tagging",
		"set interfaces ge-0/0/3 unit 30 vlan-id 30",
		"set interfaces ge-0/0/3 unit 30 family inet address 10.0.30.1/24 primary",
		"set interfaces ge-0/0/3 unit 30 family inet address 10.0.30.1/24 preferred",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// Non-vacuity at the config layer: the probe really is primary+preferred.
	reth := cfg.Interfaces.Interfaces["reth0"]
	if reth == nil || reth.Units[80].PrimaryAddress != staleProbe13549 || reth.Units[80].PreferredAddress != staleProbe13549 {
		t.Fatalf("fixture lost primary/preferred probe: %+v", reth)
	}
	return cfg
}

func TestVRRPRethVLANReplacementClearsStalePrimaryPreferred_13549(t *testing.T) {
	cfg := rethVLANStalePrimaryCfg13549(t)
	result := &CompileResult{ifCache: map[string]*net.Interface{}}
	for i, name := range []string{"ge-0-0-2", "ge-0-0-3"} {
		result.ifCache[name] = &net.Interface{
			Index:        80 + i,
			Name:         name,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, byte(2 + i)},
		}
	}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	models := map[string]bool{}
	var sub, ctrl bool
	for _, m := range result.ManagedInterfaces {
		models[m.Name] = true
		switch m.Name {
		case "ge-0-0-2.80":
			sub = true
			if len(m.Addresses) != 1 || m.Addresses[0] != llSource13549 {
				t.Errorf("ge-0-0-2.80 Addresses = %v, want [%s] (fixture not VRRP-backed?)", m.Addresses, llSource13549)
			}
			if m.PrimaryAddress != "" {
				t.Errorf("ge-0-0-2.80 PrimaryAddress = %q, want cleared: addresses were replaced with %s, stale primary %s is not among them",
					m.PrimaryAddress, llSource13549, staleProbe13549)
			}
			if m.PreferredAddress != "" {
				t.Errorf("ge-0-0-2.80 PreferredAddress = %q, want cleared: addresses were replaced with %s, stale preferred %s is not among them",
					m.PreferredAddress, llSource13549, staleProbe13549)
			}
		case "ge-0-0-3.30":
			ctrl = true
			if len(m.Addresses) != 1 || m.Addresses[0] != "10.0.30.1/24" {
				t.Errorf("ge-0-0-3.30 Addresses = %v, want [10.0.30.1/24] (control broken)", m.Addresses)
			}
			if m.PrimaryAddress != "10.0.30.1/24" || m.PreferredAddress != "10.0.30.1/24" {
				t.Errorf("ge-0-0-3.30 Primary/Preferred = %q/%q, want both 10.0.30.1/24 preserved: no replacement happened on the control",
					m.PrimaryAddress, m.PreferredAddress)
			}
		}
	}
	if !sub || !ctrl {
		t.Fatalf("missing models sub=%v ctrl=%v in %v", sub, ctrl, models)
	}
}
