package dataplane

import (
	"net"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// #9721: on a VRRP-backed RETH with vlan-tagging, a unit with no vlan-id has no
// sub-interface, so vrrp.CollectRethInstances binds that unit's instance to the
// member's VLAN PARENT device. buildInterfaceNetworkdModels gave every other
// device of the RETH the 169.254.<rg>.<node+1>/32 advert source and gave the
// parent nothing. The instance found no IPv4 source (resolveLocalIPv4 returns
// nil), sent no IPv4 advertisement, and both nodes could claim the unit's VIPs.
//
// The binding half is pinned in pkg/vrrp (reth_untagged_unit_binding_9721_test.go)
// on the same device NAMES this file asserts the source on: `ge-0-0-2` for
// unit 0 and `ge-0-0-2.80` for unit 80. This package cannot import pkg/vrrp
// (pkg/vrrp -> pkg/cluster -> pkg/dataplane), so the pairing is held from both
// sides: if either side moves to another device, one of the two cells goes red.
//
// FAIL-ON-REVERT: remove the parentAddrs block from the VLAN arm and the first
// cell goes red, because the parent model carries no address.

const src9721 = "169.254.1.1/32" // redundancy-group 1, node 0 -> .1

func rethVLANUntaggedCfg9721(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-9721",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		// The issue's shape: an addressed unit with no vlan-id, beside a tagged one.
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 0 family inet address 172.16.50.8/24",
		"set interfaces reth0 unit 80 vlan-id 80",
		"set interfaces reth0 unit 80 family inet address 172.16.80.8/24",
		// Control: a tagged-only VRRP-backed RETH whose untagged unit carries no
		// address, so it builds no VRRP instance and needs no source.
		"set interfaces ge-0/0/4 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 0 description no-addresses",
		"set interfaces reth1 unit 50 vlan-id 50",
		"set interfaces reth1 unit 50 family inet address 172.16.51.8/24",
		// Control: the same untagged shape on a plain, non-RETH interface.
		"set interfaces ge-0/0/3 vlan-tagging",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
		"set interfaces ge-0/0/3 unit 30 vlan-id 30",
		"set interfaces ge-0/0/3 unit 30 family inet address 10.0.30.1/24",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	// Strict: the fix renders this shape; it does not reject it.
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile of the legacy-mode RETH fixture: %v", err)
	}
	return cfg
}

// models9721 runs the generator with every member netdev seeded, so no model is
// skipped for a missing device and no control below can pass vacuously.
func models9721(t *testing.T, cfg *config.Config) map[string]networkd.InterfaceConfig {
	t.Helper()
	result := &CompileResult{ifCache: map[string]*net.Interface{}}
	for i, name := range []string{"ge-0-0-2", "ge-0-0-3", "ge-0-0-4"} {
		result.ifCache[name] = &net.Interface{
			Index:        70 + i,
			Name:         name,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, byte(2 + i)},
		}
	}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	out := map[string]networkd.InterfaceConfig{}
	for _, m := range result.ManagedInterfaces {
		out[m.Name] = m
	}
	return out
}

func modelNames9721(models map[string]networkd.InterfaceConfig) []string {
	names := make([]string, 0, len(models))
	for n := range models {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func TestVRRPRethVLANParentCarriesTheAdvertSourceForAnUntaggedUnit_9721(t *testing.T) {
	models := models9721(t, rethVLANUntaggedCfg9721(t))

	parent, ok := models["ge-0-0-2"]
	if !ok {
		t.Fatalf("no networkd model for reth0's member ge-0-0-2; models=%v", modelNames9721(models))
	}
	if !parent.IsVLANParent {
		t.Fatalf("ge-0-0-2 is not rendered as a VLAN parent: %+v", parent)
	}
	if len(parent.VLANParentAddresses) != 1 || parent.VLANParentAddresses[0] != src9721 {
		t.Errorf("reth0's VLAN parent carries %v, want the VRRP advert source [%s]: unit 0 has no "+
			"vlan-id, so its VRRP instance is bound to this device and has no other IPv4 source",
			parent.VLANParentAddresses, src9721)
	}
	if !parent.KeepAddresses {
		t.Errorf("reth0's VLAN parent carries the source but not KeepAddresses: a networkctl reload " +
			"would strip the VIPs VRRP adds to it")
	}
	if len(parent.Addresses) != 0 {
		t.Errorf("reth0's VLAN parent carries unit addresses %v; the VIPs belong to VRRP", parent.Addresses)
	}

	// Non-vacuity: the fixture really is VRRP-backed. The tagged sub-interface
	// gets the same source by the pre-existing rule.
	if sub, ok := models["ge-0-0-2.80"]; !ok || len(sub.Addresses) != 1 || sub.Addresses[0] != src9721 {
		t.Errorf("ge-0-0-2.80 = %+v (present=%v), want Addresses [%s]; the fixture is not VRRP-backed",
			sub, ok, src9721)
	}
}

func TestVLANParentSourceIsOnlyForAnAddressedUntaggedUnitOfAVRRPReth_9721(t *testing.T) {
	models := models9721(t, rethVLANUntaggedCfg9721(t))
	for _, tc := range []struct{ name, why string }{
		{"ge-0-0-4", "reth1's only untagged unit has no address, so it builds no VRRP instance"},
		{"ge-0-0-3", "ge-0/0/3 is not a RETH, so nothing advertises from it"},
	} {
		m, ok := models[tc.name]
		if !ok {
			t.Errorf("no model for %s (the control would be vacuous); models=%v", tc.name, modelNames9721(models))
			continue
		}
		if !m.IsVLANParent {
			t.Errorf("%s is not rendered as a VLAN parent: %+v", tc.name, m)
		}
		if len(m.VLANParentAddresses) != 0 || m.KeepAddresses {
			t.Errorf("%s carries VLANParentAddresses=%v KeepAddresses=%v, want neither: %s",
				tc.name, m.VLANParentAddresses, m.KeepAddresses, tc.why)
		}
	}
	// Non-vacuity for the reth1 control: it IS VRRP-backed.
	if sub, ok := models["ge-0-0-4.50"]; !ok || len(sub.Addresses) != 1 || sub.Addresses[0] != src9721 {
		t.Errorf("ge-0-0-4.50 = %+v (present=%v), want Addresses [%s]; the reth1 control is not VRRP-backed",
			sub, ok, src9721)
	}
}
