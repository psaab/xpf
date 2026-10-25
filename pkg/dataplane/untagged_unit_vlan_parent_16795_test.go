package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// #16795: untagged unit 0 on a tagged non-RETH, non-VRRP parent. The netlink
// reconcile (planPhysDesired) installs the unit's address on the parent, but
// the parent's networkd row rendered no address and no keep, so networkd's
// own reconfigure tail stripped it as foreign at the end of every apply
// whose files changed.
//
// FAIL-ON-REVERT: revert untaggedUnitAddresses (or its call in
// buildInterfaceNetworkdModels) and the first cell goes RED — the parent
// model carries no VLANParentAddresses and no KeepAddresses. The rendered
// .network half (Address=10.0.0.1/24, KeepConfiguration=static) is pinned
// in pkg/networkd (vlan_parent_untagged_unit_16795_test.go), which owns
// generateNetwork; this package pins the model that feeds it.

func untaggedVLANParentCfg16795(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		// The issue's shape, in both tagging modes.
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 50 vlan-id 50",
		"set interfaces ge-0/0/1 unit 50 family inet address 10.0.50.1/24",
		"set interfaces ge-0/0/6 flexible-vlan-tagging",
		"set interfaces ge-0/0/6 unit 0 family inet address 10.0.6.1/24",
		"set interfaces ge-0/0/6 unit 60 vlan-id 60",
		"set interfaces ge-0/0/6 unit 60 family inet address 10.0.60.1/24",
		// Control: tagged-only parent — no untagged unit, nothing to carry.
		"set interfaces ge-0/0/2 vlan-tagging",
		"set interfaces ge-0/0/2 unit 30 vlan-id 30",
		"set interfaces ge-0/0/2 unit 30 family inet address 10.0.30.1/24",
		// Control: untagged unit carries a standalone vrrp-group — its real
		// address stays VIP-foreign (KeepForeignStatic), NOT rendered (#15061).
		"set interfaces ge-0/0/3 vlan-tagging",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.2/24 vrrp-group 3 virtual-address 10.0.3.1",
		"set interfaces ge-0/0/3 unit 33 vlan-id 33",
		"set interfaces ge-0/0/3 unit 33 family inet address 10.0.33.1/24",
		// Control: disabled untagged unit contributes nothing (#14575).
		"set interfaces ge-0/0/4 vlan-tagging",
		"set interfaces ge-0/0/4 unit 0 disable",
		"set interfaces ge-0/0/4 unit 0 family inet address 10.0.4.1/24",
		"set interfaces ge-0/0/4 unit 44 vlan-id 44",
		"set interfaces ge-0/0/4 unit 44 family inet address 10.0.44.1/24",
		// RETH control (reth0 member ge-0/0/5), judged by the #9721 cells:
		// its parent carries only the advert source, never the unit's VIP.
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-16795",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 1",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces ge-0/0/5 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 0 family inet address 172.16.50.8/24",
		"set interfaces reth0 unit 80 vlan-id 80",
		"set interfaces reth0 unit 80 family inet address 172.16.80.8/24",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	// Strict: the fix renders this shape; it does not reject it. Zone refs
	// are unnecessary — buildInterfaceNetworkdModels iterates interfaces.
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile of untagged-on-tagged fixture: %v", err)
	}
	return cfg
}

func models16795(t *testing.T, cfg *config.Config) map[string]networkd.InterfaceConfig {
	t.Helper()
	result := &CompileResult{ifCache: map[string]*net.Interface{}}
	for i, name := range []string{"ge-0-0-1", "ge-0-0-2", "ge-0-0-3", "ge-0-0-4", "ge-0-0-5", "ge-0-0-6"} {
		result.ifCache[name] = &net.Interface{
			Index:        90 + i,
			Name:         name,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x02, byte(i)},
		}
	}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	out := map[string]networkd.InterfaceConfig{}
	for _, m := range result.ManagedInterfaces {
		out[m.Name] = m
	}
	return out
}

func TestUntaggedUnitOnTaggedParentCarriesItsAddress16795(t *testing.T) {
	models := models16795(t, untaggedVLANParentCfg16795(t))

	for _, tc := range []struct {
		name, addr, sub, subAddr string
	}{
		{"ge-0-0-1", "10.0.0.1/24", "ge-0-0-1.50", "10.0.50.1/24"}, // vlan-tagging
		{"ge-0-0-6", "10.0.6.1/24", "ge-0-0-6.60", "10.0.60.1/24"}, // flexible-vlan-tagging
	} {
		parent, ok := models[tc.name]
		if !ok {
			t.Fatalf("no model for %s", tc.name)
		}
		if !parent.IsVLANParent {
			t.Fatalf("%s is not rendered as a VLAN parent: %+v", tc.name, parent)
		}
		if len(parent.VLANParentAddresses) != 1 || parent.VLANParentAddresses[0] != tc.addr {
			t.Errorf("%s VLANParentAddresses=%v, want [%s]: planPhysDesired installs the untagged "+
				"unit's address on the parent, so the parent row must own it", tc.name, parent.VLANParentAddresses, tc.addr)
		}
		if !parent.KeepAddresses {
			t.Errorf("%s carries an untagged unit's address but not KeepAddresses: a networkctl "+
				"reconfigure would strip it", tc.name)
		}
		if len(parent.Addresses) != 0 {
			t.Errorf("%s carries Addresses=%v; the tagged unit's address belongs on the child", tc.name, parent.Addresses)
		}
		// Non-vacuity + no leak: the tagged sibling keeps its own address.
		sub, ok := models[tc.sub]
		if !ok || len(sub.Addresses) != 1 || sub.Addresses[0] != tc.subAddr {
			t.Errorf("%s = %+v (present=%v), want Addresses [%s]", tc.sub, sub, ok, tc.subAddr)
		}
	}
}

func TestUntaggedUnitOnTaggedParentControls16795(t *testing.T) {
	models := models16795(t, untaggedVLANParentCfg16795(t))

	for _, tc := range []struct{ name, why string }{
		{"ge-0-0-2", "tagged-only parent has no untagged unit to carry"},
		{"ge-0-0-4", "its untagged unit is disabled (#14575)"},
	} {
		m, ok := models[tc.name]
		if !ok {
			t.Fatalf("no model for %s (the control would be vacuous)", tc.name)
		}
		if !m.IsVLANParent {
			t.Errorf("%s is not rendered as a VLAN parent: %+v", tc.name, m)
		}
		if len(m.VLANParentAddresses) != 0 || m.KeepAddresses || m.KeepForeignStatic {
			t.Errorf("%s carries VLANParentAddresses=%v KeepAddresses=%v KeepForeignStatic=%v, want none: %s",
				tc.name, m.VLANParentAddresses, m.KeepAddresses, m.KeepForeignStatic, tc.why)
		}
	}

	// Standalone-VRRP untagged unit: real address NOT rendered; the foreign
	// VIP keep must survive alone (#15061), exactly as before.
	m3, ok := models["ge-0-0-3"]
	if !ok {
		t.Fatalf("no model for ge-0-0-3")
	}
	if len(m3.VLANParentAddresses) != 0 {
		t.Errorf("ge-0-0-3 VLANParentAddresses=%v, want none: a standalone vrrp-group unit's address is a VIP "+
			"owned by VRRP, not a static address for networkd to render", m3.VLANParentAddresses)
	}
	if !m3.KeepAddresses || !m3.KeepForeignStatic {
		t.Errorf("ge-0-0-3 KeepAddresses=%v KeepForeignStatic=%v, want both true (#15061 foreign VIP keep)",
			m3.KeepAddresses, m3.KeepForeignStatic)
	}

	// RETH parent: only the #9721 advert source, never the untagged unit's VIP.
	m5, ok := models["ge-0-0-5"]
	if !ok {
		t.Fatalf("no model for ge-0-0-5 (RETH control would be vacuous)")
	}
	if len(m5.VLANParentAddresses) != 1 || m5.VLANParentAddresses[0] != "169.254.1.1/32" {
		t.Errorf("ge-0-0-5 VLANParentAddresses=%v, want only the advert source [169.254.1.1/32]: "+
			"the untagged RETH unit's address is a VIP VRRP owns", m5.VLANParentAddresses)
	}
	if !m5.KeepAddresses {
		t.Errorf("ge-0-0-5 lost KeepAddresses for its advert source (#9721)")
	}
}
