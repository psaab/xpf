package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// #15061 (A37-02): a standalone vrrp-group VIP is foreign to networkd and
// was stripped by xpf's reconfigure while VRRP stayed MASTER.
//
// pkg/vrrp.CollectInstances builds an instance from ANY unit's
// VRRPGroups, and becomeMaster installs each VIP as a genuine kernel
// address. buildInterfaceNetworkdModels set KeepAddresses only for
// VRRP-backed RETH rows (isVRRPReth, which requires a redundant-parent),
// so a plain interface carrying `vrrp-group 1 virtual-address 10.0.1.1`
// rendered no static keep. Worse, pkg/networkd's static class also
// required a rendered Address= line, which a foreign VIP never has — so
// even KeepAddresses alone could not emit KeepConfiguration=static.
//
// FAIL-ON-REVERT: drop the standalone arms (unitCarriesStandaloneVRRP /
// interfaceCarriesStandaloneVRRP / KeepForeignStatic) and the
// standalone cells go RED — KeepAddresses/KeepForeignStatic false, so
// the generated .network carries no KeepConfiguration=static and a
// reconfigure strips 10.0.1.1/32 while the instance stays MASTER.
// The RETH-only, plain, empty-VIP, and disabled controls must stay
// without the standalone keep.

func standaloneVRRPCfg15061(t *testing.T) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range []string{
		// Standalone (non-RETH, non-cluster) VRRP: the issue's shape.
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.2/24 vrrp-group 1 virtual-address 10.0.1.1",
		// Tagged standalone: VIP lives on the sub-interface device.
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.100.2/24 vrrp-group 2 virtual-address 10.0.100.1",
		// Untagged standalone on a VLAN parent: instance binds to parent.
		"set interfaces ge-0/0/2 vlan-tagging",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.2/24 vrrp-group 3 virtual-address 10.0.2.1",
		"set interfaces ge-0/0/2 unit 200 vlan-id 200",
		"set interfaces ge-0/0/2 unit 200 family inet address 10.0.200.2/24",
		// Control: plain interface, no vrrp-group.
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.2/24",
		// Control: vrrp-group with no virtual-address owns no VIP.
		"set interfaces ge-0/0/4 unit 0 family inet address 10.0.4.2/24 vrrp-group 4 priority 200",
		// Control: unit-disabled standalone group installs nothing here.
		"set interfaces ge-0/0/5 unit 0 disable",
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.5.2/24 vrrp-group 5 virtual-address 10.0.5.1",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	return cfg
}

func models15061(t *testing.T, cfg *config.Config) map[string]networkd.InterfaceConfig {
	t.Helper()
	result := &CompileResult{ifCache: map[string]*net.Interface{}}
	for i, name := range []string{"ge-0-0-0", "ge-0-0-1", "ge-0-0-2", "ge-0-0-3", "ge-0-0-4", "ge-0-0-5"} {
		result.ifCache[name] = &net.Interface{
			Index:        80 + i,
			Name:         name,
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x01, byte(i)},
		}
	}
	buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
	out := map[string]networkd.InterfaceConfig{}
	for _, m := range result.ManagedInterfaces {
		out[m.Name] = m
	}
	return out
}

func TestStandaloneVRRPRowReportsKeepAddresses15061(t *testing.T) {
	models := models15061(t, standaloneVRRPCfg15061(t))

	// The issue's acceptance: the model row reports KeepAddresses=true.
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1.100", "ge-0-0-2"} {
		m, ok := models[name]
		if !ok {
			t.Fatalf("no networkd model for %s; the standalone VRRP device was not rendered", name)
		}
		if !m.KeepAddresses {
			t.Errorf("%s KeepAddresses=false, want true: its standalone VIP is foreign to networkd "+
				"and a reconfigure would strip it while VRRP stays MASTER", name)
		}
		if !m.KeepForeignStatic {
			t.Errorf("%s KeepForeignStatic=false, want true: the VIP is never rendered as Address=, "+
				"so KeepAddresses alone cannot emit KeepConfiguration=static", name)
		}
	}
	// The tagged sibling on ge-0/0/2 carries no group: no standalone keep.
	if m, ok := models["ge-0-0-2.200"]; !ok {
		t.Error("no model for ge-0-0-2.200 (control would be vacuous)")
	} else if m.KeepAddresses || m.KeepForeignStatic {
		t.Errorf("ge-0-0-2.200 KeepAddresses=%v KeepForeignStatic=%v, want neither: it carries no vrrp-group",
			m.KeepAddresses, m.KeepForeignStatic)
	}
	// Controls: plain, empty-VIP, and disabled rows get no standalone keep.
	for _, tc := range []struct{ name, why string }{
		{"ge-0-0-3", "plain interface with no vrrp-group"},
		{"ge-0-0-4", "vrrp-group with no virtual-address installs no VIP"},
		{"ge-0-0-5", "unit-disabled group contributes no addresses"},
	} {
		m, ok := models[tc.name]
		if !ok {
			t.Errorf("no model for %s (control would be vacuous: %s)", tc.name, tc.why)
			continue
		}
		if m.KeepAddresses || m.KeepForeignStatic {
			t.Errorf("%s KeepAddresses=%v KeepForeignStatic=%v, want neither: %s",
				tc.name, m.KeepAddresses, m.KeepForeignStatic, tc.why)
		}
	}
}
