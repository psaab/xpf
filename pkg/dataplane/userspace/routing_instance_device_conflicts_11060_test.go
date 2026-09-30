package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRIMemberDeviceConflictLeavesAliasClaimUnassigned11060(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/7": {Name: "ge-0/0/7", Units: map[int]*config.InterfaceUnit{
				10: {Number: 10, VlanID: 100},
				20: {Number: 20, VlanID: 200},
			}},
		}},
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "blue", Interfaces: []string{"ge-0/0/7"}},
			{Name: "red", Interfaces: []string{"ge-0-0-7.10"}},
		},
	}

	members := buildInterfaceRoutingInstances(cfg)
	if _, found := members["ge-0/0/7.10"]; found {
		t.Fatalf("cross-spelled dual-claimed VLAN unit was assigned to an RI: %v", members)
	}
	if got := members["ge-0/0/7"]; got != "blue" {
		t.Fatalf("unambiguous bare primary membership = %q, want blue; map=%v", got, members)
	}
	if got := members["ge-0/0/7.20"]; got != "blue" {
		t.Fatalf("unambiguous VLAN sibling membership = %q, want blue; map=%v", got, members)
	}

	v4, v6 := buildInterfaceRouteTables(cfg)
	if _, found := v4["ge-0/0/7.10"]; found {
		t.Fatalf("cross-spelled dual-claimed VLAN unit received an IPv4 table: %v", v4)
	}
	if _, found := v6["ge-0/0/7.10"]; found {
		t.Fatalf("cross-spelled dual-claimed VLAN unit received an IPv6 table: %v", v6)
	}
	if got := v4["ge-0/0/7.20"]; got != "blue.inet.0" {
		t.Fatalf("unambiguous VLAN sibling IPv4 table = %q, want blue.inet.0", got)
	}
	if got := v6["ge-0/0/7.20"]; got != "blue.inet6.0" {
		t.Fatalf("unambiguous VLAN sibling IPv6 table = %q, want blue.inet6.0", got)
	}
}

func TestTolerantTunnelStanzaConflictUsesDefaultDataplaneMembership11060(t *testing.T) {
	lines := []string{
		"set system dataplane-type userspace",
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances red instance-type virtual-router",
		"set routing-instances red interface gr-0/0/0",
	}
	cfg, err := config.CompileConfigLenient(treeFromSet6722(t, lines))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if len(cfg.QuarantinedRIMemberDeviceConflicts) != 1 ||
		cfg.QuarantinedRIMemberDeviceConflicts[0].LinuxName != "gr-0-0-0" {
		t.Fatalf("quarantine evidence = %+v, want gr-0-0-0", cfg.QuarantinedRIMemberDeviceConflicts)
	}
	if cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel.RoutingInstance != "" {
		t.Fatal("tunnel stanza remained scoped after its competing membership was quarantined")
	}
	if got := buildInterfaceRoutingInstances(cfg); len(got) != 0 {
		t.Fatalf("userspace assigned a quarantined tunnel to an RI: %v", got)
	}
	v4, v6 := buildInterfaceRouteTables(cfg)
	if len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("userspace route tables retained a quarantined tunnel claim: v4=%v v6=%v", v4, v6)
	}
}
