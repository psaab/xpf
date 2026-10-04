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

func TestTolerantTunnelStanzaConflictUsesSentinelDomain12044(t *testing.T) {
	lines := []string{
		"set system dataplane-type userspace",
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/1.0",
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
	if got := buildInterfaceRoutingInstances(cfg); len(got) != 1 ||
		got["ge-0/0/1.0"] != "blue" {
		t.Fatalf("userspace membership = %v, want only the uncontested blue sibling", got)
	}
	v4, v6 := buildInterfaceRouteTables(cfg)
	if _, found := v4["gr-0/0/0"]; found {
		t.Fatalf("quarantined tunnel retained an IPv4 route-table claim: %v", v4)
	}
	if _, found := v6["gr-0/0/0"]; found {
		t.Fatalf("quarantined tunnel retained an IPv6 route-table claim: %v", v6)
	}
	if got := v4["ge-0/0/1.0"]; got != "blue.inet.0" {
		t.Fatalf("uncontested sibling IPv4 table = %q, want blue.inet.0", got)
	}
	if got := v6["ge-0/0/1.0"]; got != "blue.inet6.0" {
		t.Fatalf("uncontested sibling IPv6 table = %q, want blue.inet6.0", got)
	}

	snaps := buildInterfaceSnapshots(cfg)
	contested := snapshotByName9132(t, snaps, "gr-0/0/0")
	if contested.RoutingInstance != "" ||
		contested.RoutingDomain != QuarantinedRoutingInstanceDomain {
		t.Errorf("contested %q = (%q, %d), want unassigned RI with sentinel session domain %d",
			contested.Name, contested.RoutingInstance, contested.RoutingDomain,
			QuarantinedRoutingInstanceDomain)
	}
	sibling := snapshotByName9132(t, snaps, "ge-0/0/1.0")
	wantDomain := uint32(config.StableRoutingInstanceTableID("blue"))
	if sibling.RoutingInstance != "blue" || sibling.RoutingDomain != wantDomain {
		t.Errorf("single-claimed sibling %q = (%q, %d), want (blue, %d)",
			sibling.Name, sibling.RoutingInstance, sibling.RoutingDomain, wantDomain)
	}
}

func TestTolerantBareMemberConflictSentinelizesOnlyContestedUnit12044(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/7 vlan-tagging",
		"set interfaces ge-0/0/7 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/7 unit 100 vlan-id 100",
		"set interfaces ge-0/0/7 unit 100 family inet address 198.51.100.1/24",
		"set interfaces ge-0/0/7 unit 200 vlan-id 200",
		"set interfaces ge-0/0/7 unit 200 family inet address 203.0.113.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/7",
		"set routing-instances red instance-type virtual-router",
		"set routing-instances red interface ge-0-0-7.100",
	}
	cfg, err := config.CompileConfigLenient(treeFromSet6722(t, lines))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if len(cfg.QuarantinedRIMemberDeviceConflicts) != 1 ||
		cfg.QuarantinedRIMemberDeviceConflicts[0].LinuxName != "ge-0-0-7.100" {
		t.Fatalf("quarantine evidence = %+v, want ge-0-0-7.100",
			cfg.QuarantinedRIMemberDeviceConflicts)
	}

	members := buildInterfaceRoutingInstances(cfg)
	if _, found := members["ge-0/0/7.100"]; found {
		t.Fatalf("contested VLAN unit retained an RI membership: %v", members)
	}
	for _, key := range []string{"ge-0/0/7", "ge-0/0/7.0", "ge-0/0/7.200"} {
		if members[key] != "blue" {
			t.Errorf("uncontested sibling membership[%q] = %q, want blue; map=%v",
				key, members[key], members)
		}
	}

	snaps := buildInterfaceSnapshots(cfg)
	contested := snapshotByName9132(t, snaps, "ge-0/0/7.100")
	if contested.RoutingInstance != "" ||
		contested.RoutingDomain != QuarantinedRoutingInstanceDomain {
		t.Errorf("contested %q = (%q, %d), want unassigned RI with sentinel session domain %d",
			contested.Name, contested.RoutingInstance, contested.RoutingDomain,
			QuarantinedRoutingInstanceDomain)
	}
	wantDomain := uint32(config.StableRoutingInstanceTableID("blue"))
	for _, key := range []string{"ge-0/0/7", "ge-0/0/7.0", "ge-0/0/7.200"} {
		row := snapshotByName9132(t, snaps, key)
		if row.RoutingInstance != "blue" || row.RoutingDomain != wantDomain {
			t.Errorf("uncontested sibling %q = (%q, %d), want (blue, %d)",
				row.Name, row.RoutingInstance, row.RoutingDomain, wantDomain)
		}
	}
}
