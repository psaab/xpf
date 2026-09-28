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
