package configstore

import (
	"strings"
	"testing"
)

// #15028 through the real operator check pipeline (CheckText is the thin
// composition of the same functions Store.Commit uses): two DHCP group
// interface refs that resolve to one kernel device must be rejected
// naming both refs, and the valid control in the same shape must pass.
func TestCheckTextRefusesDuplicateDHCPGroupInterface15028(t *testing.T) {
	cluster := "chassis { cluster { authentication-key test-cluster-psk-15028; node 0; reth-count 2; redundancy-group 1 { node 0 priority 200; node 1 priority 100; } } } " +
		"interfaces { ge-0/0/1 { gigether-options { redundant-parent reth1; } } " +
		"reth1 { redundant-ether-options { redundancy-group 1; } unit 0 { family inet { address 10.0.61.1/24; } } } } "
	v4dup := cluster + "system { services { dhcp-local-server { " +
		"group g1 { interface reth1.0; pool p1 { subnet 10.0.61.0/24; address-range low 10.0.61.100 high 10.0.61.199; } } " +
		"group g2 { interface ge-0/0/1.0; pool p1 { subnet 10.0.62.0/24; address-range low 10.0.62.100 high 10.0.62.199; } } } } }"
	v6dup := cluster + "system { services { dhcpv6-local-server { " +
		"group g1 { interface reth1.0; pool p1 { subnet 2001:db8:61::/64; address-range low 2001:db8:61::10 high 2001:db8:61::20; } } " +
		"group g2 { interface ge-0/0/1.0; pool p1 { subnet 2001:db8:62::/64; address-range low 2001:db8:62::10 high 2001:db8:62::20; } } } } }"
	for _, tc := range []struct{ name, text string }{
		{"v4 reth+member", v4dup},
		{"v6 reth+member", v6dup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, 0); err == nil ||
				!strings.Contains(err.Error(), "reth1.0") ||
				!strings.Contains(err.Error(), "ge-0/0/1.0") ||
				!strings.Contains(err.Error(), "ge-0-0-1") {
				t.Fatalf("CheckText accepted two refs resolving to one device: %v", err)
			}
		})
	}
	control := cluster + "system { services { dhcp-local-server { " +
		"group g1 { interface reth1.0; pool p1 { subnet 10.0.61.0/24; address-range low 10.0.61.100 high 10.0.61.199; } } " +
		"group g2 { interface ge-0/0/2.0; pool p1 { subnet 10.0.62.0/24; address-range low 10.0.62.100 high 10.0.62.199; } } } } }"
	if _, err := CheckText(control, 0); err != nil {
		t.Fatalf("control: a valid two-device DHCP config was refused: %v", err)
	}
}
