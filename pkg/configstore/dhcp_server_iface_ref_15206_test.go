package configstore

import (
	"strings"
	"testing"
)

// #15206 (A17-03) through the real operator check pipeline (CheckText is
// the thin composition of the same functions Store.Commit uses): a
// DHCP-server group interface ref naming no configured interface or unit
// must be rejected naming the ref and the whole-family consequence, and
// the declared control in the same shape must pass.
func TestCheckTextRefusesUndeclaredDHCPServerInterface15206(t *testing.T) {
	ifaces := "interfaces { ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } } " +
		"ge-0/0/2 { gigether-options { redundant-parent reth1; } } " +
		"reth1 { redundant-ether-options { redundancy-group 1; } vlan-tagging; unit 0 { family inet { address 10.0.61.1/24; } } unit 80 { vlan-id 180; family inet { address 10.0.180.1/24; } } } } "
	v4bad := ifaces + "system { services { dhcp-local-server { " +
		"group g1 { interface reth1.7; pool p1 { subnet 10.0.61.0/24; address-range low 10.0.61.100 high 10.0.61.199; } } } } }"
	v6bad := ifaces + "system { services { dhcpv6-local-server { " +
		"group g6 { interface reth9.0; pool p1 { subnet 2001:db8:61::/64; address-range low 2001:db8:61::10 high 2001:db8:61::20; } } } } }"
	for _, tc := range []struct{ name, text, family, ref string }{
		{"v4 undeclared unit", v4bad, "dhcp-local-server", "reth1.7"},
		{"v6 undeclared interface", v6bad, "dhcpv6-local-server", "reth9.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckText(tc.text, -1)
			if err == nil {
				t.Fatalf("CheckText accepted an undeclared DHCP-server interface ref (%s)", tc.ref)
			}
			for _, w := range []string{tc.family, tc.ref, "every pool of the " + tc.family + " family stops serving"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("CheckText refusal %q does not contain %q", err, w)
				}
			}
		})
	}
	control := ifaces + "system { services { dhcp-local-server { " +
		"group g1 { interface reth1.80; pool p1 { subnet 10.0.61.0/24; address-range low 10.0.61.100 high 10.0.61.199; } } } } }"
	if _, err := CheckText(control, -1); err != nil {
		t.Fatalf("control: a declared VLAN-unit DHCP config was refused: %v", err)
	}
}
