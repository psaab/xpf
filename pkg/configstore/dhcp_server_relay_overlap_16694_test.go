package configstore

import (
	"strings"
	"testing"
)

// #16694 through the real operator check pipeline (CheckText is the
// thin composition of the same functions Store.Commit uses): the
// probe's both-row must be refused naming the interface, and the
// single-service rows still commit.
func TestCheckTextRefusesDHCPServerRelayOverlap16694(t *testing.T) {
	ifaces := "interfaces { ge-0/0/1 { vlan-tagging; unit 0 { family inet { address 10.0.1.1/24; } family inet6 { address 2001:db8:1::1/64; } } } " +
		"ge-0/0/2 { gigether-options { redundant-parent reth1; } } " +
		"reth1 { redundant-ether-options { redundancy-group 1; } vlan-tagging; unit 0 { family inet { address 10.0.61.1/24; } family inet6 { address 2001:db8:61::1/64; } } } } "
	v4srv := "system { services { dhcp-local-server { group g1 { interface reth1.0; pool p1 { subnet 10.0.61.0/24; address-range low 10.0.61.100 high 10.0.61.199; } } } } } "
	v4relay := "forwarding-options { dhcp-relay { server-group sg1 192.0.2.53; group r1 { active-server-group sg1; interface ge-0/0/2.0; } } } "
	v6srv := "system { services { dhcpv6-local-server { group g6 { interface ge-0/0/1.0; pool p1 { subnet 2001:db8:61::/64; address-range low 2001:db8:61::10 high 2001:db8:61::20; } } } } } "
	v6relay := "forwarding-options { dhcp-relay { dhcpv6 { server-group sg6 2001:db8::53; group r6 { active-server-group sg6; interface ge-0/0/1.0; } } } }"

	for _, tc := range []struct{ name, text, device string }{
		{"v4 reth server vs member relay", ifaces + v4srv + v4relay, "ge-0-0-2"},
		{"v6 both-row", ifaces + v6srv + v6relay, "ge-0-0-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckText(tc.text, -1)
			if err == nil {
				t.Fatalf("CheckText accepted a DHCP server+relay overlap on %s", tc.device)
			}
			for _, w := range []string{tc.device, "both resolve to kernel device", "(#16694)"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("CheckText refusal %q does not contain %q", err, w)
				}
			}
		})
	}
	for _, tc := range []struct{ name, text string }{
		{"server only", ifaces + v4srv},
		{"relay only", ifaces + v4relay},
		{"cross-family same device", ifaces + v4srv + v6relay},
	} {
		t.Run("control "+tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, -1); err != nil {
				t.Fatalf("control %q refused: %v", tc.name, err)
			}
		})
	}
}
