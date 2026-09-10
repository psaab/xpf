package configstore

import (
	"strings"
	"testing"
)

// #9411 on the OPERATOR channel: configstore.CheckText is compileTreeStrict, the
// gate sequence every commit goes through.
//
// The elided spellings are asserted only as REFUSED, not refused-by-#9411: this
// path runs the typed schema walk before the compiler, and that walk may refuse
// a packed `dhcp-relay dhcpv6` run on its own first. Either way the operator is
// told; what must never happen is a clean commit. The load-bearing rows are the
// DHCPv4 relays, which must still commit.
func TestDHCPRelayDHCPv6RefusedAtCheckText9411(t *testing.T) {
	for _, tc := range []struct {
		name     string
		txt      string
		refused  bool
		need9411 bool
	}{
		{"braced nested", "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }", true, true},
		{"bare dhcpv6 leaf", "forwarding-options { dhcp-relay { dhcpv6; } }", true, true},
		{"BESIDE a working v4 relay", "forwarding-options { dhcp-relay { group g1 { interface ge-0/0/0.0; } dhcpv6 { group g6 { interface ge-0/0/1.0; } } } }", true, true},
		{"relay elided onto dhcpv6", "forwarding-options { dhcp-relay dhcpv6 { group g6 { interface ge-0/0/0.0; } } }", true, false},
		{"fully elided", "forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0;", true, false},
		{"relay-elided dhcpv6 BEFORE a v4 relay block", "forwarding-options { dhcp-relay dhcpv6 { group g6 { interface ge-0/0/1.0; } } dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } }", true, false},
		{"injected via apply-groups", "groups { g1 { forwarding-options { dhcp-relay { dhcpv6 { group g6 { interface ge-0/0/0.0; } } } } } } apply-groups g1;", true, false},
		{"inactive: dhcpv6 is NOT refused", "forwarding-options { dhcp-relay { inactive: dhcpv6 { group g6 { interface ge-0/0/0.0; } } } }", false, false},
		{"CONTROL braced v4 relay", "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } }", false, false},
		{"v4 GROUP named dhcpv6", "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group dhcpv6 { active-server-group isp; interface ge-0/0/0.0; } } }", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckText(tc.txt, -1)
			if !tc.refused {
				if err != nil {
					t.Fatalf("#9411 OVER-REJECTION at CheckText: a DHCPv4 relay no longer commits: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("#9411: CheckText COMMITTED the dhcpv6 relay stanza clean. It compiles to " +
					"nothing, so the operator gets no relay and no complaint.")
			}
			if tc.need9411 && !strings.Contains(err.Error(), "#9411") {
				t.Errorf("#9411: CheckText refused, but not for this reason, so this row says nothing "+
					"about the #9411 gate: %v", err)
			}
			t.Logf("refused: %v", err)
		})
	}
}
