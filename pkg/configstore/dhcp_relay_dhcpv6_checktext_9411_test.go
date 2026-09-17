package configstore

import (
	"strings"
	"testing"
)

// #9553 on the OPERATOR channel: configstore.CheckText must accept the
// implemented RFC 8415 subset and reject only unsupported/incomplete family
// statements. The DHCPv4 controls remain load-bearing.
func TestDHCPRelayDHCPv6RefusedAtCheckText9411(t *testing.T) {
	for _, tc := range []struct {
		name     string
		txt      string
		accepted bool
	}{
		{"braced nested", "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }", true},
		{"bare family Interface-ID", "forwarding-options { dhcp-relay { dhcpv6 { relay-agent-interface-id; server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }", true},
		{"bare group Interface-ID", "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; relay-agent-interface-id; } } } }", true},
		{"bare family remains refused", "forwarding-options { dhcp-relay { dhcpv6; } }", false},
		{"unknown direct child remains refused", "forwarding-options { dhcp-relay { dhcpv6 { unsupported-knob foo; server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }", false},
		{"CONTROL braced v4 relay", "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } }", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.txt, -1)
			if tc.accepted {
				if err != nil {
					t.Fatalf("#9553: implemented/configured relay was refused: %v", err)
				}
				if cfg == nil {
					t.Fatal("#9553: accepted relay returned nil config")
				}
				if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#9411") {
					t.Fatalf("#9553: accepted relay carried obsolete #9411 warning: %v", cfg.Warnings)
				}
				return
			}
			if err == nil {
				t.Fatal("#9553: unsupported DHCPv6 relay committed clean")
			}
			if !strings.Contains(err.Error(), "#9553") {
				t.Fatalf("#9553: unsupported relay refused without the scoped remainder message: %v", err)
			}
		})
	}
}
