package config

import (
	"strings"
	"testing"
)

// #9552: an undeclared `forwarding-options dhcp-relay` child committed clean on
// all four channels and compiled to nothing. It must be refused at strict
// commit, in every spelling, and warned on the tolerant path.
func TestDHCPRelayUndeclaredChildIsRefused9552(t *testing.T) {
	for _, sp := range []spelling9414{
		{label: "braced", braced: "forwarding-options { dhcp-relay { xpfbogus9552 { foo 1; } } }"},
		{label: "brace-elided", braced: "forwarding-options { dhcp-relay xpfbogus9552 { foo 1; } }"},
		{label: "flat-set", flat: []string{"set forwarding-options dhcp-relay xpfbogus9552 foo 1"}},
		// The same keyword on two flat-set lines is ONE statement: one warning.
		{label: "flat-set, two lines", flat: []string{
			"set forwarding-options dhcp-relay xpfbogus9552 foo 1",
			"set forwarding-options dhcp-relay xpfbogus9552 bar 2",
		}},
		{label: "beside a working DHCPv4 relay", braced: "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } " +
			"group g1 { active-server-group isp; interface ge-0/0/0.0; } xpfbogus9552; } }"},
	} {
		sp := sp
		t.Run(sp.label, func(t *testing.T) {
			if _, err := CompileConfig(sp.tree(t)); err == nil ||
				!strings.Contains(err.Error(), "xpfbogus9552") || !strings.Contains(err.Error(), "(#9552)") {
				t.Fatalf("strict compile did not refuse the undeclared child with the #9552 message: %v", err)
			}
			cfg, err := CompileConfigLenient(sp.tree(t))
			if err != nil {
				t.Fatalf("lenient compile must not fail (#1960): %v", err)
			}
			n := 0
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "(#9552)") {
					n++
				}
			}
			if n != 1 {
				t.Errorf("lenient compile raised %d #9552 warnings, want exactly 1: %q", n, cfg.Warnings)
			}
		})
	}
}

// LOAD-BEARING: "refuses unknown children" is satisfiable by refusing the relay
// outright, which is worse than the silent drop. Every DHCPv4 relay spelling
// must still commit, and must still compile to its server-group and group.
func TestDHCPv4RelaySpellingsStillCompile9552(t *testing.T) {
	for _, sp := range []spelling9414{
		{label: "braced", braced: "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } " +
			"group g1 { active-server-group isp; interface ge-0/0/0.0; } } }"},
		{label: "server-group inline", braced: "forwarding-options { dhcp-relay { server-group isp 10.0.0.5; " +
			"group g1 { active-server-group isp; interface ge-0/0/0.0; } } }"},
		{label: "group overrides", braced: "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } " +
			"group g1 { active-server-group isp; interface ge-0/0/0.0; overrides { always-broadcast; } } } }"},
		// A Junos meta statement is legal at any hierarchy point and is not a
		// relay statement (#7029), so the gate must not judge it.
		{label: "apply-macro beside the relay", braced: "forwarding-options { dhcp-relay { apply-macro m9552 { k v; } " +
			"server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } }"},
		{label: "flat-set", flat: []string{
			"set forwarding-options dhcp-relay server-group isp 10.0.0.5",
			"set forwarding-options dhcp-relay group g1 active-server-group isp",
			"set forwarding-options dhcp-relay group g1 interface ge-0/0/0.0",
		}},
	} {
		sp := sp
		t.Run(sp.label, func(t *testing.T) {
			for _, path := range []struct {
				name    string
				compile func(*ConfigTree) (*Config, error)
			}{{"strict", CompileConfig}, {"lenient", CompileConfigLenient}} {
				cfg, err := path.compile(sp.tree(t))
				if err != nil {
					t.Fatalf("%s: a valid DHCPv4 relay was refused: %v", path.name, err)
				}
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "(#9552)") {
						t.Errorf("%s: a valid DHCPv4 relay raised a #9552 warning: %q", path.name, w)
					}
				}
				r := cfg.ForwardingOptions.DHCPRelay
				if r == nil || r.ServerGroups["isp"] == nil || r.Groups["g1"] == nil {
					t.Fatalf("%s: the relay did not compile its server-group and group: %+v", path.name, r)
				}
			}
		})
	}
}

// `dhcpv6` stays #9411's: its message says the relay agent does not exist.
// The new gate must not replace that message or add a second warning.
func TestDHCPRelayDHCPv6KeepsItsOwnMessage9552(t *testing.T) {
	sp := spelling9414{label: "braced", braced: "forwarding-options { dhcp-relay { dhcpv6 { group g6 { interface ge-0/0/0.0; } } } }"}
	_, err := CompileConfig(sp.tree(t))
	if err == nil || !strings.Contains(err.Error(), "#9411") || strings.Contains(err.Error(), "#9552") {
		t.Fatalf("dhcpv6 must be refused by #9411's message alone, got: %v", err)
	}
	cfg, err := CompileConfigLenient(sp.tree(t))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#9552)") {
			t.Errorf("dhcpv6 raised a #9552 warning beside #9411's: %q", w)
		}
	}
}
