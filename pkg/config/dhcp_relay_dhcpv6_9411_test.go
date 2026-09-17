package config

import (
	"strings"
	"testing"
)

// #9411 — `forwarding-options dhcp-relay dhcpv6` must be LOUD, not discarded.
//
// CHANNELS. This file drives config.CompileConfig (the strict compiler, where
// the gate is fatal) and config.CompileConfigLenient (the tolerant Store.Load /
// Store.SyncApply ingress, where it is a warning). configstore.CheckText — the
// operator commit path — is asserted in
// pkg/configstore/dhcp_relay_dhcpv6_checktext_9411_test.go. SchemaValidate still
// ACCEPTS the stanza: the refusal lives in the compiler's pre-walk, because the
// stanza compiles to nothing and the schema walk is open-world under dhcp-relay.

func bracedTree9411(t *testing.T, txt string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(txt).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", txt, errs[0])
	}
	return tree
}

func flatTree9411(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tr := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	return tr
}

func relayCounts9411(cfg *Config) (sg, g int) {
	if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil {
		return 0, 0
	}
	r := cfg.ForwardingOptions.DHCPRelay
	return len(r.ServerGroups), len(r.Groups)
}

func mentions9411(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "#9411") {
			return true
		}
	}
	return false
}

// TestDHCPRelayDHCPv6IsAcceptedInEveryShape9553 exercises the Junos forms
// which #9411 previously refused. Every valid shape must compile into the
// typed DHCPv6 relay without a DHCPv4 group or an obsolete warning.
func TestDHCPRelayDHCPv6IsAcceptedInEveryShape9553(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tree     func(*testing.T) *ConfigTree
		wantV4SG int
		wantV4G  int
	}{
		{"braced nested", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }")
		}, 0, 0},
		{"relay elided onto dhcpv6", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } }")
		}, 0, 0},
		{"flat-set", func(t *testing.T) *ConfigTree {
			return flatTree9411(t,
				"set forwarding-options dhcp-relay dhcpv6 server-group isp6 2001:db8::5",
				"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group isp6",
				"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0")
		}, 0, 0},
		{"BESIDE a working v4 relay", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/1.0; } } } }")
		}, 1, 1},
		{"relay-elided dhcpv6 BEFORE a v4 relay block", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/1.0; } } dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } }")
		}, 1, 1},
		{"injected via apply-groups", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "groups { g1 { forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } } } } apply-groups g1;")
		}, 0, 0},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("#9553: implemented DHCPv6 relay was rejected: %v", err)
			}
			if cfg == nil || cfg.ForwardingOptions.DHCPRelay == nil || cfg.ForwardingOptions.DHCPRelay.V6 == nil {
				t.Fatalf("#9553: strict compile did not produce a typed DHCPv6 relay: %+v", cfg)
			}
			if got := len(cfg.ForwardingOptions.DHCPRelay.V6.ServerGroups); got != 1 {
				t.Errorf("#9553: v6 server-groups=%d, want 1", got)
			}
			if got := len(cfg.ForwardingOptions.DHCPRelay.V6.Groups); got != 1 {
				t.Errorf("#9553: v6 groups=%d, want 1", got)
			}
			if sg, g := relayCounts9411(cfg); sg != tc.wantV4SG || g != tc.wantV4G {
				t.Errorf("#9553: v4 relay = %d server-groups / %d groups, want %d / %d", sg, g, tc.wantV4SG, tc.wantV4G)
			}
			if mentions9411(cfg.Warnings) {
				t.Fatalf("#9553: strict compile carried obsolete #9411 warning: %v", cfg.Warnings)
			}

			lenient, err := CompileConfigLenient(tc.tree(t))
			if err != nil {
				t.Fatalf("#9553: tolerant compile rejected implemented DHCPv6 relay: %v", err)
			}
			if mentions9411(lenient.Warnings) {
				t.Fatalf("#9553: tolerant compile carried obsolete #9411 warning: %v", lenient.Warnings)
			}
			if r := lenient.ForwardingOptions.DHCPRelay; r != nil {
				if _, ok := r.Groups["g6"]; ok {
					t.Fatalf("#9553 MIS-COMPILE: DHCPv6 group g6 surfaced as DHCPv4 relay")
				}
			}
		})
	}
}

// TestDHCPRelayDHCPv6UnsupportedRemainderRefused9553 keeps the refusal boundary
// from #9411: unsupported or incomplete family statements must fail loudly,
// rather than compile to an inert relay.
func TestDHCPRelayDHCPv6UnsupportedRemainderRefused9553(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"bare family", "forwarding-options { dhcp-relay { dhcpv6; } }"},
		{"unknown direct child", "forwarding-options { dhcp-relay { dhcpv6 { unsupported-knob foo; server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }"},
		{"unknown group child", "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { active-server-group isp6; unsupported-knob foo; interface ge-0/0/0.0; } } } }"},
		{"missing active group", "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 2001:db8::5; } group g6 { interface ge-0/0/0.0; } } } }"},
		{"IPv4 server", "forwarding-options { dhcp-relay { dhcpv6 { server-group isp6 { 192.0.2.5; } group g6 { active-server-group isp6; interface ge-0/0/0.0; } } } }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(bracedTree9411(t, tc.text))
			if err == nil || !strings.Contains(err.Error(), "#9553") {
				t.Fatalf("#9553: unsupported DHCPv6 remainder committed or used the obsolete refusal: %v", err)
			}
			lenient, err := CompileConfigLenient(bracedTree9411(t, tc.text))
			if err != nil {
				t.Fatalf("#9553 no-brick: tolerant compile rejected persisted remainder: %v", err)
			}
			foundWarning := false
			for _, warning := range lenient.Warnings {
				if strings.Contains(warning, "#9553") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("#9553 no-brick: tolerant compile emitted no remainder warning: %v", lenient.Warnings)
			}
		})
	}

}

// TestDHCPRelayDHCPv6GateDoesNotRefuseAWorkingV4Relay9411 carries the rows that
// matter most, because "the stanza is refused" is satisfiable by refusing every
// relay config — which would take down DHCPv4 relay for everyone on their next
// commit, a far worse defect than the silent discard being fixed (#4191).
//
// The sharpest rows are a DHCPv4 relay GROUP or SERVER-GROUP that is merely NAMED
// `dhcpv6`. They are why the gate matches by token POSITION: a gate that looked
// for the token anywhere under dhcp-relay would refuse them.
func TestDHCPRelayDHCPv6GateDoesNotRefuseAWorkingV4Relay9411(t *testing.T) {
	for _, tc := range []struct {
		name             string
		tree             func(*testing.T) *ConfigTree
		strictMustCommit bool
		wantSG, wantG    int // -1 = not asserted
	}{
		{"CONTROL braced v4 relay", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group g1 { active-server-group isp; interface ge-0/0/0.0; } } }")
		}, true, 1, 1},
		{"CONTROL flat-set v4 relay", func(t *testing.T) *ConfigTree {
			return flatTree9411(t,
				"set forwarding-options dhcp-relay server-group isp 10.0.0.5",
				"set forwarding-options dhcp-relay group g1 active-server-group isp",
				"set forwarding-options dhcp-relay group g1 interface ge-0/0/0.0")
		}, true, 1, 1},
		{"v4 GROUP named dhcpv6, braced", func(t *testing.T) *ConfigTree {
			return bracedTree9411(t, "forwarding-options { dhcp-relay { server-group isp { 10.0.0.5; } group dhcpv6 { active-server-group isp; interface ge-0/0/0.0; } } }")
		}, true, 1, 1},
		{"v4 GROUP named dhcpv6, flat-set", func(t *testing.T) *ConfigTree {
			return flatTree9411(t,
				"set forwarding-options dhcp-relay server-group isp 10.0.0.5",
				"set forwarding-options dhcp-relay group dhcpv6 active-server-group isp",
				"set forwarding-options dhcp-relay group dhcpv6 interface ge-0/0/0.0")
		}, true, 1, 1},
		{"v4 SERVER-GROUP named dhcpv6, flat-set", func(t *testing.T) *ConfigTree {
			return flatTree9411(t,
				"set forwarding-options dhcp-relay server-group dhcpv6 10.0.0.5",
				"set forwarding-options dhcp-relay group g1 active-server-group dhcpv6",
				"set forwarding-options dhcp-relay group g1 interface ge-0/0/0.0")
		}, true, 1, 1},
		{
			// Elided spelling of the named group: the assertion is only that THIS
			// gate does not fire, since the elided grammar is not this fix's subject.
			"v4 GROUP named dhcpv6, fully elided", func(t *testing.T) *ConfigTree {
				return bracedTree9411(t, "forwarding-options dhcp-relay group dhcpv6 interface ge-0/0/0.0;")
			}, false, -1, -1},
		{
			// A DEACTIVATED dhcpv6 stanza is inert by design and is pruned before the
			// gate runs (measured). Refusing it would stop an operator committing a
			// deactivated migration artefact they have deliberately set aside.
			"inactive: dhcpv6 is NOT refused", func(t *testing.T) *ConfigTree {
				return bracedTree9411(t, "forwarding-options { dhcp-relay { inactive: dhcpv6 { group g6 { interface ge-0/0/0.0; } } } }")
			}, true, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)
			cfg, err := CompileConfig(tree)
			if err != nil && strings.Contains(err.Error(), "#9411") {
				t.Fatalf("#9411 OVER-REJECTION: a DHCPv4 relay was refused as a DHCPv6 stanza: %v\n"+
					"The gate must match `dhcpv6` by POSITION — immediately after `dhcp-relay`, or "+
					"as a child's own name — not anywhere it appears as a token.", err)
			}
			if tc.strictMustCommit && err != nil {
				t.Fatalf("#9411: a DHCPv4 relay control no longer commits: %v", err)
			}
			if tc.wantSG >= 0 {
				if sg, g := relayCounts9411(cfg); sg != tc.wantSG || g != tc.wantG {
					t.Errorf("#9411: v4 relay = %d server-groups / %d groups, want %d / %d",
						sg, g, tc.wantSG, tc.wantG)
				}
			}
			if lc, lerr := CompileConfigLenient(tree); lerr == nil && mentions9411(lc.Warnings) {
				t.Errorf("#9411 OVER-REJECTION (tolerant path): a DHCPv4 relay drew a DHCPv6 warning: %v",
					lc.Warnings)
			}
		})
	}
}
