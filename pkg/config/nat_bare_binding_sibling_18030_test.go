package config

import (
	"strings"
	"testing"
)

// #18030 / #18031: a bare `st0` NAT interface scope must not resolve to
// unit 0 when a NONZERO sibling unit is materialized only by VPN
// bind-interfaces — with no `interfaces st0` stanza at all (#18030), with
// only unit 0 authored, with a unitless tunnel stanza standing in for unit
// 0, or with the unit-0 binding authored as the bare `st0` spelling
// (#18031). The binding-derived sibling census covers BOTH the
// canonicalizer (a stanza-less multi-binding bare ref is NOT folded to
// st0.0 before the gate) and the #15278 ambiguity gate (strict rejects,
// lenient warns + records, the scope stays bare). Multi-VPN sharing of the
// SAME unit stays legitimate and keeps folding.

// natBareST0AxisCases18030 returns the four NAT interface-scope axis cases
// (source from, source to, destination from, static from) naming bare st0.
func natBareST0AxisCases18030() []struct {
	name string
	cmds []string
	want string
} {
	return []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "source from",
			cmds: []string{
				"set security nat source rule-set snat-from-bad from interface st0",
				"set security nat source rule-set snat-from-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-from-bad rule r1 then source-nat pool pool1",
			},
			want: `source-nat rule-set "snat-from-bad": from interface "st0" not defined`,
		},
		{
			name: "source to",
			cmds: []string{
				"set security nat source rule-set snat-to-bad from zone trust",
				"set security nat source rule-set snat-to-bad to interface st0",
				"set security nat source rule-set snat-to-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-to-bad rule r1 then source-nat pool pool1",
			},
			want: `source-nat rule-set "snat-to-bad": to interface "st0" not defined`,
		},
		{
			name: "destination from",
			cmds: []string{
				"set security nat destination rule-set dnat-bad from interface st0",
				"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1",
			},
			want: `destination-nat rule-set "dnat-bad": from interface "st0" not defined`,
		},
		{
			name: "static from",
			cmds: []string{
				"set security nat static rule-set stat-bad from interface st0",
				"set security nat static rule-set stat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat static rule-set stat-bad rule R1 then static-nat prefix 10.0.0.5/32",
			},
			want: `static-nat rule-set "stat-bad": from interface "st0" not defined`,
		},
	}
}

// natBareST0CombinedCmds18030 builds every axis's rule-set in one config so
// one lenient compile can assert each scope independently.
func natBareST0CombinedCmds18030() []string {
	var cmds []string
	for _, tc := range natBareST0AxisCases18030() {
		cmds = append(cmds, tc.cmds...)
	}
	return cmds
}

// assertNATBareST0SiblingRejected18030 asserts the shared contract for one
// base shape: every strict axis rejects naming the bare ref, and the lenient
// compile warns + records each rule-set while every scope STAYS bare (the
// canonicalizer must not have folded it to st0.0 first).
func assertNATBareST0SiblingRejected18030(t *testing.T, base []string) {
	t.Helper()
	for _, tc := range natBareST0AxisCases18030() {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append(append([]string(nil), base...), tc.cmds...)
			_, err := CompileConfig(buildBindIfaceTree(t, cmds...))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict must reject the scope with diagnostic %q, got %v", tc.want, err)
			}
		})
	}
	cmds := append(append([]string(nil), base...), natBareST0CombinedCmds18030()...)
	cfg, err := CompileConfigLenient(buildBindIfaceTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "st0" {
		t.Fatalf("source from scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Source[1].ToInterface; got != "st0" {
		t.Fatalf("source to scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Destination.RuleSets[0].FromInterface; got != "st0" {
		t.Fatalf("destination from scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Static[0].FromInterface; got != "st0" {
		t.Fatalf("static from scope must stay bare, got %q", got)
	}
	for key := range map[string]bool{
		"source\x00snat-from-bad": true,
		"source\x00snat-to-bad":   true,
		"destination\x00dnat-bad": true,
		"static\x00stat-bad":      true,
	} {
		if !cfg.LenientNATUndefinedScopeRuleSets[key] {
			t.Errorf("lenient must record %s, got %v", key, cfg.LenientNATUndefinedScopeRuleSets)
		}
	}
	for _, want := range []string{
		`source-nat rule-set "snat-from-bad": from interface "st0" not defined`,
		`source-nat rule-set "snat-to-bad": to interface "st0" not defined`,
		`destination-nat rule-set "dnat-bad": from interface "st0" not defined`,
		`static-nat rule-set "stat-bad": from interface "st0" not defined`,
	} {
		found := false
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("lenient must warn with %q, warnings=%v", want, cfg.Warnings)
		}
	}
}

// TestNATBareST0StanzalessMultiBindingRejected18030 is the #18030 primary
// shape: bindings materialize BOTH st0.0 and st0.1 and NO `interfaces st0`
// stanza exists. The old canonicalizer folded the bare ref through the
// bound .0 before the gate could judge it.
func TestNATBareST0StanzalessMultiBindingRejected18030(t *testing.T) {
	base := append(bareNATBase16827(),
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security ipsec vpn vpn1 bind-interface st0.1",
	)
	// Fixture control: the binding-only shape itself compiles, no stanza
	// exists, and both units really are binding-derived.
	control, err := CompileConfig(buildBindIfaceTree(t, base...))
	if err != nil {
		t.Fatalf("stanza-less multi-binding control must compile: %v", err)
	}
	if ifc := control.Interfaces.Interfaces["st0"]; ifc != nil {
		t.Fatalf("fixture must have no st0 stanza, got %+v", ifc)
	}
	if _, bound := control.SecureTunnelNetdevForRef("st0.0"); !bound {
		t.Fatal("fixture must materialize bound st0.0")
	}
	if _, bound := control.SecureTunnelNetdevForRef("st0.1"); !bound {
		t.Fatal("fixture must materialize bound st0.1")
	}
	assertNATBareST0SiblingRejected18030(t, base)
}

// TestNATBareST0AuthoredUnit0BindingSiblingRejected18031: only unit 0 is
// authored while the sibling arrives as a binding (#18031 shape 2).
func TestNATBareST0AuthoredUnit0BindingSiblingRejected18031(t *testing.T) {
	base := append(bareNATBase16827(),
		"set interfaces st0 unit 0 family inet address 10.9.0.1/30",
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security ipsec vpn vpn1 bind-interface st0.1",
	)
	if _, err := CompileConfig(buildBindIfaceTree(t, base...)); err != nil {
		t.Fatalf("authored-unit-0 plus binding-sibling control must compile: %v", err)
	}
	assertNATBareST0SiblingRejected18030(t, base)
}

// TestNATBareST0TunnelStanzaBindingSiblingRejected18031: a unitless tunnel
// stanza implies unit 0 while a binding materializes the sibling (#18031
// shape 3).
func TestNATBareST0TunnelStanzaBindingSiblingRejected18031(t *testing.T) {
	base := append(bareNATBase16827(),
		"set interfaces st0 tunnel source 192.0.2.1 destination 192.0.2.2",
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security ipsec vpn vpn1 bind-interface st0.1",
	)
	control, err := CompileConfig(buildBindIfaceTree(t, base...))
	if err != nil {
		t.Fatalf("unitless tunnel stanza plus bindings control must compile: %v", err)
	}
	ifc := control.Interfaces.Interfaces["st0"]
	if ifc == nil || ifc.Tunnel == nil || ifc.AuthoredUnits || len(ifc.Units) != 0 {
		t.Fatalf("fixture must carry a unitless st0 tunnel stanza, got %+v", ifc)
	}
	assertNATBareST0SiblingRejected18030(t, base)
}

// TestNATBareST0BareBindSiblingRejected18031: the unit-0 binding itself is
// the bare `st0` spelling and the sibling is `st0.1` (#18031 shape 4) —
// previously accepted by the materialized shortcut before any census.
func TestNATBareST0BareBindSiblingRejected18031(t *testing.T) {
	base := append(bareNATBase16827(),
		"set security ipsec vpn vpn0 bind-interface st0",
		"set security ipsec vpn vpn1 bind-interface st0.1",
	)
	control, err := CompileConfig(buildBindIfaceTree(t, base...))
	if err != nil {
		t.Fatalf("bare-bind plus sibling binding control must compile: %v", err)
	}
	if _, bound := control.SecureTunnelNetdevForRef("st0"); !bound {
		t.Fatal("fixture must materialize the bare st0 device")
	}
	if _, bound := control.SecureTunnelNetdevForRef("st0.1"); !bound {
		t.Fatal("fixture must materialize bound st0.1")
	}
	assertNATBareST0SiblingRejected18030(t, base)
}

// TestNATBareST0SameUnitSharingPreserved18030: two VPNs sharing the SAME
// unit (both `bind-interface st0.0`) are NOT siblings — the shared unit is
// the only binding-derived unit, so the bare scope still folds to st0.0 and
// commits. A description-only st0 stanza plus a single unit-0 binding
// (#18024 doctrine) folds too instead of staying inert-bare.
func TestNATBareST0SameUnitSharingPreserved18030(t *testing.T) {
	sharing := append(bareNATBase16827(),
		"set security ike gateway gw-a address 198.51.100.1",
		"set security ike gateway gw-b address 198.51.100.2",
		"set security ipsec vpn vpn0 ike gateway gw-a",
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security ipsec vpn vpn0 traffic-selector ts0 local-ip 10.0.0.0/24 remote-ip 198.51.100.0/24",
		"set security ipsec vpn vpn1 ike gateway gw-b",
		"set security ipsec vpn vpn1 bind-interface st0.0",
		"set security ipsec vpn vpn1 traffic-selector ts0 local-ip 10.0.0.0/24 remote-ip 203.0.113.0/24",
		"set security nat source rule-set snat-shared from interface st0",
		"set security nat source rule-set snat-shared rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-shared rule r1 then source-nat pool pool1",
	)
	cfg, err := CompileConfig(buildBindIfaceTree(t, sharing...))
	if err != nil {
		t.Fatalf("multi-VPN same-unit sharing must compile: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "st0.0" {
		t.Fatalf("shared-unit bare scope = %q, want st0.0", got)
	}

	descriptionOnly := append(bareNATBase16827(),
		"set interfaces st0 description \"vpn termination\"",
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security nat source rule-set snat-desc from interface st0",
		"set security nat source rule-set snat-desc rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-desc rule r1 then source-nat pool pool1",
	)
	cfg, err = CompileConfig(buildBindIfaceTree(t, descriptionOnly...))
	if err != nil {
		t.Fatalf("description-only stanza plus unit-0 binding must compile: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "st0.0" {
		t.Fatalf("description-only bare scope = %q, want st0.0 (bound unit 0)", got)
	}
}

// TestNATBareST0PaddedSpellingSiblings18030 (fold of Rev18046Opus
// residual): padded spellings derive into the same XFRM if_id family,
// so st00.1 is a sibling of st0, st00.0 is unit 0 of the family, and a
// st1.1 binding must NOT cross-veto st0.
func TestNATBareST0PaddedSpellingSiblings18030(t *testing.T) {
	paddedSibling := append(bareNATBase16827(),
		"set security ipsec vpn vpn0 bind-interface st00.0",
		"set security ipsec vpn vpn1 bind-interface st00.1",
	)
	assertNATBareST0SiblingRejected18030(t, paddedSibling)

	otherFamily := append(bareNATBase16827(),
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security ipsec vpn vpn1 bind-interface st1.1",
		"set security nat source rule-set snat-ok from interface st0",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1",
	)
	cfg, err := CompileConfig(buildBindIfaceTree(t, otherFamily...))
	if err != nil {
		t.Fatalf("st1.1 sibling must not cross-veto st0: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "st0.0" {
		t.Fatalf("bare scope = %q, want st0.0", got)
	}
}
