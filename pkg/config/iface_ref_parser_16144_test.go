package config

import "testing"

// TestSplitIfaceRefRawSuffix16144 pins the #16144 raw-suffix contract: the
// extracted parser returns the suffix after the FIRST dot verbatim —
// including non-decimal, empty, and multi-dot suffixes — and never
// validates, canonicalizes, or integer-parses it. A universal
// (name, unit int, hasUnit) parser would fail these rows; that is the
// unsound form Codex rejected and this issue must not ship.
func TestSplitIfaceRefRawSuffix16144(t *testing.T) {
	tests := []struct {
		ref      string
		wantName string
		wantSuf  string
		wantHas  bool
	}{
		{"reth0", "reth0", "", false},
		{"reth0.50", "reth0", "50", true},
		{"reth0.foo", "reth0", "foo", true},     // non-decimal: carried raw
		{"reth0.50.60", "reth0", "50.60", true}, // multi-dot: only first dot splits
		{"reth0.", "reth0", "", true},           // trailing dot: hasSuffix with empty raw suffix
		{"reth0.+1", "reth0", "+1", true},       // sign preserved, not normalized
		{"reth0.01", "reth0", "01", true},       // padding preserved, not canonicalized
		{"gr-0/0/0.0", "gr-0/0/0", "0", true},   // authored dotted-name shape splits raw
		{".5", "", "5", true},
		{"", "", "", false},
	}
	for _, tt := range tests {
		name, suf, has := SplitIfaceRef(tt.ref)
		if name != tt.wantName || suf != tt.wantSuf || has != tt.wantHas {
			t.Errorf("SplitIfaceRef(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.ref, name, suf, has, tt.wantName, tt.wantSuf, tt.wantHas)
		}
	}
}

// TestResolveRawSuffixAdoption16144 pins the per-caller adoption table:
// ResolveReth/ResolveFab copy the raw suffix verbatim (multi-dot and
// non-decimal included), while DHCPLeaseKey discards the suffix and uses
// the separately supplied unit number. These rows are RED if the raw
// suffix is ever routed through an integer-unit parser.
func TestResolveRawSuffixAdoption16144(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"fab0":     {Name: "fab0", LocalFabricMember: "ge-0/0/1"},
				"ge-0/0/1": {Name: "ge-0/0/1"},
			},
		},
	}
	// Raw copy: arbitrary suffix text survives verbatim.
	for ref, want := range map[string]string{
		"reth0.foo":   "ge-0/0/0.foo",
		"reth0.50.60": "ge-0/0/0.50.60",
		"reth0.+1":    "ge-0/0/0.+1",
		"fab0.foo":    "ge-0/0/1.foo",
		"fab0.0.1":    "ge-0/0/1.0.1",
	} {
		if got := cfg.ResolveReth(ref); ref[:4] == "reth" && got != want {
			t.Errorf("ResolveReth(%q) = %q, want raw copy %q", ref, got, want)
		}
		if got := cfg.ResolveFab(ref); ref[:3] == "fab" && got != want {
			t.Errorf("ResolveFab(%q) = %q, want raw copy %q", ref, got, want)
		}
	}
	// Discard: DHCPLeaseKey("reth0.<anything>", 50) keys by unit 50's VLAN,
	// identical to the bare form — the ref suffix plays no role.
	cfg.Interfaces.Interfaces["reth0"].Units = map[int]*InterfaceUnit{
		50: {Number: 50, VlanID: 180},
	}
	bare, okBare := cfg.DHCPLeaseKey("reth0", 50)
	dotted, okDotted := cfg.DHCPLeaseKey("reth0.999", 50)
	if !okBare || !okDotted || bare != dotted || bare != "reth0.180" {
		t.Errorf("DHCPLeaseKey discard: bare=(%q,%v) dotted=(%q,%v), want both (\"reth0.180\",true)",
			bare, okBare, dotted, okDotted)
	}
}

// TestDeclaredDottedNameUnchanged16144 pins the decisive #16144 check: an
// authored interface whose NAME contains a dot (gr-0/0/0.0 declared as a
// stanza) still resolves through ResolveKernelIfName's declared-name-wins
// arm to its own device, exactly as before the parser extraction — the
// extraction must not misroute it as unit 0 of gr-0/0/0.
func TestDeclaredDottedNameUnchanged16144(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"gr-0/0/0": {
					Name:   "gr-0/0/0",
					Tunnel: &TunnelConfig{Source: "10.0.0.1", Destination: "10.0.0.2"},
					Units:  map[int]*InterfaceUnit{0: {Number: 0}},
				},
				// The authored dotted interface itself.
				"gr-0/0/0.0": {Name: "gr-0/0/0.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
			},
		},
	}
	if got := cfg.ResolveKernelIfName("gr-0/0/0.0"); got != "gr-0-0-0.0" {
		t.Errorf("ResolveKernelIfName(gr-0/0/0.0 declared) = %q, want gr-0-0-0.0 (declared-name-wins)", got)
	}
	// Control: without the dotted declaration, the same string is unit 0
	// of gr-0/0/0 and follows the tunnel arm.
	cfg2 := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"gr-0/0/0": {
					Name:   "gr-0/0/0",
					Tunnel: &TunnelConfig{Source: "10.0.0.1", Destination: "10.0.0.2"},
					Units:  map[int]*InterfaceUnit{0: {Number: 0}},
				},
			},
		},
	}
	if got := cfg2.ResolveKernelIfName("gr-0/0/0.0"); got != "gr-0-0-0" {
		t.Errorf("ResolveKernelIfName(gr-0/0/0.0 undeclared) = %q, want gr-0-0-0 (unit/tunnel arm)", got)
	}
}
