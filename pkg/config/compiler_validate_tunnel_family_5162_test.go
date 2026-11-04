package config

import (
	"strings"
	"testing"
)

// #18958 closing census: the mixed-family outcome clause is per-arm.
// Strict returns the message as the commit refusal, so its outcome says
// the commit is refused; "a mixed pair commits clean but the dataplane
// silently drops every encapsulated packet" is only true on the lenient
// arm, where the config boots and the Rust helper skips the mixed row.
// Literals, not builder references, so an outcome swap cannot satisfy
// them tautologically; the head ("different address families") is
// shared, unchanged, and pinned by hasFamilyMismatch.
const (
	strictTail5162  = "(the commit is refused, #5162)"
	lenientTail5162 = "(a mixed pair commits clean but the dataplane silently drops every encapsulated packet, #5162)"
)

// hasFamilyMismatch reports whether err carries the #5162 mixed-family
// tunnel rejection message.
func hasFamilyMismatch(err error) bool {
	return err != nil && strings.Contains(err.Error(), "different address families")
}

// treeFromSet builds a ConfigTree from flat-set commands via the
// ParseSetCommand + SetPath loop (the dual-AST gotcha: NEVER NewParser
// for newline-separated set lines). Used by the lenient-path case, which
// needs CompileConfigLenient rather than compileSet's strict CompileConfig.
func treeFromSet(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	return tree
}

// TestTunnelOuterFamilyGate exercises the #5162 cross-field outer-family
// gate directly: a mixed-family GRE outer pair (both orders, interface-
// and unit-level) is rejected on the strict path and downgraded to a
// warning on the lenient path, while a same-family v4/v4 and v6/v6 pair
// (and a WireGuard tunnel, which carries no Source/Destination) are
// accepted. This is the fail-on-revert guard for the gate function.
func TestTunnelOuterFamilyGate(t *testing.T) {
	// (a) v4 source + v6 destination, interface-level → strict reject.
	cfgA := &Config{}
	cfgA.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{
			Mode: "gre", Source: "192.0.2.1", Destination: "2001:db8::1"}},
	}
	if _, err := validateTunnelOuterFamilyStrict(cfgA, false); !hasFamilyMismatch(err) {
		t.Fatalf("(a) v4-src/v6-dst GRE must be rejected, got %v", err)
	} else if !strings.Contains(err.Error(), strictTail5162) {
		t.Fatalf("(a) strict rejection must carry the refused outcome (#18958), got %v", err)
	}

	// (b) reverse order: v6 source + v4 destination → strict reject.
	cfgB := &Config{}
	cfgB.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{
			Mode: "gre", Source: "2001:db8::1", Destination: "192.0.2.1"}},
	}
	if _, err := validateTunnelOuterFamilyStrict(cfgB, false); !hasFamilyMismatch(err) {
		t.Fatalf("(b) v6-src/v4-dst GRE must be rejected, got %v", err)
	} else if !strings.Contains(err.Error(), strictTail5162) {
		t.Fatalf("(b) strict rejection must carry the refused outcome (#18958), got %v", err)
	}

	// (c) same-family v4/v4 → no error (over-reject guard).
	cfgC := &Config{}
	cfgC.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{
			Mode: "gre", Source: "192.0.2.1", Destination: "192.0.2.2"}},
	}
	if w, err := validateTunnelOuterFamilyStrict(cfgC, false); err != nil || len(w) != 0 {
		t.Fatalf("(c) v4/v4 GRE must commit clean, got err=%v warns=%v", err, w)
	}

	// (d) same-family v6/v6 → no error (over-reject guard).
	cfgD := &Config{}
	cfgD.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{
			Mode: "gre", Source: "2001:db8::1", Destination: "2001:db8::2"}},
	}
	if w, err := validateTunnelOuterFamilyStrict(cfgD, false); err != nil || len(w) != 0 {
		t.Fatalf("(d) v6/v6 GRE must commit clean, got err=%v warns=%v", err, w)
	}

	// (e) unit-level mixed pair → strict reject naming the tunnel.
	cfgE := &Config{}
	cfgE.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Tunnel: &TunnelConfig{Mode: "gre", Source: "192.0.2.1", Destination: "2001:db8::1"}},
		}},
	}
	if _, err := validateTunnelOuterFamilyStrict(cfgE, false); !hasFamilyMismatch(err) {
		t.Fatalf("(e) unit-level mixed GRE must be rejected, got %v", err)
	} else if !strings.Contains(err.Error(), strictTail5162) {
		t.Fatalf("(e) strict rejection must carry the refused outcome (#18958), got %v", err)
	}

	// (f) WireGuard tunnel (no Source/Destination) → skipped, no error.
	cfgF := &Config{}
	cfgF.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"wg0": {Name: "wg0", Tunnel: &TunnelConfig{Mode: "wireguard"}},
	}
	if w, err := validateTunnelOuterFamilyStrict(cfgF, false); err != nil || len(w) != 0 {
		t.Fatalf("(f) WireGuard tunnel must be skipped, got err=%v warns=%v", err, w)
	}

	// (g) lenient path: the mixed pair downgrades to a warning, no error
	// (#1960 no-brick — the Rust helper skips the row independently).
	if w, err := validateTunnelOuterFamilyStrict(cfgA, true); err != nil {
		t.Fatalf("(g) lenient must not reject a mixed pair, got %v", err)
	} else if len(w) == 0 || !strings.Contains(w[0], "different address families") ||
		!strings.Contains(w[0], lenientTail5162) {
		t.Fatalf("(g) lenient must warn with the commits-clean outcome (#18958), got %v", w)
	}
}

// TestGRETunnelMixedOuterFamilyRejectedAtCommit is the end-to-end
// fail-on-revert guard: the gate is wired into the strict commit path
// (CompileConfig) so a mixed-family GRE tunnel is HARD-REJECTED at commit
// instead of committing clean and silently dropping every encap. It also
// pins the over-reject guard (same-family tunnels still commit) and the
// #1960 lenient-load downgrade.
func TestGRETunnelMixedOuterFamilyRejectedAtCommit(t *testing.T) {
	// Mixed v4 source + v6 destination → rejected at strict commit.
	if _, err := compileSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 2001:db8::1",
	}); !hasFamilyMismatch(err) {
		t.Fatalf("mixed v4/v6 GRE must be rejected at commit, got %v", err)
	} else if !strings.Contains(err.Error(), strictTail5162) {
		t.Fatalf("commit rejection must carry the refused outcome (#18958), got %v", err)
	}

	// Reverse: v6 source + v4 destination → rejected at strict commit.
	if _, err := compileSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 2001:db8::1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.1",
	}); !hasFamilyMismatch(err) {
		t.Fatalf("mixed v6/v4 GRE must be rejected at commit, got %v", err)
	} else if !strings.Contains(err.Error(), strictTail5162) {
		t.Fatalf("commit rejection must carry the refused outcome (#18958), got %v", err)
	}

	// Over-reject guard: a same-family v4/v4 GRE tunnel commits clean.
	if _, err := compileSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
	}); err != nil {
		t.Fatalf("v4/v4 GRE must commit clean, got %v", err)
	}

	// Over-reject guard: a same-family v6/v6 GRE tunnel commits clean.
	if _, err := compileSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 2001:db8::1",
		"set interfaces gr-0/0/0 tunnel destination 2001:db8::2",
	}); err != nil {
		t.Fatalf("v6/v6 GRE must commit clean, got %v", err)
	}

	// Lenient load path: the same mixed config warns (does not reject) so
	// an upgraded / peer-synced node still boots (#1960).
	tree := treeFromSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 2001:db8::1",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not reject a mixed GRE tunnel, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "different address families") &&
			strings.Contains(w, lenientTail5162) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient load must surface a mixed-family warning, got %v", cfg.Warnings)
	}
}
