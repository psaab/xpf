package config

import (
	"strings"
	"testing"
)

// hasGreDupOuter reports whether err carries the #10654 duplicate-GRE-outer
// rejection message.
func hasGreDupOuter(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate GRE outer")
}

// greDupTunnel returns an interface-level GRE tunnel with the given outer
// pair and key for the #10654 gate cells.
func greDupTunnel(mode, src, dst string, key uint32) *TunnelConfig {
	return &TunnelConfig{Mode: mode, Source: src, Destination: dst, Key: key}
}

// TestGreDuplicateOuterGate10654 exercises the #10654 cross-tunnel
// outer-identity gate directly: two GRE endpoints sharing an identical outer
// (source, destination, key) triple match exactly the same inbound frames,
// and Rust decap (match_tunnel_endpoint) returns the first key-matching
// endpoint in snapshot order — so the strict path hard-rejects the
// collision instead of committing into ambiguous attribution. This is the
// fail-on-revert guard for the gate function: delete the gate body and
// cases (a), (b), (f), (g) go RED.
func TestGreDuplicateOuterGate10654(t *testing.T) {
	// (a) identical v4 outer + same key on two tunnels → strict reject
	// naming the first-sorting owner.
	cfgA := &Config{}
	cfgA.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)},
	}
	if _, err := validateGreDuplicateOuterStrict(cfgA, false); !hasGreDupOuter(err) {
		t.Fatalf("(a) identical GRE outer+key must be rejected, got %v", err)
	} else if !strings.Contains(err.Error(), `"gr-0/0/0"`) {
		t.Fatalf("(a) rejection must name the first-sorting owner tunnel, got %v", err)
	}

	// (b) two UNKEYED tunnels (key 0) on one outer pair → strict reject:
	// both match every unkeyed frame, so key 0 still collides.
	cfgB := &Config{}
	cfgB.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 0)},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 0)},
	}
	if _, err := validateGreDuplicateOuterStrict(cfgB, false); !hasGreDupOuter(err) {
		t.Fatalf("(b) duplicate unkeyed GRE outer must be rejected, got %v", err)
	} else if !strings.Contains(err.Error(), "key 0 (unkeyed)") {
		t.Fatalf("(b) rejection must spell out the unkeyed key, got %v", err)
	}

	// (c) same outer pair, DIFFERENT keys → clean (over-reject guard):
	// each keyed frame matches exactly one row.
	cfgC := &Config{}
	cfgC.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 8)},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgC, false); err != nil || len(w) != 0 {
		t.Fatalf("(c) distinct GRE keys on one outer pair must commit clean, got err=%v warns=%v", err, w)
	}

	// (d) keyed + unkeyed on one outer pair → clean (over-reject guard):
	// the Rust key predicate disambiguates (keyed frames match only the
	// keyed row, unkeyed frames only the unkeyed row).
	cfgD := &Config{}
	cfgD.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 0)},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgD, false); err != nil || len(w) != 0 {
		t.Fatalf("(d) keyed+unkeyed GRE on one outer pair must commit clean, got err=%v warns=%v", err, w)
	}

	// (e) reversed direction (A,B)+(B,A), same key → clean (over-reject
	// guard): different decap buckets, never the same frames.
	cfgE := &Config{}
	cfgE.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("gre", "192.0.2.2", "192.0.2.1", 7)},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgE, false); err != nil || len(w) != 0 {
		t.Fatalf("(e) reversed GRE direction must commit clean, got err=%v warns=%v", err, w)
	}

	// (f) IPv6 RESPELLINGS of one outer pair ("2001:db8::1" vs the
	// uncompressed form), same key → strict reject: both parse to one
	// Rust bucket key, so they collide on the dataplane.
	cfgF := &Config{}
	cfgF.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "2001:db8::1", "2001:db8::2", 7)},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("gre", "2001:db8:0:0:0:0:0:1", "2001:db8::2", 7)},
	}
	if _, err := validateGreDuplicateOuterStrict(cfgF, false); !hasGreDupOuter(err) {
		t.Fatalf("(f) IPv6-respelled duplicate GRE outer must be rejected, got %v", err)
	}

	// (g) cross-mode gre + ip6gre on one v4 triple, same key → strict
	// reject: Rust tunnel_mode_kind maps BOTH modes to TunnelKind::Gre,
	// so both rows decap from the same bucket.
	cfgG := &Config{}
	cfgG.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("ip6gre", "192.0.2.1", "192.0.2.2", 7)},
	}
	if _, err := validateGreDuplicateOuterStrict(cfgG, false); !hasGreDupOuter(err) {
		t.Fatalf("(g) cross-mode gre/ip6gre duplicate outer must be rejected, got %v", err)
	}

	// (h) WireGuard tunnels carry no outer pair and are never
	// decap-indexed → skipped, no error.
	cfgH := &Config{}
	cfgH.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"wg0": {Name: "wg0", Tunnel: &TunnelConfig{Mode: "wireguard"}},
		"wg1": {Name: "wg1", Tunnel: &TunnelConfig{Mode: "wireguard"}},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgH, false); err != nil || len(w) != 0 {
		t.Fatalf("(h) WireGuard tunnels must be skipped, got err=%v warns=%v", err, w)
	}

	// (i) ipip tunnels are owned by the sibling #4785 gate → skipped HERE,
	// no error from this gate even on an identical outer pair.
	cfgI := &Config{}
	cfgI.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ip-0/0/0": {Name: "ip-0/0/0", Tunnel: greDupTunnel("ipip", "192.0.2.1", "192.0.2.2", 7)},
		"ip-0/0/1": {Name: "ip-0/0/1", Tunnel: greDupTunnel("ipip", "192.0.2.1", "192.0.2.2", 7)},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgI, false); err != nil || len(w) != 0 {
		t.Fatalf("(i) ipip tunnels must be skipped by the GRE gate, got err=%v warns=%v", err, w)
	}

	// (j) half-configured tunnel (destination missing) is already declined
	// by the emitter and never reaches the dataplane → cannot collide.
	cfgJ := &Config{}
	cfgJ.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{Mode: "gre", Source: "192.0.2.1", Key: 7}},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgJ, false); err != nil || len(w) != 0 {
		t.Fatalf("(j) half-configured tunnel must not collide, got err=%v warns=%v", err, w)
	}

	// (k) unparseable endpoint literal is a schema-level concern, not a
	// cross-field duplicate → skipped (same posture as the #5162 gate).
	cfgK := &Config{}
	cfgK.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "not-an-ip", "192.0.2.2", 7)},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: greDupTunnel("gre", "not-an-ip", "192.0.2.2", 7)},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgK, false); err != nil || len(w) != 0 {
		t.Fatalf("(k) unparseable endpoints must be skipped, got err=%v warns=%v", err, w)
	}

	// (l) nil config → no error (defensive; mirrors the sibling gates).
	if w, err := validateGreDuplicateOuterStrict(nil, false); err != nil || len(w) != 0 {
		t.Fatalf("(l) nil config must be clean, got err=%v warns=%v", err, w)
	}

	// (m) lenient path: the duplicate downgrades to a warning, no error
	// (#1960 no-brick — the snapshot builder drops the later-sorting
	// collider loudly, so the loaded tunnel is inert).
	if w, err := validateGreDuplicateOuterStrict(cfgA, true); err != nil {
		t.Fatalf("(m) lenient must not reject a duplicate GRE outer, got %v", err)
	} else if len(w) == 0 || !strings.Contains(w[0], "duplicate GRE outer") {
		t.Fatalf("(m) lenient must warn on a duplicate GRE outer, got %v", w)
	}

	// (n) determinism: the emitter walks sorted-by-Name, so both HA nodes
	// report the same owner on the same config.
	for i := 0; i < 50; i++ {
		_, err := validateGreDuplicateOuterStrict(cfgA, false)
		if !hasGreDupOuter(err) || !strings.Contains(err.Error(), `"gr-0/0/0"`) {
			t.Fatalf("(n) iteration %d: owner report must be stable, got %v", i, err)
		}
	}

	// (o) same triple in DIFFERENT transport instances → clean
	// (over-reject guard): #10653 selects by ingress VRF, so the rows are
	// unambiguous and must commit.
	tunO1 := greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)
	tunO1.RoutingInstance = "blue"
	tunO2 := greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)
	tunO2.RoutingInstance = "red"
	cfgO := &Config{}
	cfgO.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: tunO1},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: tunO2},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgO, false); err != nil || len(w) != 0 {
		t.Fatalf("(o) same triple in different instances must be clean, got err=%v warns=%v", err, w)
	}

	// (p) same triple in the SAME transport instance → strict reject: the
	// VRF arm does not save a genuinely ambiguous pair.
	tunP1 := greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)
	tunP1.RoutingInstance = "blue"
	tunP2 := greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 7)
	tunP2.RoutingInstance = "blue"
	cfgP := &Config{}
	cfgP.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: tunP1},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: tunP2},
	}
	if _, err := validateGreDuplicateOuterStrict(cfgP, false); !hasGreDupOuter(err) {
		t.Fatalf("(p) same triple in one instance must be rejected, got %v", err)
	}

	// (q) pure inheritance: two units with NO tunnel stanza reuse the
	// interface *TunnelConfig object (the #7509/#5631 multi-unit
	// logical model) → clean. This is ONE definition, not a duplicate.
	cfgQ := &Config{}
	cfgQ.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 0),
			Units: map[int]*InterfaceUnit{0: {}, 1: {}}},
	}
	if w, err := validateGreDuplicateOuterStrict(cfgQ, false); err != nil || len(w) != 0 {
		t.Fatalf("(q) inherited multi-unit endpoints must be clean, got err=%v warns=%v", err, w)
	}

	// (r) per-unit CLONES with the same outer+key (distinct objects, as
	// cloneForUnit produces for units WITH stanzas) → strict reject:
	// separate definitions sharing one identity genuinely collide.
	cfgR := &Config{}
	cfgR.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 0),
			Units: map[int]*InterfaceUnit{
				0: {Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 0)},
				1: {Tunnel: greDupTunnel("gre", "192.0.2.1", "192.0.2.2", 0)},
			}},
	}
	if _, err := validateGreDuplicateOuterStrict(cfgR, false); !hasGreDupOuter(err) {
		t.Fatalf("(r) per-unit clones sharing one outer must be rejected, got %v", err)
	}
}

// TestGreDuplicateOuterRejectedAtCommit10654 is the end-to-end
// fail-on-revert guard: the gate is wired into the strict commit path
// (CompileConfig via runTailGates) so a duplicate GRE outer-tuple/key pair
// is HARD-REJECTED at commit instead of committing clean into ambiguous
// decap attribution. It also pins the over-reject guards (distinct keys,
// keyed-vs-unkeyed, and reversed direction still commit) and the #1960
// lenient-load downgrade. Revert the tailgate wiring and the strict
// assertions go RED.
func TestGreDuplicateOuterRejectedAtCommit10654(t *testing.T) {
	dupKeyed := []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel key 7",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/1 tunnel key 7",
	}

	// Duplicate keyed outer triple → rejected at strict commit.
	if _, err := compileSet(t, dupKeyed); !hasGreDupOuter(err) {
		t.Fatalf("duplicate keyed GRE outer must be rejected at commit, got %v", err)
	}

	// Duplicate UNKEYED outer pair (no key stanza on either) → rejected:
	// both tunnels match every unkeyed frame.
	if _, err := compileSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.2",
	}); !hasGreDupOuter(err) {
		t.Fatalf("duplicate unkeyed GRE outer must be rejected at commit, got %v", err)
	}

	// Over-reject guard: same outer pair with distinct keys commits clean.
	if _, err := compileSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel key 7",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/1 tunnel key 8",
	}); err != nil {
		t.Fatalf("distinct GRE keys on one outer pair must commit clean, got %v", err)
	}

	// Over-reject guard: keyed + unkeyed on one outer pair commits clean.
	if _, err := compileSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel key 7",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.2",
	}); err != nil {
		t.Fatalf("keyed+unkeyed GRE on one outer pair must commit clean, got %v", err)
	}

	// Over-reject guard: reversed direction commits clean.
	if _, err := compileSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel key 7",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.2",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.1",
		"set interfaces gr-0/0/1 tunnel key 7",
	}); err != nil {
		t.Fatalf("reversed GRE direction must commit clean, got %v", err)
	}

	// Lenient load path: the same duplicate warns (does not reject) so an
	// upgraded / peer-synced node still boots (#1960).
	tree := treeFromSet(t, dupKeyed)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not reject a duplicate GRE outer, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "duplicate GRE outer") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient load must surface a duplicate-GRE-outer warning, got %v", cfg.Warnings)
	}
}
