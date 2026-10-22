package config

import "testing"

// #4713: the BGP compiler parsed peer-as / local-as with `strconv.Atoi(v)`
// then cast to `uint32(n)`, which SILENTLY WRAPPED an out-of-range or negative
// AS onto a different-but-valid ASN: `peer-as -1` -> remote-as 4294967295, and
// `peer-as 5000000000` -> 705032704 (a small-looking ASN). The operator's
// intended AS then differed from what was programmed into frr.conf, with no
// diagnostic.
//
// The strict operator commit / commit-check path already hard-rejects these at
// the typed-leaf SchemaValidate gate (#4589, ValidateInteger(1, 4294967295) on
// every peer-as/local-as leaf) — TestBGPASWrapCommitRejected below pins that.
// The residual #4713 gap was the LENIENT load / peer-sync path
// (compileTreeLenient / CompileConfigLenient), where SchemaValidate is
// downgraded to a warning so a persisted or peer-synced config still boots
// (#1960): there the compiler still wrapped the bad AS into a valid-looking
// ASN and the FRR renderer emitted `remote-as <garbage>` — the leniently-loaded
// bad neighbor peered under a wrong-but-valid ASN instead of being inert.
//
// The fix parses every AS leaf via parseASNumber (strconv.ParseUint(v, 10, 32)
// + reject 0), leaving the field UNSET on a bad value so the renderer's
// remote-as-0 skip / local-as-0 omit (#2963) keeps the neighbor inert.
//
// RED-on-revert: restore the raw `Atoi(v); uint32(n)` at the parse sites and
// the wrap returns — the lenient compile yields the wrapped ASN (4294967295 /
// 705032704) and TestBGPASWrapLenientInert fails.

// firstBGPNeighbor returns the single compiled neighbor for a config that
// declares exactly one, or fails.
func firstBGPNeighbor(t *testing.T, cfg *Config) *BGPNeighbor {
	t.Helper()
	if cfg.Protocols.BGP == nil {
		t.Fatalf("no BGP config compiled")
	}
	if len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected exactly 1 neighbor, got %d", len(cfg.Protocols.BGP.Neighbors))
	}
	return cfg.Protocols.BGP.Neighbors[0]
}

// TestBGPASWrapLenientInert is the RED-on-revert core: on the tolerant
// load / peer-sync compile path a negative or oversized peer-as / local-as
// must NOT wrap into a valid-looking ASN — it must be left unset (0) so the
// neighbor renders inert (remote-as-0 skipped, local-as-0 omitted).
func TestBGPASWrapLenientInert(t *testing.T) {
	cases := []struct {
		name        string
		sets        []string
		wantPeerAS  uint32 // expected neighbor.PeerAS after lenient compile
		wantLocalAS uint32 // expected neighbor.LocalAS after lenient compile
	}{
		{
			name: "neighbor peer-as negative wraps to unset",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group EXT neighbor 10.0.2.1 peer-as -1",
			},
			wantPeerAS: 0, // pre-fix: 4294967295
		},
		{
			name: "neighbor peer-as oversized wraps to unset",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group EXT neighbor 10.0.2.1 peer-as 5000000000",
			},
			wantPeerAS: 0, // pre-fix: 705032704
		},
		{
			name: "group peer-as oversized wraps to unset (inherited by neighbor)",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group EXT peer-as 5000000000",
				"set protocols bgp group EXT neighbor 10.0.2.1 description peer",
			},
			wantPeerAS: 0, // pre-fix: 705032704 inherited
		},
		{
			name: "neighbor local-as negative wraps to unset",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group EXT neighbor 10.0.2.1 peer-as 65001",
				"set protocols bgp group EXT neighbor 10.0.2.1 local-as -1",
			},
			wantPeerAS:  65001,
			wantLocalAS: 0, // pre-fix: 4294967295
		},
		{
			name: "neighbor local-as oversized wraps to unset",
			sets: []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group EXT neighbor 10.0.2.1 peer-as 65001",
				"set protocols bgp group EXT neighbor 10.0.2.1 local-as 5000000000",
			},
			wantPeerAS:  65001,
			wantLocalAS: 0, // pre-fix: 705032704
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, tc.sets)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			n := firstBGPNeighbor(t, cfg)
			if n.PeerAS != tc.wantPeerAS {
				t.Errorf("neighbor PeerAS = %d, want %d (a non-zero here is the #4713 uint32 wrap)", n.PeerAS, tc.wantPeerAS)
			}
			if n.LocalAS != tc.wantLocalAS {
				t.Errorf("neighbor LocalAS = %d, want %d (a non-zero here is the #4713 uint32 wrap)", n.LocalAS, tc.wantLocalAS)
			}
		})
	}
}

// TestBGPTopLevelLocalASWrapLenientInert covers the top-level `protocols bgp
// local-as` leaf (parsed from child.Keys[1], a separate site): an out-of-range
// value must leave LocalAS unset (0), not the wrapped ASN.
func TestBGPTopLevelLocalASWrapLenientInert(t *testing.T) {
	for _, set := range []string{
		"set protocols bgp local-as 5000000000",
		"set protocols bgp local-as -1",
	} {
		t.Run(set, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{set})
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Protocols.BGP != nil && cfg.Protocols.BGP.LocalAS != 0 {
				t.Errorf("top-level LocalAS = %d, want 0 (a non-zero here is the #4713 uint32 wrap)", cfg.Protocols.BGP.LocalAS)
			}
		})
	}
}

// TestBGPASWrapCommitRejected pins the strict commit posture: an out-of-range
// or negative peer-as / local-as is hard-rejected at commit / commit-check
// (SchemaValidate, #4589). This documents the full fail-closed posture; it is
// green independent of the compiler fix (the schema gate is the strict-path
// belt), so it is NOT the RED-on-revert probe — TestBGPASWrapLenientInert is.
func TestBGPASWrapCommitRejected(t *testing.T) {
	for _, set := range []string{
		"set protocols bgp group EXT neighbor 10.0.2.1 peer-as -1",
		"set protocols bgp group EXT neighbor 10.0.2.1 peer-as 5000000000",
		"set protocols bgp group EXT local-as -1",
		"set protocols bgp group EXT local-as 5000000000",
		"set protocols bgp local-as -1",
		"set protocols bgp local-as 5000000000",
	} {
		t.Run(set, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{set})
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("SchemaValidate accepted out-of-range AS %q; expected commit rejection", set)
			}
		})
	}
}

// TestBGPASValidUnchanged is the over-rejection guard: valid AS numbers at
// every boundary (1, 65535, 65536, 4294967295) parse and compile to the exact
// value on both the strict and lenient paths.
func TestBGPASValidUnchanged(t *testing.T) {
	for _, as := range []uint32{1, 65535, 65536, 4294967295} {
		t.Run("peer-as", func(t *testing.T) {
			sets := []string{
				"set protocols bgp local-as 65000",
				"set protocols bgp group EXT neighbor 10.0.2.1 peer-as " + itoaU32(as),
			}
			tree := buildTreeFromSet(t, sets)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate rejected valid peer-as %d: %v", as, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile valid peer-as %d: %v", as, err)
			}
			if got := firstBGPNeighbor(t, cfg).PeerAS; got != as {
				t.Errorf("neighbor PeerAS = %d, want %d", got, as)
			}
		})
		t.Run("top-level local-as", func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{"set protocols bgp local-as " + itoaU32(as)})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile valid local-as %d: %v", as, err)
			}
			if cfg.Protocols.BGP == nil || cfg.Protocols.BGP.LocalAS != as {
				t.Errorf("top-level LocalAS = %v, want %d", cfg.Protocols.BGP, as)
			}
		})
	}
}

func itoaU32(v uint32) string {
	// small local helper to avoid importing strconv in the test for one call
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
