package config

import "testing"

// stable_iface_ambiguous_12075_test.go — Review12304 P2: the shared #7095/#12075
// fold resolver must fail CLOSED when the owner lookup is ambiguous.
//
// Two DISTINCT authored member names can canonicalize to the SAME Linux device
// (`ge-0/0/1` and `ge-0-0-1` both → `ge-0-0-1`, #5832). Strict commit rejects
// the pair, but the tolerant load / peer-sync path warns and keeps BOTH
// (#1960 no-brick), so a grandfathered config can carry one member under
// `reth0` and the colliding spelling under `reth1`. The resolver loop in
// ClusterStableIfaceName iterates RethToPhysical() — a MAP — and used to break
// on the first canonical match, so the fold for that device was a coin flip
// between the two reths (a prior reviewer probe observed 7874/2126 over 10k
// calls). Picking one names a device the peer may not mean; returning "" folds
// to 0 (unknown) and degrades to the zone approximation, the honest answer —
// the same doctrine LocalIfaceForStableID already applies to reverse-lookup
// collisions.

// compiledIfaceCfg12075 compiles flat-set members through the tolerant load
// path, preserving the grandfathered collision behavior exercised here.
func compiledIfaceCfg12075(t *testing.T, lines ...string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(flatTreeFromSets(t, lines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient(%v): %v", lines, err)
	}
	return cfg
}

func collidingMembersCfg12075(t *testing.T) *Config {
	t.Helper()
	return compiledIfaceCfg12075(t,
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces ge-0-0-1 gigether-options redundant-parent reth1",
	)
}

func unambiguousMembersCfg12075(t *testing.T) *Config {
	t.Helper()
	return compiledIfaceCfg12075(t,
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
	)
}

// TestStableIfaceOwnerWithoutRethMatchKeepsName_12075 covers the zero-match
// fallback: an owner outside every RETH keeps its original stable name.
func TestStableIfaceOwnerWithoutRethMatchKeepsName_12075(t *testing.T) {
	cfg := compiledIfaceCfg12075(t, "set interfaces fxp0 description management")
	if got := cfg.ClusterStableIfaceName("fxp0", 0); got != "fxp0" {
		t.Fatalf("owner without a matching RETH folded to %q, want its original name %q", got, "fxp0")
	}
}

// TestStableIfaceAmbiguousOwnerFailsClosed_12075 probes 10,000 calls: with
// two reths claiming the same Linux device, every fold must be zero. Before
// the fix, map iteration makes the results split nondeterministically.
func TestStableIfaceAmbiguousOwnerFailsClosed_12075(t *testing.T) {
	cfg := collidingMembersCfg12075(t)
	// Precondition guard: the tolerant compiler must retain both owners.
	m := cfg.RethToPhysical()
	if len(m) != 2 || LinuxIfName(m["reth0"]) != LinuxIfName(m["reth1"]) {
		t.Fatalf("fixture lost its collision: RethToPhysical=%v", m)
	}
	const n = 10000
	seen := make(map[uint32]int)
	for i := 0; i < n; i++ {
		fold := StableIfaceID(cfg.ClusterStableIfaceName("ge-0-0-1", 0))
		seen[fold]++
	}
	if len(seen) != 1 || seen[0] != n {
		t.Fatalf("ambiguous owner produced folds %v over %d calls, want exactly {%#x:%d}",
			seen, n, uint32(0), n)
	}
}

// TestStableIfaceUnambiguousOwnerDeterministic_12075 is the control: on a
// NON-colliding config 10,000 calls must yield the same nonzero reth fold.
func TestStableIfaceUnambiguousOwnerDeterministic_12075(t *testing.T) {
	cfg := unambiguousMembersCfg12075(t)
	const n = 10000
	seen := make(map[uint32]int)
	for i := 0; i < n; i++ {
		fold := StableIfaceID(cfg.ClusterStableIfaceName("ge-0-0-1", 0))
		seen[fold]++
	}
	if len(seen) != 1 {
		t.Fatalf("unambiguous owner produced %d distinct folds %v, want exactly one", len(seen), seen)
	}
	for fold := range seen {
		if fold == 0 {
			t.Fatal("unambiguous owner folded to 0 (unknown); want the member's nonzero reth fold")
		}
		if want := StableIfaceID("reth1"); fold != want {
			t.Fatalf("unambiguous owner folded to %#x, want StableIfaceID(reth1)=%#x", fold, want)
		}
	}
}
