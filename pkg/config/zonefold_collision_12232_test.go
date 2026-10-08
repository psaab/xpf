package config

import (
	"testing"
)

// TestZoneLocalFoldLiteralTwinSentinelRefuses12232 pins the #12232
// sentinel-refuse: a persisted pre-validator config whose GLOBAL book holds an
// entry literally named `zone-local/trust/<name>` (P1) alongside a ZONE-LOCAL
// `<name>` (P2) in trust must never silently bind the trust policy to the
// operator's global twin P1. The fold's no-clobber skip keeps the operator
// entry (no-clobber preserved), but the qualified key must land in
// CollidingNames so userspace policy lowering refuses the reference
// (addrRepresentable / nameRepresentability return false) instead of
// resolving the wrong value. The tolerant path still boots (#1960 no-brick).
//
// FAIL-ON-REVERT: removing the CollidingNames mark from the fold's skip branch
// makes the mark assertions go RED while the policy token still rewrites to
// the qualified twin — the silent misbinding.
func TestZoneLocalFoldLiteralTwinSentinelRefuses12232(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0-0-1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0-0-0",
		"set security zones security-zone untrust interfaces ge-0-0-1",
		// Operator literal twin (P1): a global entry literally named with the
		// reserved synthetic prefix — rejected on strict commit, warned on the
		// tolerant path, but present in a persisted pre-validator config.
		"set security address-book global address zone-local/trust/A 10.9.9.0/24",
		"set security address-book global address other 10.9.9.9/32",
		"set security address-book global address-set zone-local/trust/S address other",
		// Zone-local originals (P2).
		"set security zones security-zone trust address-book address A 10.1.0.0/24",
		"set security zones security-zone trust address-book address-set S address A",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address A",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address S",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a persisted pre-validator config: %v", err)
	}

	// Precondition: the fold still rewrites zone-local tokens to the qualified
	// key (the rewrite is unconditional on localDefines).
	pol := findPolicy(t, cfg, "trust", "untrust", "p1")
	assertContains(t, "source-address", pol.Match.SourceAddresses, "zone-local/trust/A")
	assertContains(t, "source-address", pol.Match.SourceAddresses, "zone-local/trust/S")

	// No-clobber preserved: the operator's literal global entries survive.
	if got := cfg.Security.AddressBook.Addresses["zone-local/trust/A"]; got == nil || got.Value != "10.9.9.0/24" {
		t.Fatalf("no-clobber violated: global twin = %+v, want value 10.9.9.0/24", got)
	}
	if cfg.Security.AddressBook.AddressSets["zone-local/trust/S"] == nil {
		t.Fatalf("no-clobber violated: global twin address-set zone-local/trust/S missing")
	}

	// The fix: both skipped qualified keys are marked colliding so the
	// dataplane refuses the policy reference instead of silently binding P1.
	for _, q := range []string{"zone-local/trust/A", "zone-local/trust/S"} {
		if _, ok := cfg.Security.AddressBook.CollidingNames[q]; !ok {
			t.Fatalf("#12232: qualified key %q skipped by the fold is not marked colliding — the trust policy silently binds the global twin", q)
		}
	}
}

// TestZoneLocalFoldNoFalseCollision12232 guards the other side: an ordinary
// zone-local fold with no pre-existing qualified key must NOT mark anything
// colliding — the #12232 mark fires only on a real no-clobber skip.
func TestZoneLocalFoldNoFalseCollision12232(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0-0-1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0-0-0",
		"set security zones security-zone untrust interfaces ge-0-0-1",
		"set security zones security-zone trust address-book address A 10.1.0.0/24",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address A",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile of an ordinary config failed: %v", err)
	}
	if len(cfg.Security.AddressBook.CollidingNames) != 0 {
		t.Fatalf("ordinary fold marked collisions %v, want none", cfg.Security.AddressBook.CollidingNames)
	}
	pol := findPolicy(t, cfg, "trust", "untrust", "p1")
	assertContains(t, "source-address", pol.Match.SourceAddresses, "zone-local/trust/A")
	if got := cfg.Security.AddressBook.Addresses["zone-local/trust/A"]; got == nil || got.Value != "10.1.0.0/24" {
		t.Fatalf("folded zone-local entry = %+v, want value 10.1.0.0/24", got)
	}
}
