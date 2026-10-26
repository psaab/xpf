// #6041 (full-parity follow-up to #5819): a source-NAT pool may configure BOTH
// `persistent-nat` and `port no-translation`. The userspace dataplane now
// implements an ADDRESS-ONLY persistent lease
// (reserve_address_only_persistent, userspace-dp/src/nat/allocator.rs) that
// pins a public pool ADDRESS across the configured permit scope WITHOUT
// consuming a translated pool port. The combination is therefore SUPPORTED:
// it commits cleanly at strict commit AND on the tolerant/lenient load path,
// and the pool materializes as usable (no "persistent_nat_no_translation"
// fail-closed marker).
//
// This replaces the #5819 fail-closed reject
// (validateSourceNATPersistentNoTranslationStrict + its dispatch, removed).
//
// RED-on-revert: reinstating the strict reject makes
// TestSourceNATPersistentNoTranslationAcceptedAtCommit_6041 RED (CompileConfig
// would return an error again).
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath (snatPoolTree),
// never NewParser.
package config

import (
	"strings"
	"testing"
)

// TestSourceNATPersistentNoTranslationAcceptedAtCommit_6041: a pool configuring
// both `persistent-nat` and `port no-translation` now COMMITS cleanly at strict
// commit and materializes with both modifiers set. RED-on-revert (reject
// reinstated): CompileConfig returns an error.
func TestSourceNATPersistentNoTranslationAcceptedAtCommit_6041(t *testing.T) {
	cases := []struct {
		name        string
		sourceMatch string
		pool        []string
	}{
		{"permit-any-remote-host", "", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat permit any-remote-host"}},
		{"permit-target-host", "", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat permit target-host"}},
		{"inactivity-timeout-only", "", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat inactivity-timeout 600"}},
		{"ipv6-pool", "2001:db8:ffff::/64", []string{
			"set security nat source pool p1 address 2001:db8::5/128",
			"set security nat source pool p1 address 2001:db8::6/128",
			"set security nat source pool p1 port no-translation",
			"set security nat source pool p1 persistent-nat permit any-remote-host"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			match := tc.sourceMatch
			if match == "" {
				match = "10.0.0.0/24"
			}
			tree := snatPoolTreeWithMatch(t, match, tc.pool...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected persistent-nat + port no-translation pool (now supported, #6041): %v", err)
			}
			pool := cfg.Security.NAT.SourcePools["p1"]
			if pool == nil {
				t.Fatalf("pool p1 missing from compiled config")
			}
			if !pool.PortNoTranslation {
				t.Fatalf("PortNoTranslation lost")
			}
			if pool.PersistentNAT == nil {
				t.Fatalf("PersistentNAT lost")
			}
		})
	}
}

// TestSourceNATPersistentNoTranslationLenientAccepted_6041: the combo also
// compiles cleanly on the tolerant / lenient load path with NO fail-closed
// warning — the pool is fully supported, not degraded.
func TestSourceNATPersistentNoTranslationLenientAccepted_6041(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 address 203.0.113.6/32",
		"set security nat source pool p1 port no-translation",
		"set security nat source pool p1 persistent-nat permit any-remote-host")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected the now-supported combo: %v", err)
	}
	if cfg.Security.NAT.SourcePools["p1"] == nil {
		t.Fatalf("pool p1 missing from leniently-compiled config")
	}
	// No fail-closed downgrade warning should be emitted for the (now supported)
	// combination.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no-translation") && strings.Contains(w, "persistent-nat") {
			t.Fatalf("unexpected fail-closed warning for a supported combo: %q", w)
		}
	}
}

// TestSourceNATPersistentNoTranslationOtherModifiers_6041: each modifier alone,
// and a plain pool, still compile clean (unchanged behaviour).
func TestSourceNATPersistentNoTranslationOtherModifiers_6041(t *testing.T) {
	t.Run("persistent-nat-without-no-translation", func(t *testing.T) {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 persistent-nat permit any-remote-host")
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected persistent-nat pool WITHOUT no-translation: %v", err)
		}
		pool := cfg.Security.NAT.SourcePools["p1"]
		if pool.PersistentNAT == nil {
			t.Fatalf("PersistentNAT lost")
		}
		if pool.PortNoTranslation {
			t.Fatalf("PortNoTranslation set unexpectedly")
		}
	})
	t.Run("no-translation-without-persistent-nat", func(t *testing.T) {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 address 203.0.113.6/32",
			"set security nat source pool p1 port no-translation")
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected no-translation pool WITHOUT persistent-nat: %v", err)
		}
		pool := cfg.Security.NAT.SourcePools["p1"]
		if !pool.PortNoTranslation {
			t.Fatalf("PortNoTranslation lost")
		}
		if pool.PersistentNAT != nil {
			t.Fatalf("PersistentNAT set unexpectedly")
		}
	})
	t.Run("plain-pool", func(t *testing.T) {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32")
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected plain pool: %v", err)
		}
	})
}
