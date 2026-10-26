package config

import (
	"strings"
	"testing"
)

// #4826: the RETH-derived VRRP GroupID (100+rgID, CollectRethInstances in
// pkg/vrrp/vrrp.go) had no commit-time bound, unlike the explicit
// `vrrp-group <id>` path (#4573, validateVRRPGroupIDStrict). The chassis
// redundancy-group id validator (validateChassisClusterStrict) caps id at
// 255 — the heartbeat wire bound — not the VRRP one, so a redundancy-group
// in 156..255 committed cleanly and then silently lost VRRP for the whole
// group at runtime (pkg/vrrp/manager.go UpdateInstances skips an
// out-of-range GroupID with only a WARN log). validateRethVRRPGroupIDStrict
// closes that gap by rejecting a redundancy-group id whose derived VRID
// (100+id) would overflow the RFC 5798 byte range.
//
// FAIL-ON-REVERT: drop the validateRethVRRPGroupIDStrict dispatch in
// compiler_uniformgates.go (or the range check inside the validator) and
// the out-of-range subtests below go green on the BAD config — exactly the
// silent-VRRP-blackhole regression this test exists to catch.

// rethRedundancyGroupSetLines returns the flat-set lines for a minimal
// chassis-cluster config with a single reth interface in the given
// redundancy-group id. `no-private-rg-election` is required to actually
// activate reth-derived VRRP instance synthesis — private-rg-election
// (election over the control link only, no RETH VRRP) is the compiler
// default for any `chassis cluster` stanza (compiler_system.go), and
// CollectRethInstances early-returns nil while it is set, same as
// no-reth-vrrp.
func rethRedundancyGroupSetLines(id string) []string {
	return []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster reth-count 1",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group " + id + " node 0 priority 200",
		"set chassis cluster redundancy-group " + id + " node 1 priority 100",
		"set interfaces reth0 redundant-ether-options redundancy-group " + id,
	}
}

func TestRethRedundancyGroupIDOverflowsVRIDFailsCommit(t *testing.T) {
	// 156 is the first id whose derived VRID (100+156=256) overflows the
	// single wire byte; 255 is the chassis validator's own ceiling.
	for _, id := range []string{"156", "200", "255"} {
		t.Run("id="+id, func(t *testing.T) {
			tree := buildTree(t, rethRedundancyGroupSetLines(id))
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to reject reth redundancy-group %s "+
					"(derived VRID 100+%s overflows the RFC 5798 byte range), "+
					"got nil error", id, id)
			} else if !stringContainsAll(err.Error(),
				"redundancy-group "+id, "out of range") {
				t.Fatalf("error %q does not name the out-of-range "+
					"redundancy-group id %s", err.Error(), id)
			}

			// Tolerant path (load / peer-sync) must NOT brick — it downgrades
			// to a warning so an already-persisted config still boots (#1960).
			lcfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient compile must not reject an out-of-range "+
					"reth redundancy-group id (no-brick), got %v", lerr)
			}
			if !warningsContain(lcfg.Warnings, "redundancy-group") {
				t.Fatalf("lenient compile should have warned about the "+
					"reth redundancy-group id; warnings=%v", lcfg.Warnings)
			}
		})
	}
}

func TestRethRedundancyGroupIDInRangeCommits(t *testing.T) {
	// 1 and 155 are the boundaries: 100+155=255 still fits the VRID byte.
	for _, id := range []string{"1", "100", "155"} {
		t.Run("id="+id, func(t *testing.T) {
			tree := buildTree(t, rethRedundancyGroupSetLines(id))
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("in-range reth redundancy-group %s must commit "+
					"cleanly, got %v", id, err)
			}
			if warningsContain(cfg.Warnings, "redundancy-group") {
				t.Fatalf("in-range reth redundancy-group %s should not warn; "+
					"warnings=%v", id, cfg.Warnings)
			}
		})
	}
}

// TestRethRedundancyGroupIDOverflowSkippedWhenRGElectionPrivate pins that
// the gate mirrors CollectRethInstances' own early return: private RG
// election (the compiler default for any `chassis cluster` stanza — no
// synthesized RETH VRRP instance at all, election happens over the control
// link only) means an overflowing redundancy-group id has no runtime
// consequence and must not be rejected.
func TestRethRedundancyGroupIDOverflowSkippedWhenRGElectionPrivate(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster reth-count 1",
		"set chassis cluster redundancy-group 200 node 0 priority 200",
		"set chassis cluster redundancy-group 200 node 1 priority 100",
		"set interfaces reth0 redundant-ether-options redundancy-group 200",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("default private-rg-election must not reject an "+
			"overflowing redundancy-group id (no synthesized VRRP "+
			"instance), got %v", err)
	}
	if warningsContain(cfg.Warnings, "redundancy-group") {
		t.Fatalf("private-rg-election should not warn about "+
			"redundancy-group id; warnings=%v", cfg.Warnings)
	}
}

// TestRethRedundancyGroupIDOverflowSkippedUnderNoRethVRRP is the legacy-VRRP
// sibling: with no-private-rg-election active (so reth VRRP would otherwise
// synthesize), explicit no-reth-vrrp still suppresses instance creation
// entirely and the overflowing id must not be rejected.
func TestRethRedundancyGroupIDOverflowSkippedUnderNoRethVRRP(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster reth-count 1",
		"set chassis cluster redundancy-group 200 node 0 priority 200",
		"set chassis cluster redundancy-group 200 node 1 priority 100",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster no-reth-vrrp",
		"set interfaces reth0 redundant-ether-options redundancy-group 200",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("no-reth-vrrp must not reject an overflowing "+
			"redundancy-group id (no synthesized VRRP instance), got %v", err)
	}
	if warningsContain(cfg.Warnings, "redundancy-group") {
		t.Fatalf("no-reth-vrrp should not warn about redundancy-group id; "+
			"warnings=%v", cfg.Warnings)
	}
}

// stringContainsAll reports whether s contains every substring in subs.
func stringContainsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
