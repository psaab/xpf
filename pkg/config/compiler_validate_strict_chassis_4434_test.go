package config

import (
	"fmt"
	"strings"
	"testing"
)

// #4434 (codex-172 C172-H02): the HA heartbeat group-count field and each
// per-group id byte are uint8 (pkg/cluster/heartbeat.go), and neither the
// chassis schema nor compileChassis bounded the redundancy-group cardinality
// or id. So a config with 256+ redundancy-groups advertised a count byte of 0
// (wire desync against the 256 records still written) and a redundancy-group
// id > 255 truncated on the wire and collided with another group.
// validateChassisClusterStrict makes both an operator-visible commit error.
//
// FAIL-ON-REVERT: remove the validateChassisClusterStrict dispatch in
// compileExpanded (compiler.go) or the range checks in the validator and the
// over-size / over-id subtests go green on the BAD config — exactly the
// wire-desync regression this test exists to catch. The tolerant-path and
// in-range subtests pin that the gate does not over-reject.

// rgSetLines returns the flat-set lines that define n redundancy groups with
// sequential ids 0..n-1, each with a well-formed node priority so the compiler
// materializes a RedundancyGroup instance.
func rgSetLines(n int) []string {
	lines := make([]string, 0, n+3)
	lines = append(lines, "set chassis cluster cluster-id 1")
	lines = append(lines, "set chassis cluster authentication-key test-cluster-psk-6611")
	// #16746: opt out of private-RG election so the wire-width gates
	// below are the first error, not the complete-control-link gate.
	lines = append(lines, "set chassis cluster no-private-rg-election")
	for i := 0; i < n; i++ {
		lines = append(lines,
			fmt.Sprintf("set chassis cluster redundancy-group %d node 0 priority 100", i))
	}
	return lines
}

func TestChassisRedundancyGroupCardinalityFailsCommit(t *testing.T) {
	// 256 groups (ids 0..255) — the count byte would wrap uint8(256) == 0.
	tree := buildTree(t, rgSetLines(MaxHeartbeatRedundancyGroups+1))

	cfg, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject %d redundancy-groups (heartbeat "+
			"count byte is uint8), got nil error", MaxHeartbeatRedundancyGroups+1)
	}
	if !strings.Contains(err.Error(), "redundancy-groups exceeds") {
		t.Fatalf("error %q does not describe the redundancy-group cardinality cap", err.Error())
	}
	_ = cfg

	// Tolerant path (load / peer-sync) must NOT brick — it downgrades to a
	// warning so an already-persisted config still boots.
	lcfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must not reject an over-size RG set (no-brick), got %v", lerr)
	}
	if !warningsContain(lcfg.Warnings, "chassis cluster redundancy-group") {
		t.Fatalf("lenient compile should have warned about the RG cardinality; warnings=%v", lcfg.Warnings)
	}
}

func TestChassisRedundancyGroupIDFailsCommit(t *testing.T) {
	// A single group with an id > 255 truncates on the wire.
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 300 node 0 priority 100",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject redundancy-group id 300 (heartbeat " +
			"id byte is uint8), got nil error")
	}
	if !strings.Contains(err.Error(), "id 300") || !strings.Contains(err.Error(), "out of") {
		t.Fatalf("error %q does not name the out-of-range redundancy-group id", err.Error())
	}
}

// #8317 NARROWED THIS DELIBERATELY — read before "restoring" the 255s.
//
// This cell asserted that 255 groups (ids 0..254) and an id of exactly 255
// commit cleanly, because both fit the uint8 heartbeat wire fields. That was
// true of the WIRE and false of the dataplane: the id is used directly as the
// index into the `rg_active` / `ha_watchdog` arrays, which hold
// MaxRedundancyGroups (16) entries. A BPF array with max_entries 16 returns
// E2BIG at key 16, and `UpdateRGActive` propagates that error before recording
// the group or syncing HA state, so an id >= 16 could COMMIT but never
// ACTIVATE — its RETH interfaces never forwarded and the reconcile loop retried
// forever.
//
// So the old assertions pinned commit-acceptance of configs that could not
// function. The bound is now the array length, and the in-range boundary moves
// with it. This is a narrowing of what commits, and it is intentional: it turns
// a silent runtime failure into a loud commit-time one. No WORKING config
// loses, because no config with an id >= 16 was ever working.
//
// The alternative — growing the arrays to 256 so those ids function — is
// recorded on #8317. It would preserve the original 255s but costs a Go + Rust
// (`MAX_RG_EPOCHS`) + shim-rebuild change; the bound is Go-only.
func TestChassisRedundancyGroupInRangeCommits(t *testing.T) {
	// The boundary is now the dataplane array length: MaxRedundancyGroups
	// groups (ids 0..MaxRedundancyGroups-1) and an id of exactly
	// MaxRedundancyGroups-1 must commit cleanly. Derived from the constant, not
	// spelled as a literal, so growing the arrays moves this with them.
	tree := buildTree(t, rgSetLines(MaxRedundancyGroups))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("commit rejected %d in-range redundancy-groups: %v", MaxRedundancyGroups, err)
	}

	boundary := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		fmt.Sprintf("set chassis cluster redundancy-group %d node 1 priority 100", MaxRedundancyGroups-1),
	})
	if _, err := CompileConfig(boundary); err != nil {
		t.Fatalf("commit rejected a boundary redundancy-group id %d: %v", MaxRedundancyGroups-1, err)
	}

	// A cluster with no redundancy-group stanza at all is unaffected.
	none := buildTree(t, []string{"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611"})
	if _, err := CompileConfig(none); err != nil {
		t.Fatalf("commit rejected a cluster with no redundancy-groups: %v", err)
	}
}
