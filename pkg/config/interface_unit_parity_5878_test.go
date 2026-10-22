package config

import (
	"strings"
	"testing"
)

// #5878: the #5631 numeric interface-unit alias gate originally ran INSIDE
// compileExpanded (runPreWalkGates) AFTER tree.ExpandGroupsWithVars, so it saw
// only the SUBMITTING node's post-`${node}` effective view. A peer-only
// `groups node1 { … unit 01 }` block applied through apply-groups "${node}"
// folds its aliasing spelling onto a base `unit 1` ONLY in the standby node's
// effective view — invisible at a node0 commit (Store.compileTree compiles
// s.nodeID only). The active node commits green; the standby's compiled config
// then diverges and a failover silently changes forwarding / security posture.
//
// The fix promotes the gate to a BOTH-NODE-effective UNION (View 1 pre-expansion
// group union + Views 2/3 node0/node1 expansions) run in the PRE-expansion gate
// block, so a peer-only alias is rejected at EITHER node's commit and the
// accept/reject verdict is identical on both nodes.
//
// These tests use ParseSetCommand + tree.SetPath (buildTreeFromSet, shared with
// ipsec_proposal_ref_test.go) per CLAUDE.md — NewParser must not be used for
// multi-line set input. Faithful HA configs define BOTH `groups node0` and
// `groups node1` (as `apply-groups "${node}"` requires the per-node group to
// exist on each node), with the alias living in exactly one peer group so that
// node's own view is clean while the OTHER node's diverges.

// canonParityBase gives the two firewall filters the aliasing units reference.
func canonParityBase() []string {
	return []string{
		"set firewall family inet filter good term t1 then accept",
		"set firewall family inet filter evil term t1 then accept",
	}
}

// peerOnlyAliasConfig builds a shared HA candidate where the base carries the
// canonical `unit <base>`, `groups node0` re-states the canonical unit (clean),
// and `groups node1` injects the aliasing spelling `unit <alias>`. With
// apply-groups "${node}", node0's effective view is a single canonical unit
// (clean) while node1 folds two spellings of the same logical unit. A
// node-LOCAL gate therefore ACCEPTS on node0 and REJECTS on node1 (the #5878
// divergent commit); the both-node union rejects on BOTH.
func peerOnlyAliasConfig(base, alias string) []string {
	return append(canonParityBase(),
		"set interfaces ge-0/0/0 unit "+base+" family inet filter input good",
		"set groups node0 interfaces ge-0/0/0 unit "+base+" family inet address 10.0.0.1/24",
		"set groups node1 interfaces ge-0/0/0 unit "+alias+" family inet filter input evil",
		`set apply-groups "${node}"`,
	)
}

// -----------------------------------------------------------------------------
// 6.1 Core RED (pre-fix) case — peer-only alias.
// -----------------------------------------------------------------------------

// A base `unit 1` plus a peer-only `groups node1 { … unit 01 }` collide ONLY in
// node1's effective view. Both a node0 commit AND a node1 commit must REJECT
// with the SAME error (verdict parity), and a generic CompileConfig too.
//
// FAIL-ON-REVERT: reverting the pre-expansion relocation (putting the gate back
// node-local inside runPreWalkGates) makes CompileConfigForNode(tree, 0) ACCEPT
// the divergent config — node0's own effective view is the clean canonical
// `unit 1` — so the node0 assertion below goes RED.
func TestUnitAliasPeerOnlyGroupRejectedBothNodes_5878(t *testing.T) {
	tree := buildTreeFromSet(t, peerOnlyAliasConfig("1", "01"))

	_, err0 := CompileConfigForNode(tree, 0)
	_, err1 := CompileConfigForNode(tree, 1)
	_, errG := CompileConfig(tree)

	if err0 == nil {
		t.Fatal("node0 commit ACCEPTED a peer-only unit-alias collision (unit 01 in groups node1) — the #5878 divergent-commit fail-open")
	}
	if err1 == nil {
		t.Fatal("node1 commit accepted a unit-alias collision visible in its own effective view")
	}
	if errG == nil {
		t.Fatal("generic CompileConfig accepted a peer-only unit-alias collision")
	}

	// Verdict parity: identical rejection on both nodes (the union is a pure
	// function of the candidate config).
	if err0.Error() != err1.Error() {
		t.Fatalf("node0/node1 verdicts diverge:\n node0: %v\n node1: %v", err0, err1)
	}

	for _, want := range []string{"ge-0/0/0", "#5631", "#5878", "`unit 01`", "`unit 1`", "same logical unit 1"} {
		if !strings.Contains(err0.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err0)
		}
	}
}

// -----------------------------------------------------------------------------
// 6.2 Alias-form matrix — each aliasing spelling injected via a peer-only
// groups node1 block, asserted rejected identically on node0 and node1.
// -----------------------------------------------------------------------------

func TestUnitAliasFormMatrixPeerOnly_5878(t *testing.T) {
	cases := []struct {
		name  string
		base  string // canonical spelling on the base interface + groups node0
		alias string // aliasing spelling injected via groups node1
		canon int
	}{
		{"leading-zero", "1", "01", 1},
		{"double-leading-zero", "1", "001", 1},
		{"signed", "1", "+1", 1},
		{"zero-double", "0", "00", 0},
		{"zero-signed-neg", "0", "-0", 0},
		{"zero-signed-pos", "0", "+0", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, peerOnlyAliasConfig(tc.base, tc.alias))

			_, err0 := CompileConfigForNode(tree, 0)
			_, err1 := CompileConfigForNode(tree, 1)
			if err0 == nil {
				t.Fatalf("node0 accepted peer-only alias %q vs %q (canon %d)", tc.alias, tc.base, tc.canon)
			}
			if err1 == nil {
				t.Fatalf("node1 accepted alias %q vs %q (canon %d)", tc.alias, tc.base, tc.canon)
			}
			if err0.Error() != err1.Error() {
				t.Fatalf("verdict not symmetric for %q:\n node0: %v\n node1: %v", tc.name, err0, err1)
			}
			if !strings.Contains(err0.Error(), "#5878") {
				t.Fatalf("error missing #5878 provenance: %v", err0)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 6.3 Injection-vector matrix.
// -----------------------------------------------------------------------------

// Node inversion: aliasing spelling in `groups node0` while `groups node1` is
// clean. node0's effective view folds `01` onto `1`; node1 never applies
// node0's group — but the both-node UNION rejects on both nodes so config-sync
// cannot split (originator accepts / peer rejects).
func TestUnitAliasNodeInversionGroupNode0_5878(t *testing.T) {
	tree := buildTreeFromSet(t, append(canonParityBase(),
		"set interfaces ge-0/0/0 unit 1 family inet filter input good",
		"set groups node0 interfaces ge-0/0/0 unit 01 family inet filter input evil",
		"set groups node1 interfaces ge-0/0/0 unit 1 family inet address 10.0.0.1/24",
		`set apply-groups "${node}"`,
	))
	_, err0 := CompileConfigForNode(tree, 0)
	_, err1 := CompileConfigForNode(tree, 1)
	if err0 == nil {
		t.Fatal("node0 accepted a groups node0 unit-alias collision it directly applies")
	}
	if err1 == nil {
		t.Fatal("node1 accepted a groups node0 unit-alias collision (both-node union must reject on the peer too)")
	}
	if err0.Error() != err1.Error() {
		t.Fatalf("node-inversion verdict not symmetric:\n node0: %v\n node1: %v", err0, err1)
	}
}

// Plain (non-node) apply-groups inheritance: a shared group carries the
// aliasing spelling. Both node views apply it, so both reject. No `${node}`, so
// no per-node group is required.
func TestUnitAliasGroupInheritance_5878(t *testing.T) {
	tree := buildTreeFromSet(t, append(canonParityBase(),
		"set interfaces ge-0/0/0 unit 1 family inet filter input good",
		"set groups aliasg interfaces ge-0/0/0 unit 01 family inet filter input evil",
		"set interfaces ge-0/0/0 apply-groups aliasg",
	))
	_, err0 := CompileConfigForNode(tree, 0)
	_, err1 := CompileConfigForNode(tree, 1)
	if err0 == nil || err1 == nil {
		t.Fatalf("apply-groups-inherited unit alias not rejected: node0=%v node1=%v", err0, err1)
	}
	if err0.Error() != err1.Error() {
		t.Fatalf("group-inheritance verdict not symmetric:\n node0: %v\n node1: %v", err0, err1)
	}
}

// Interface-range / wildcard expansion: a peer-only group applies the aliasing
// spelling onto an interface named by an interface-range member. The alias only
// lands on the concrete interface AFTER expandInterfaceRanges runs on the
// node-expanded view (Views 2/3), which the union gate performs. groups node0
// exists (harmless, unrelated interface) so node0's `${node}` expansion resolves.
func TestUnitAliasInterfaceRangeExpansion_5878(t *testing.T) {
	tree := buildTreeFromSet(t, append(canonParityBase(),
		"set interfaces interface-range r1 member ge-0/0/5",
		"set interfaces interface-range r1 unit 1 family inet filter input good",
		"set groups node0 interfaces ge-0/0/9 description clean",
		"set groups node1 interfaces ge-0/0/5 unit 01 family inet filter input evil",
		`set apply-groups "${node}"`,
	))
	_, err0 := CompileConfigForNode(tree, 0)
	_, err1 := CompileConfigForNode(tree, 1)
	if err0 == nil {
		t.Fatal("node0 accepted an interface-range member unit-alias collision hidden in groups node1")
	}
	if err1 == nil {
		t.Fatal("node1 accepted an interface-range member unit-alias collision")
	}
	if err0.Error() != err1.Error() {
		t.Fatalf("interface-range verdict not symmetric:\n node0: %v\n node1: %v", err0, err1)
	}
	if !strings.Contains(err0.Error(), "ge-0/0/5") {
		t.Fatalf("error does not name the expanded range member ge-0/0/5: %v", err0)
	}
}

// Rollback / load (lenient) path: the same peer-only collision must NOT
// hard-fail on the tolerant load / peer-sync path — an already-persisted or
// peer-synced config an older binary accepted still has to boot — but it
// surfaces the collision as a warning (#1960 no-brick doctrine).
func TestUnitAliasPeerOnlyLenientWarns_5878(t *testing.T) {
	tree := buildTreeFromSet(t, peerOnlyAliasConfig("1", "01"))
	// Node-aware lenient (HA peer-sync ingress) for node1 — the view that folds
	// the alias. Must warn, not error.
	cfg, err := CompileConfigForNodeLenient(tree, 1)
	if err != nil {
		t.Fatalf("CompileConfigForNodeLenient(node1) must downgrade the peer-only alias to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5878") && strings.Contains(w, "ge-0/0/0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #5878 unit-alias warning on the lenient node1 path, got: %v", cfg.Warnings)
	}
}

// -----------------------------------------------------------------------------
// 6.4 Compile-parity harness — verdict identity across node0 and node1 for the
// whole alias-form matrix, driven through one helper.
// -----------------------------------------------------------------------------

func TestUnitAliasCompileParityHarness_5878(t *testing.T) {
	cases := []struct {
		name       string
		cmds       []string
		wantReject bool
	}{
		{
			name:       "peer-only-node1-alias",
			cmds:       peerOnlyAliasConfig("1", "01"),
			wantReject: true,
		},
		{
			name: "peer-only-node0-alias",
			cmds: append(canonParityBase(),
				"set interfaces ge-0/0/0 unit 1 family inet filter input good",
				"set groups node0 interfaces ge-0/0/0 unit 001 family inet filter input evil",
				"set groups node1 interfaces ge-0/0/0 unit 1 family inet address 10.0.0.1/24",
				`set apply-groups "${node}"`,
			),
			wantReject: true,
		},
		{
			name: "clean-distinct-units",
			cmds: append(canonParityBase(),
				"set interfaces ge-0/0/0 unit 0 family inet filter input good",
				"set interfaces ge-0/0/0 unit 1 family inet filter input evil",
			),
			wantReject: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, tc.cmds)
			_, err0 := CompileConfigForNode(tree, 0)
			_, err1 := CompileConfigForNode(tree, 1)
			// (a) verdict identical across nodes.
			if (err0 == nil) != (err1 == nil) {
				t.Fatalf("verdict diverges across nodes: node0=%v node1=%v", err0, err1)
			}
			if tc.wantReject {
				if err0 == nil {
					t.Fatalf("expected rejection, both nodes accepted")
				}
				if err0.Error() != err1.Error() {
					t.Fatalf("reject text differs across nodes:\n node0: %v\n node1: %v", err0, err1)
				}
			} else if err0 != nil {
				t.Fatalf("expected acceptance, got node0=%v node1=%v", err0, err1)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// 6.6 Regression guards — the gate must NOT false-positive on the common case
// or a legitimate VLAN split.
// -----------------------------------------------------------------------------

// A single canonical `unit 0` (the overwhelming common case) is not an alias.
func TestUnitAliasSingleCanonicalUnitClean_5878(t *testing.T) {
	tree := buildTreeFromSet(t, append(canonParityBase(),
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet filter input good",
	))
	for _, nodeID := range []int{0, 1} {
		if _, err := CompileConfigForNode(tree, nodeID); err != nil {
			t.Fatalf("node%d rejected a single canonical unit 0: %v", nodeID, err)
		}
	}
}

// A legitimate VLAN split — distinct units 0 and 1 on one interface assigned to
// different zones — must not trip the gate on either node, including when a
// peer-only group adds a DISTINCT further unit (unit 2, not an alias).
func TestUnitAliasVLANSplitDistinctUnitsClean_5878(t *testing.T) {
	tree := buildTreeFromSet(t, append(canonParityBase(),
		"set interfaces ge-0/0/0 unit 0 vlan-id 10 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 1 vlan-id 20 family inet address 10.0.1.1/24",
		"set groups node0 interfaces ge-0/0/0 unit 2 vlan-id 30 family inet address 10.0.2.1/24",
		"set groups node1 interfaces ge-0/0/0 unit 3 vlan-id 40 family inet address 10.0.3.1/24",
		`set apply-groups "${node}"`,
	))
	for _, nodeID := range []int{0, 1} {
		cfg, err := CompileConfigForNode(tree, nodeID)
		if err != nil {
			t.Fatalf("node%d rejected a legitimate VLAN split (distinct units): %v", nodeID, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#5878") || strings.Contains(w, "same logical unit") {
				t.Fatalf("node%d emitted a spurious unit-alias warning on distinct units: %q", nodeID, w)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// CanonicalLogicalUnit unit tests — the shared normalizer (#5878).
// -----------------------------------------------------------------------------

func TestCanonicalLogicalUnit_5878(t *testing.T) {
	ok := []struct {
		raw   string
		num   int
		canon string
	}{
		{"0", 0, "0"},
		{"00", 0, "0"},
		{"-0", 0, "0"},
		{"+0", 0, "0"},
		{"1", 1, "1"},
		{"01", 1, "1"},
		{"001", 1, "1"},
		{"+1", 1, "1"},
		{"16385", 16385, "16385"},
	}
	for _, tc := range ok {
		num, canon, err := CanonicalLogicalUnit(tc.raw)
		if err != nil {
			t.Fatalf("CanonicalLogicalUnit(%q) unexpected error: %v", tc.raw, err)
		}
		if num != tc.num || canon != tc.canon {
			t.Fatalf("CanonicalLogicalUnit(%q) = (%d, %q); want (%d, %q)", tc.raw, num, canon, tc.num, tc.canon)
		}
		// All aliases of a value fold to one canonical string.
		if _, altCanon, _ := CanonicalLogicalUnit(tc.canon); altCanon != canon {
			t.Fatalf("canonical form not idempotent for %q: %q vs %q", tc.raw, canon, altCanon)
		}
	}

	// Malformed / out-of-range are rejected (parity with ValidateLogicalUnit).
	for _, bad := range []string{"", "tenant", "-1", "16386", "1.0", " 1", "0x1", "99999999999999999999"} {
		if _, _, err := CanonicalLogicalUnit(bad); err == nil {
			t.Fatalf("CanonicalLogicalUnit(%q) accepted a malformed/out-of-range unit", bad)
		}
		// ValidateLogicalUnit delegates to CanonicalLogicalUnit — same verdict.
		if err := ValidateLogicalUnit(bad); err == nil {
			t.Fatalf("ValidateLogicalUnit(%q) accepted a malformed/out-of-range unit", bad)
		}
	}
}
