package config

import (
	"strings"
	"testing"
)

// Tests for #5694 (codex-182 M15): before the fix, a malformed chassis-cluster
// redundancy-group / per-RG node IDENTITY parsed to a DEFAULT of 0 in
// compileChassis (`rgID := 0; if n, err := Atoi(name); err == nil { rgID = n }`,
// same for the RG-scoped `node <id>`), so a non-numeric identity silently
// aliased a valid id 0 and mis-assigned cluster ownership / priority instead of
// being rejected. The sibling validateChassisClusterStrict only sees the
// COMPILED int (already collapsed to 0, which passes its 0..255 range check).
// The validateChassisClusterIdentitiesAST gate runs on the RAW AST and
// REJECTS a malformed identity at strict commit / WARNS on tolerant load;
// #10002 additionally pins that tolerant compilation drops the malformed RG
// instance / node statement rather than retaining the old zero coercion.
//
// The TOP-LEVEL `chassis cluster node <id>` is a typed value leaf
// (ValidateInteger(0,1)) already rejected by SchemaValidate, so it is out of
// scope for this gate (covered by TestChassisIdentity5694_TopLevelNodeSchema).
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath (flatTreeFromSets),
// never NewParser (CLAUDE.md "Testing flat set syntax").
//
// FAIL-ON-REVERT: drop the validateChassisClusterIdentitiesAST call from
// runPreWalkGates (or make validID always return true) and the malformed
// configs compile clean — the reject assertions below go RED.

// TestChassisIdentity5694_MalformedRejectedAtCommit proves a malformed RG id or
// per-RG node id is hard-rejected at strict commit, naming the bad token.
func TestChassisIdentity5694_MalformedRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the commit error (the bad token)
	}{
		{
			name: "non-numeric redundancy-group id",
			cmds: []string{"set chassis cluster redundancy-group reth0 node 0 priority 100"},
			want: `"reth0"`,
		},
		{
			name: "alpha redundancy-group id",
			cmds: []string{"set chassis cluster redundancy-group primary node 0 priority 100"},
			want: `"primary"`,
		},
		{
			name: "non-numeric per-RG node id",
			cmds: []string{"set chassis cluster redundancy-group 1 node one priority 100"},
			want: `"one"`,
		},
		{
			// A negative per-RG node id is caught ONLY by this gate (there is no
			// node-id range check elsewhere; the strict RG-id gate would catch a
			// negative RG id, so a node id is the clean pure-new-coverage case).
			name: "negative per-RG node id",
			cmds: []string{"set chassis cluster redundancy-group 1 node -1 priority 100"},
			want: `"-1"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.cmds...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a malformed chassis identity (coerced to 0); want reject")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should name the bad identity token %s: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "chassis cluster") {
				t.Fatalf("error should scope to chassis cluster: %v", err)
			}
		})
	}
}

// TestChassisIdentity5694_ValidCommits guards against a false-reject: a valid
// redundancy-group 0 (the id the bug aliased) AND a positive id, with valid
// node ids, must all commit clean.
func TestChassisIdentity5694_ValidCommits(t *testing.T) {
	cases := [][]string{
		// RG 0 is a legitimate id — must NOT be rejected just because 0 is also
		// the malformed-token default.
		{"set chassis cluster authentication-key test-cluster-psk-6611",
			"set chassis cluster redundancy-group 0 node 0 priority 100",
			"set chassis cluster redundancy-group 0 node 1 priority 1"},
		// Positive RG id + both node ids.
		{"set chassis cluster authentication-key test-cluster-psk-6611",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 1 priority 100"},
		// An RG with no per-RG node stanza at all.
		{"set chassis cluster authentication-key test-cluster-psk-6611",
			"set chassis cluster redundancy-group 2"},
	}
	for _, cmds := range cases {
		tree := flatTreeFromSets(t, cmds...)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected a valid chassis identity: %v (cmds=%v)", err, cmds)
		}
	}
}

// TestChassisIdentity5694_MalformedLenientWarns proves the tolerant load /
// peer-sync path WARNS (does not error) on a malformed identity, so an
// already-persisted or peer-synced config an older binary silently accepted
// still boots (#1960).
func TestChassisIdentity5694_MalformedLenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, "set chassis cluster redundancy-group reth0 node 0 priority 100")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a malformed identity (want warn): %v", err)
	}
	assertWarns(t, cfg.Warnings, `"reth0"`, "redundancy-group instance is dropped")
}

// TestChassisIdentity5694_PackedOneLinerCovered proves the AST gate catches the
// hierarchical packed one-liner `node <id> priority <v>;` shape that the schema
// walker bypasses (the known residual noted in docs/config-schema.md) — a
// malformed node id there is reported and ignored on tolerant compilation,
// rather than retaining the old Atoi-to-zero alias.
func TestChassisIdentity5694_PackedOneLinerCovered(t *testing.T) {
	tree := hierTree(t, `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        redundancy-group 1 {
            node foo priority 100;
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("packed one-liner malformed node id must be rejected by the AST gate")
	}
	if !strings.Contains(err.Error(), "foo") {
		t.Fatalf("error should name the bad node token: %v", err)
	}
}

// TestChassisIdentity5694_TopLevelNodeSchema documents that the top-level
// `chassis cluster node <id>` is already rejected by the schema value-leaf gate
// (ValidateInteger(0,1)), so the AST identity gate deliberately does not
// re-check it.
func TestChassisIdentity5694_TopLevelNodeSchema(t *testing.T) {
	tree := flatTreeFromSets(t, "set chassis cluster node foo")
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("top-level chassis cluster node foo must be rejected by SchemaValidate")
	}
}
