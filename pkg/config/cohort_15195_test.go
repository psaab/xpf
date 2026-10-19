package config

import (
	"strings"
	"testing"
)

// #15195 A01-05: parse budget must count keys inside one statement.
// A single key-dense statement (one node with hundreds of thousands of keys)
// costs ~4x the documented live-AST bound at the 16 MiB cap but was counted as
// 1 node, so it sailed past maxParseNodes with no ParseError.
//
// #15195 A01-06: rename/copy with a MISSING source must not descend through a
// partial (first-key-only) match into a different object. findNodeWithParent /
// childrenAtPath preferred the longest consumed match, but matchNodeKeys
// returns 1 on a first-key-only hit, so a path naming a non-existent sibling
// (e.g. policy ZZ where only policy A/B exist) resolved to policy A and the
// rename/copy mutated it, and Store.Rename recorded phantom lineage.

func hasBudgetError(errs []ParseError) bool {
	for _, e := range errs {
		if strings.Contains(e.Message, "parse budget") {
			return true
		}
	}
	return false
}

// --- A01-05 ---

// TestParseBudget_KeyDenseStatement_15195 is the RED-on-base core for A01-05:
// one statement carrying more keys than the whole node budget must report a
// budget ParseError and truncate, not build the full key slice silently.
func TestParseBudget_KeyDenseStatement_15195(t *testing.T) {
	// One leaf statement with maxParseNodes+5000 keys: a single AST node, but
	// its Keys/kinds/bracketed/quote slices are each that wide.
	text := "a " + strings.Repeat("k ", maxParseNodes+5000) + ";\n"
	_, errs := NewParser(text).Parse()
	if !hasBudgetError(errs) {
		t.Fatalf("key-dense single statement (%d keys in 1 node) produced no budget ParseError; "+
			"keys are not counted toward maxParseNodes (#15195 A01-05); errs=%v", maxParseNodes+5000, errs)
	}
}

// TestParseBudget_KeyDenseBlockHeader_15195: same probe on a block header.
func TestParseBudget_KeyDenseBlockHeader_15195(t *testing.T) {
	text := "a " + strings.Repeat("k ", maxParseNodes+100) + "{ b; }\n"
	_, errs := NewParser(text).Parse()
	if !hasBudgetError(errs) {
		t.Fatalf("key-dense block header produced no budget ParseError (#15195 A01-05); errs=%v", errs)
	}
}

// TestParseBudget_NormalKeysControl_15195: legitimate multi-key statements
// well below the budget parse clean (control: fix must not be over-broad).
func TestParseBudget_NormalKeysControl_15195(t *testing.T) {
	text := "security { policies { from-zone trust to-zone untrust { policy p1 { then { permit; } } } } }\n" +
		"interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }\n"
	tree, errs := NewParser(text).Parse()
	if hasBudgetError(errs) {
		t.Fatalf("normal config hit budget: %v", errs)
	}
	if len(errs) != 0 {
		t.Fatalf("normal config errors: %v", errs)
	}
	if tree == nil || len(tree.Children) == 0 {
		t.Fatal("normal config parsed to nothing")
	}
	// Many distinct moderate statements also stay clean.
	var b strings.Builder
	for i := 0; i < 2000; i++ {
		b.WriteString("a b c d e;\n")
	}
	_, errs = NewParser(b.String()).Parse()
	if hasBudgetError(errs) || len(errs) != 0 {
		t.Fatalf("2000 five-key statements hit budget/errors: %v", errs)
	}
}

// --- A01-06 ---

// build15195Tree builds the hierarchical fixture via NewParser (never SetPath:
// hierarchy preserves the multi-key node shapes the partial match abuses).
func build15195Tree(t *testing.T) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(`
firewall {
    filter F1 {
        term T1 {
            then { accept; }
        }
        term T2 {
            then { discard; }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet;
        }
    }
}
`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse fixture: %v", errs)
	}
	return tree
}

// TestRenameMissingSourceNoPartialMatch_15195: `rename firewall filter term T2`
// names NO node — the filter node is [filter F1], so the path is missing its
// name key. On base, matchNodeKeys returns a 1-key partial match for
// [filter F1], the walk descends into F1, finds term T2, and RenamePath renames
// T2 (a different object than the one named). After the fix it must return
// "source not found" and leave the tree byte-for-byte unchanged.
func TestRenameMissingSourceNoPartialMatch_15195(t *testing.T) {
	tree := build15195Tree(t)
	before := tree.Format()
	src := []string{"firewall", "filter", "term", "T2"}
	dst := []string{"firewall", "filter", "term", "RENAMED"}
	err := tree.RenamePath(src, dst)
	if err == nil {
		t.Fatalf("RenamePath with missing source %v returned nil; it partially matched filter F1 and renamed term T2 (#15195 A01-06)", src)
	}
	if !strings.Contains(err.Error(), "source not found") {
		t.Fatalf("RenamePath missing source error = %q, want containing 'source not found'", err)
	}
	if got := tree.Format(); got != before {
		t.Fatalf("failed rename mutated the tree:\nbefore:\n%s\nafter:\n%s", before, got)
	}
}

// TestCopyMissingSourceNoPartialMatch_15195: copy twin of the rename probe.
func TestCopyMissingSourceNoPartialMatch_15195(t *testing.T) {
	tree := build15195Tree(t)
	before := tree.Format()
	src := []string{"firewall", "filter", "term", "T1"}
	dst := []string{"firewall", "filter", "term", "COPIED"}
	err := tree.CopyPath(src, dst)
	if err == nil {
		t.Fatalf("CopyPath with missing source %v returned nil; it partially matched filter F1 (#15195 A01-06)", src)
	}
	if !strings.Contains(err.Error(), "source") {
		t.Fatalf("CopyPath missing source error = %q, want source error", err)
	}
	if got := tree.Format(); got != before {
		t.Fatalf("failed copy mutated the tree:\nbefore:\n%s\nafter:\n%s", before, got)
	}
}

// TestRenameTruncatedSourceNoPartialMatch_15195: `... ge-0/0/0 unit` ends one
// key short of the [unit 0] node. On base the terminal partial branch (node has
// more keys than remaining path) returns that node and the rename corrupts it.
// After the fix: source not found, tree unchanged.
func TestRenameTruncatedSourceNoPartialMatch_15195(t *testing.T) {
	tree := build15195Tree(t)
	before := tree.Format()
	err := tree.RenamePath(
		[]string{"interfaces", "ge-0/0/0", "unit"},
		[]string{"interfaces", "ge-0/0/0", "RENAMED"})
	if err == nil {
		t.Fatalf("RenamePath with truncated source returned nil (#15195 A01-06)")
	}
	if !strings.Contains(err.Error(), "source not found") {
		t.Fatalf("error = %q, want 'source not found'", err)
	}
	if got := tree.Format(); got != before {
		t.Fatalf("failed rename mutated the tree:\nbefore:\n%s\nafter:\n%s", before, got)
	}
}

// TestRenameLegitControl_15195: legitimate renames/copies through the same
// navigator stay green — full-identity multi-key sources resolve as before.
func TestRenameLegitControl_15195(t *testing.T) {
	tree := build15195Tree(t)
	if err := tree.RenamePath(
		[]string{"firewall", "filter", "F1", "term", "T2"},
		[]string{"firewall", "filter", "F1", "term", "T2x"}); err != nil {
		t.Fatalf("legit rename term T2->T2x failed: %v", err)
	}
	out := tree.Format()
	if !strings.Contains(out, "term T2x") {
		t.Fatalf("renamed term missing:\n%s", out)
	}
	if err := tree.CopyPath(
		[]string{"firewall", "filter", "F1", "term", "T1"},
		[]string{"firewall", "filter", "F1", "term", "T1copy"}); err != nil {
		t.Fatalf("legit copy term T1 failed: %v", err)
	}
	if !strings.Contains(tree.Format(), "term T1copy") {
		t.Fatalf("copied term missing:\n%s", tree.Format())
	}
	if err := tree.RenamePath(
		[]string{"interfaces", "ge-0/0/0", "unit", "0"},
		[]string{"interfaces", "ge-0/0/0", "unit", "1"}); err != nil {
		t.Fatalf("legit rename unit 0->1 failed: %v", err)
	}
	tree2 := build15195Tree(t)
	before := tree2.Format()
	if err := tree2.InsertBefore(
		[]string{"firewall", "filter", "term", "T1"},
		[]string{"firewall", "filter", "F1", "term", "T2"}); err == nil {
		t.Fatalf("InsertBefore with missing (partial-match) element returned nil (#15195 A01-06 sibling path)")
	}
	if got := tree2.Format(); got != before {
		t.Fatalf("failed InsertBefore mutated tree")
	}
	if err := tree2.InsertBefore(
		[]string{"firewall", "filter", "F1", "term", "T2"},
		[]string{"firewall", "filter", "F1", "term", "T1"}); err != nil {
		t.Fatalf("legit InsertBefore: %v", err)
	}
}

// TestCopyRenameWidePrefixParent_15195 is the #9881-shaped control the strict
// matcher must NOT break: a flat-set leaf wider than the spelled destination
// parent (`[as-path AP1 0-9 +]` addressed as `as-path AP2`) still copies and
// renames, because the destination parent legitimately resolves through the
// wide node's key prefix while the SOURCE is spelled in full.
func TestCopyRenameWidePrefixParent_15195(t *testing.T) {
	build := func() *ConfigTree {
		return buildFlat9881(t, `set policy-options as-path AP1 [0-9]+`)
	}
	src := []string{"policy-options", "as-path", "AP1", "0-9", "+"}
	dst := []string{"policy-options", "as-path", "AP2", "0-9", "+"}
	tree := build()
	if err := tree.CopyPath(src, dst); err != nil {
		t.Fatalf("copy via wide-prefix destination parent: %v (#15195 must not break #9881)", err)
	}
	tree = build()
	if err := tree.RenamePath(src, dst); err != nil {
		t.Fatalf("rename via wide-prefix destination parent: %v (#15195 must not break #9881)", err)
	}
}
