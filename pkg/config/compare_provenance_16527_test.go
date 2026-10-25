package config

import (
	"strings"
	"testing"
)

// #16527: nodesEqual and alignSiblings compared nodes by KeyPath() — the keys
// joined with spaces — and never looked at key count, KeysQuoted or
// KeysBracketed. A `change-configuration commands` entry that changes from
// two quoted members ("set" "system host-name pwned", which
// eventMultiWordLeafValues splits into two members and classifyPlan then
// rejects) to one bare command (`set system host-name pwned`, which it joins
// and applies) therefore rendered as [no changes] on both the plain and the
// redacted compare, while the compiled ThenCommands differ.
//
// Fixtures are hierarchical text so the parser stamps real quote provenance
// exactly as an operator-authored config would carry it.

const compare16527Quoted = `event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands [ "set" "system host-name pwned" ];
            }
        }
    }
}
`

const compare16527Bare = `event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands set system host-name pwned;
            }
        }
    }
}
`

func TestFormatCompareQuotedGrouping16527(t *testing.T) {
	oldTree := parseHierText(t, compare16527Quoted)
	newTree := parseHierText(t, compare16527Bare)

	// Non-vacuity: the two trees really do compile to different command
	// batches — the quoted form splits into two members, the bare form
	// joins into one applicable command.
	oldCmds := compileTreeStrictKit(t, oldTree).EventOptions[0].ThenCommands
	newCmds := compileTreeStrictKit(t, newTree).EventOptions[0].ThenCommands
	if len(oldCmds) != 2 || oldCmds[0] != "set" || oldCmds[1] != "system host-name pwned" {
		t.Fatalf("quoted fixture ThenCommands = %q, want [set, system host-name pwned] split members", oldCmds)
	}
	if len(newCmds) != 1 || newCmds[0] != "set system host-name pwned" {
		t.Fatalf("bare fixture ThenCommands = %q, want [set system host-name pwned] joined command", newCmds)
	}

	diff := FormatCompare(oldTree, newTree)
	if diff == "" {
		t.Fatalf("quoted->bare grouping change rendered as no changes; the compiled batch differs (%q -> %q)", oldCmds, newCmds)
	}
	// Both arms must render, and the old arm must show the authored quotes
	// so a reviewer sees the grouping that made the batch inert.
	if !strings.Contains(diff, "-") || !strings.Contains(diff, "+") {
		t.Fatalf("grouping diff must render -/+ arms:\n%s", diff)
	}
	if !strings.Contains(diff, `"set"`) || !strings.Contains(diff, `"system host-name pwned"`) {
		t.Fatalf("old arm must render quoted members via QuotedKeyPath:\n%s", diff)
	}
	if !strings.Contains(diff, "set system host-name pwned") {
		t.Fatalf("new arm must render the bare joined command:\n%s", diff)
	}

	// Reverse direction must also be visible.
	rev := FormatCompare(newTree, oldTree)
	if rev == "" || !strings.Contains(rev, `"set"`) {
		t.Fatalf("reverse grouping diff must name the quoted members:\n%s", rev)
	}

	// Redacted compare shares diffNodes, so it must not hide it either.
	if rd := FormatCompareRedacted(oldTree, newTree); rd == "" {
		t.Fatalf("redacted compare hid the grouping change")
	}
	// Scoped compares go through the same diffNodes.
	if sd := FormatCompareAtPath(oldTree, newTree, []string{"event-options"}); sd == "" {
		t.Fatalf("scoped compare hid the grouping change")
	}
	if srd := FormatCompareRedactedAtPath(oldTree, newTree, []string{"event-options"}); srd == "" {
		t.Fatalf("scoped redacted compare hid the grouping change")
	}
}

func TestFormatCompareQuotedGroupingIdentical16527(t *testing.T) {
	// Controls: identical provenance on both sides is no change, in either
	// authoring. All-bare trees carry nil provenance (reads as all-false),
	// so this also pins the zero-churn rule for provenance-less trees.
	for name, src := range map[string]string{"quoted": compare16527Quoted, "bare": compare16527Bare} {
		a := parseHierText(t, src)
		b := parseHierText(t, src)
		if diff := FormatCompare(a, b); diff != "" {
			t.Fatalf("%s: identical trees rendered a diff:\n%s", name, diff)
		}
		if diff := FormatCompareRedacted(a, b); diff != "" {
			t.Fatalf("%s: identical trees rendered a redacted diff:\n%s", name, diff)
		}
	}
}

// Key-count / bracket provenance: `"a b"` (one key) vs `a b` (two keys) join
// to the same KeyPath, and a bracketed group vs the same tokens bare do too.
// Both must compare unequal even though neither involves event-options.
func TestNodesEqualKeyProvenance16527(t *testing.T) {
	quotedOne := &Node{Keys: []string{"commands", "a b"}, IsLeaf: true}
	quotedOne.setKeysQuoted([]bool{false, true})
	bareTwo := &Node{Keys: []string{"commands", "a", "b"}, IsLeaf: true}
	if quotedOne.KeyPath() != bareTwo.KeyPath() {
		t.Fatalf("fixture KeyPaths differ (%q vs %q); test is vacuous", quotedOne.KeyPath(), bareTwo.KeyPath())
	}
	if nodesEqual(quotedOne, bareTwo) {
		t.Fatal("nodesEqual treated one quoted key as equal to two bare keys with the same joined text")
	}

	bracketed := &Node{Keys: []string{"members", "a", "b"}, IsLeaf: true}
	bracketed.setKeysBracketed([]bool{false, true, true}, true)
	bare := &Node{Keys: []string{"members", "a", "b"}, IsLeaf: true}
	if nodesEqual(bracketed, bare) {
		t.Fatal("nodesEqual treated a bracketed group as equal to the same tokens bare")
	}

	// Same keys, same provenance (incl. nil on both sides) stays equal.
	bare2 := &Node{Keys: []string{"members", "a", "b"}, IsLeaf: true}
	if !nodesEqual(bare, bare2) {
		t.Fatal("nodesEqual treated identical provenance-less nodes as unequal")
	}
	quotedTwo := &Node{Keys: []string{"commands", "a b"}, IsLeaf: true}
	quotedTwo.setKeysQuoted([]bool{false, true})
	if !nodesEqual(quotedOne, quotedTwo) {
		t.Fatal("nodesEqual treated identically-quoted nodes as unequal")
	}
}

// alignSiblings must not pair a quoted-grouping node with a bare node that
// merely shares its joined KeyPath: the pair is a removal plus an addition.
func TestAlignSiblingsKeyProvenance16527(t *testing.T) {
	quotedOne := &Node{Keys: []string{"commands", "a b"}, IsLeaf: true}
	quotedOne.setKeysQuoted([]bool{false, true})
	bareTwo := &Node{Keys: []string{"commands", "a", "b"}, IsLeaf: true}
	al := alignSiblings([]*Node{quotedOne}, []*Node{bareTwo})
	if len(al.pairs) != 0 || len(al.oldOnly) != 1 || len(al.newOnly) != 1 {
		t.Fatalf("alignSiblings paired differing-provenance siblings: pairs=%v oldOnly=%v newOnly=%v",
			al.pairs, al.oldOnly, al.newOnly)
	}
}
