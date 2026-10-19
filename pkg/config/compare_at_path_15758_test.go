package config

import (
	"strings"
	"testing"
)

// #15758: FormatCompareAtPath discarded the matched node itself — it
// compared only the matched nodes' children for non-leaves and dropped
// leaf matches entirely. A leaf value change, a container Inactive
// toggle, and an empty-container add/delete at the scoped path
// therefore produced identical empty child lists on both sides and
// rendered "[no changes]". Diffing the matched node slice (as
// FormatPathSet / FormatPathJSON do via navigatePathWidth, at the
// parent prefix) is the fix; these cases fail pre-fix.
//
// The bare-keyword multi-match case is the acceptance check from the
// narrowing note: several same-leading-keyword siblings returned by the
// terminal navigation must each be diffed at the parent, not flattened
// into one shared child list where one side's sibling could mask the
// other's change.
func TestFormatCompareAtPathLeafAndContainerInactive(t *testing.T) {
	oldTree := &ConfigTree{}
	if err := oldTree.SetPath([]string{"system", "host-name", "old-fw"}); err != nil {
		t.Fatal(err)
	}
	if err := oldTree.SetPath([]string{"security", "zones", "security-zone", "trust", "tcp-rst"}); err != nil {
		t.Fatal(err)
	}
	newTree := oldTree.Clone()
	if err := newTree.SetPath([]string{"system", "host-name", "new-fw"}); err != nil {
		t.Fatal(err)
	}
	if err := newTree.DeactivatePath([]string{"security", "zones", "security-zone", "trust"}); err != nil {
		t.Fatal(err)
	}

	if got := FormatCompareAtPath(oldTree, newTree, []string{"system", "host-name"}); !strings.Contains(got, "new-fw") {
		t.Fatalf("expected leaf compare at [system host-name] to show new-fw diff, got %q", got)
	}
	if got := FormatCompareAtPath(oldTree, newTree, []string{"security", "zones", "security-zone", "trust"}); !strings.Contains(got, "inactive:") && !strings.Contains(got, "-") && !strings.Contains(got, "+") {
		// diffNodes renders an Inactive toggle as a -/+ pair naming the
		// stanza (inactivePrefix appears on the + arm); any of these
		// markers proves the toggle is visible. A bare "[no changes]"
		// (empty diff) contains none.
		t.Fatalf("expected container Inactive compare at [security zones security-zone trust] to show the toggle, got %q", got)
	}
}

func TestFormatCompareAtPathEmptyContainerAndMultiMatch15758(t *testing.T) {
	empty := &ConfigTree{}
	filled := &ConfigTree{}
	// Empty container as produced by SetPath followed by dropping the
	// children (same construction as #9126): a non-leaf with no children.
	p, err := ParseSetCommand("set protocols ospf area 0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := filled.SetPath(p); err != nil {
		t.Fatal(err)
	}
	var target *Node
	var walk func([]*Node)
	walk = func(ns []*Node) {
		for _, n := range ns {
			if len(n.Keys) > 0 && n.Keys[0] == "area" {
				target = n
				return
			}
			walk(n.Children)
		}
	}
	walk(filled.Children)
	if target == nil {
		t.Fatal("fixture: no `area` node")
	}
	target.Children = nil
	target.IsLeaf = false

	scope := []string{"protocols", "ospf", "area"}
	if got := FormatCompareAtPath(empty, filled, scope); !strings.Contains(got, "+") || !strings.Contains(got, "area 0.0.0.0") {
		t.Fatalf("expected empty-container add at %v to render + area 0.0.0.0, got %q", scope, got)
	}
	if got := FormatCompareAtPath(filled, empty, scope); !strings.Contains(got, "-") || !strings.Contains(got, "area 0.0.0.0") {
		t.Fatalf("expected empty-container delete at %v to render - area 0.0.0.0, got %q", scope, got)
	}

	// Bare-keyword multi-match: the terminal token `server` matches two
	// distinct leaves; only the second value changes.
	oldTree := &ConfigTree{}
	if err := oldTree.SetPath([]string{"system", "ntp", "server", "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := oldTree.SetPath([]string{"system", "ntp", "server", "2.2.2.2"}); err != nil {
		t.Fatal(err)
	}
	newTree := oldTree.Clone()
	if err := newTree.SetPath([]string{"system", "ntp", "server", "3.3.3.3"}); err != nil {
		t.Fatal(err)
	}
	// Clone+SetPath appended a third server; build the changed tree
	// explicitly to get a same-count value change instead.
	newTree = &ConfigTree{}
	if err := newTree.SetPath([]string{"system", "ntp", "server", "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := newTree.SetPath([]string{"system", "ntp", "server", "3.3.3.3"}); err != nil {
		t.Fatal(err)
	}
	got := FormatCompareAtPath(oldTree, newTree, []string{"system", "ntp", "server"})
	if !strings.Contains(got, "3.3.3.3") || !strings.Contains(got, "2.2.2.2") {
		t.Fatalf("expected multi-match leaf compare to show 2.2.2.2 -> 3.3.3.3, got %q", got)
	}
	if strings.Contains(got, "-    server 1.1.1.1") || strings.Contains(got, "+    server 1.1.1.1") {
		t.Fatalf("unchanged multi-match sibling must not render as changed, got %q", got)
	}

	// Controls: identical trees at a leaf scope stay empty, and a path
	// present on neither side stays empty.
	if got := FormatCompareAtPath(oldTree, oldTree, []string{"system", "ntp", "server"}); got != "" {
		t.Fatalf("identical trees at leaf scope rendered a diff: %q", got)
	}
	if got := FormatCompareAtPath(oldTree, newTree, []string{"system", "missing"}); got != "" {
		t.Fatalf("absent path rendered a diff: %q", got)
	}
	// Child edits within a scoped container still render (pre-fix working leg).
	childOld := &ConfigTree{}
	if err := childOld.SetPath([]string{"system", "ntp", "server", "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	childNew := &ConfigTree{}
	if err := childNew.SetPath([]string{"system", "ntp", "server", "9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	if got := FormatCompareAtPath(childOld, childNew, []string{"system"}); !strings.Contains(got, "9.9.9.9") {
		t.Fatalf("child edit under scoped container must still render, got %q", got)
	}
}
