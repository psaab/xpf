package config

import (
	"strings"
	"testing"
)

// #16523: AnnotatePath resolved its target through navigatePathWidth, the
// pair-consuming display walker. That walker cannot address a node with
// three or more keys and an odd count — e.g. the 3-key address-book leaf
// [address a1 10.0.0.1/32] — because after consuming the (address, a1) pair
// it descends into the leaf's nil children looking for 10.0.0.1/32 and
// returns nil. FormatSet emits the full identity in its annotate line, so
// replaying the box's own `display set` output (load set / load merge)
// aborted with ErrPathNotFound. These cells pin the fix: annotate targets
// resolve by full identity first, falling back to the display walk only
// for prefix addressing. Both probe shapes (flat and hierarchical) must
// round-trip, #4587 multi-key and #15718 annotation tests stay green, and
// prefix/short-form annotate must keep landing on the same node as before.

func build16523Flat(t *testing.T) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security address-book global address a1 10.0.0.1/32",
		"set security address-book global address a2 10.0.0.2/32",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func build16523Hier(t *testing.T) *ConfigTree {
	t.Helper()
	tree, errs := NewParser("security {\n    address-book {\n        global {\n            address a1 10.0.0.1/32;\n            address a2 10.0.0.2/32;\n        }\n    }\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse hierarchical: %v", errs)
	}
	return tree
}

// find16523Address walks security -> address-book -> global and returns the
// child whose Keys equal want, or nil.
func find16523Address(tree *ConfigTree, want []string) *Node {
	cur := tree.Children
	for _, step := range []string{"security", "address-book", "global"} {
		var next *Node
		for _, n := range cur {
			if len(n.Keys) == 1 && n.Keys[0] == step {
				next = n
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next.Children
	}
	for _, n := range cur {
		if keysEqual(n.Keys, want) {
			return n
		}
	}
	return nil
}

var full16523 = []string{"security", "address-book", "global", "address", "a1", "10.0.0.1/32"}

// Probe cell 1 (flat-built tree): AnnotatePath on the full 3-key identity
// resolves and lands on exactly the a1 leaf — not its a2 sibling.
// RED on revert: navigatePath returns nil -> ErrPathNotFound.
func TestAnnotateOddArityLeaf16523(t *testing.T) {
	for name, build := range map[string]func(*testing.T) *ConfigTree{
		"flat":         build16523Flat,
		"hierarchical": build16523Hier,
	} {
		t.Run(name, func(t *testing.T) {
			tree := build(t)
			if err := tree.AnnotatePath(full16523, "note-a1"); err != nil {
				t.Fatalf("AnnotatePath(full 3-key identity): %v", err)
			}
			a1 := find16523Address(tree, []string{"address", "a1", "10.0.0.1/32"})
			if a1 == nil {
				t.Fatal("a1 leaf not found in tree")
			}
			if a1.Annotation != "note-a1" {
				t.Errorf("a1.Annotation = %q, want %q", a1.Annotation, "note-a1")
			}
			a2 := find16523Address(tree, []string{"address", "a2", "10.0.0.2/32"})
			if a2 == nil {
				t.Fatal("a2 leaf not found in tree")
			}
			if a2.Annotation != "" {
				t.Errorf("a2 annotated by mistake: %q", a2.Annotation)
			}
		})
	}
}

// Probe cell 2 (round-trip): a tree carrying the annotation exports via
// FormatSet, and the emitted annotate line replays (set lines then the
// annotate line, through ParseAnnotateCommand + AnnotatePath — the
// applyEditLine sequence) onto a fresh tree, landing on exactly a1.
// RED on revert: the replayed AnnotatePath returns ErrPathNotFound,
// which is what aborted `load set` / `load merge` in production.
func TestAnnotateOddArityRoundTrip16523(t *testing.T) {
	src := build16523Flat(t)
	if err := src.AnnotatePath(full16523, "note-a1"); err != nil {
		t.Fatalf("AnnotatePath: %v", err)
	}
	out := src.FormatSet()
	wantAnn := `annotate security address-book global address a1 10.0.0.1/32 "note-a1"`
	if !strings.Contains(out, wantAnn) {
		t.Fatalf("FormatSet missing annotate line %q:\n%s", wantAnn, out)
	}

	dst := &ConfigTree{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "annotate ") {
			path, comment, ok := ParseAnnotateCommand(line)
			if !ok {
				t.Fatalf("ParseAnnotateCommand(%q) failed", line)
			}
			if err := dst.AnnotatePath(path, comment); err != nil {
				t.Fatalf("replay AnnotatePath(%q): %v", line, err)
			}
			continue
		}
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := dst.SetPath(path); err != nil {
			t.Fatalf("replay SetPath(%q): %v", line, err)
		}
	}
	a1 := find16523Address(dst, []string{"address", "a1", "10.0.0.1/32"})
	if a1 == nil || a1.Annotation != "note-a1" {
		t.Fatalf("round-trip annotation lost: %+v", a1)
	}
	a2 := find16523Address(dst, []string{"address", "a2", "10.0.0.2/32"})
	if a2 == nil || a2.Annotation != "" {
		t.Fatalf("round-trip annotated wrong node: %+v", a2)
	}
	// Re-export is stable: the same annotate line comes out again.
	if again := dst.FormatSet(); !strings.Contains(again, wantAnn) {
		t.Errorf("re-export missing annotate line:\n%s", again)
	}
}

// Prefix addressing is preserved: naming the address by name only
// (`... address a1`) and by bare keyword (`... address`) still resolves
// through the display fallback, landing on the FIRST matching node —
// exactly where navigatePath put it before this fix. Guards against an
// exact-only walk breaking short-form annotate.
func TestAnnotateOddArityPrefixFallback16523(t *testing.T) {
	tree := build16523Flat(t)
	byName := []string{"security", "address-book", "global", "address", "a1"}
	if err := tree.AnnotatePath(byName, "by-name"); err != nil {
		t.Fatalf("AnnotatePath(name-only prefix): %v", err)
	}
	if a1 := find16523Address(tree, []string{"address", "a1", "10.0.0.1/32"}); a1 == nil || a1.Annotation != "by-name" {
		t.Fatalf("name-only annotate landed wrong: %+v", a1)
	}

	tree2 := build16523Flat(t)
	byKeyword := []string{"security", "address-book", "global", "address"}
	if err := tree2.AnnotatePath(byKeyword, "by-keyword"); err != nil {
		t.Fatalf("AnnotatePath(bare keyword): %v", err)
	}
	if a1 := find16523Address(tree2, []string{"address", "a1", "10.0.0.1/32"}); a1 == nil || a1.Annotation != "by-keyword" {
		t.Fatalf("bare-keyword annotate must land on first sibling: %+v", a1)
	}
	if a2 := find16523Address(tree2, []string{"address", "a2", "10.0.0.2/32"}); a2 == nil || a2.Annotation != "" {
		t.Fatalf("bare-keyword annotate fanned out: %+v", a2)
	}
}

// A path whose last token matches no key still fails closed with
// ErrPathNotFound and mutates nothing — the exact walk must not invent a
// node for a wrong prefix (10.0.0.99/32) or a wrong name (a9).
func TestAnnotateOddArityNotFound16523(t *testing.T) {
	tree := build16523Flat(t)
	clone := tree.Clone()
	for _, bad := range [][]string{
		{"security", "address-book", "global", "address", "a1", "10.0.0.99/32"},
		{"security", "address-book", "global", "address", "a9", "10.0.0.1/32"},
		{"security", "address-book", "global", "address", "a1", "10.0.0.1/32", "extra"},
	} {
		if err := tree.AnnotatePath(bad, "nope"); err == nil {
			t.Errorf("AnnotatePath(%v) = nil, want ErrPathNotFound", bad)
		}
	}
	if got, want := tree.Format(), clone.Format(); got != want {
		t.Errorf("failed annotate mutated the tree:\n got %s\nwant %s", got, want)
	}
}
