package config

import (
	"strings"
	"testing"
)

// TestEditingRejectsMaskLength9899 pins F101: a non-nil provenance mask whose
// length disagrees with the path must be rejected BEFORE mutation at all five
// sites (SetPathQuotedGrouped quoted + grouped, Delete/Deactivate/Activate
// grouped). Nil remains honest unknown and stays allowed.
//
// The base code nils a mismatched mask and proceeds, so a caller that passes
// a short/long/empty-non-nil mask gets silent success with the wrong
// provenance (Set) or a mutation the caller did not authorize under the mask
// it passed (Delete/Deactivate/Activate). The fix returns an error before
// touching the tree.
//
// FAIL-ON-REVERT (RED against unchanged source): every "rejects" leg expects
// a non-nil error plus a byte-identical tree, but the base code returns nil
// and mutates, so each leg goes RED twice (missing error + changed tree).
// The "nil allowed" legs pass both before and after.
//
// Meaningful-mutation guard: each API first proves the same path WOULD mutate
// under a nil mask on a fresh tree, so a "rejects" leg cannot pass vacuously
// (e.g. deleting a path that does not exist errors either way). Clone
// equality is full-state (Keys + KeysQuoted + KeysBracketed + IsLeaf +
// Inactive + children in order), not FormatSet/KeyPath, so a partial mutation
// that preserves display text still fails the unchanged check.
func TestEditingRejectsMaskLength9899(t *testing.T) {
	// badMasks9899 returns the three wrong-length non-nil shapes for a path of
	// length n: short, long, and empty-non-nil.
	badMasks9899 := func(n int) map[string][]bool {
		empty := []bool{}
		if empty == nil {
			t.Fatal("fixture bug: empty mask must be non-nil to exercise the nil-vs-empty distinction")
		}
		return map[string][]bool{
			"short": make([]bool, n-1),
			"long":  make([]bool, n+1),
			"empty": empty,
		}
	}

	// setPath9899 is a fresh leaf under an existing container: absent from the
	// baseline so a nil-mask Set would create it (meaningful), present after
	// success so the mutation is observable.
	setPath9899 := []string{"system", "domain-name", "test-9899"}
	setBaseline9899 := func(t *testing.T) *ConfigTree {
		t.Helper()
		// Baseline carries quoted provenance, bracketed provenance, and an
		// inactive marker so the unchanged check proves full-state equality,
		// not just KeyPath equality.
		tree, errs := NewParser(`system {
    host-name "quoted-base";
    inactive: domain-search [ example.com ];
}`).Parse()
		if len(errs) != 0 {
			t.Fatalf("baseline parse: %v", errs)
		}
		return tree
	}

	t.Run("SetPathQuotedGrouped quoted wrong length errors before mutation", func(t *testing.T) {
		// Control first: nil masks would create the leaf.
		ctrl := setBaseline9899(t)
		if err := ctrl.SetPathQuotedGrouped(setPath9899, nil, nil); err != nil {
			t.Fatalf("nil-mask Set control must succeed: %v", err)
		}
		if ctrl.FindChild("system") == nil {
			t.Fatal("nil-mask Set control did not mutate (no system node)")
		}
		for name, bad := range badMasks9899(len(setPath9899)) {
			tree := setBaseline9899(t)
			before := tree.Clone()
			if err := tree.SetPathQuotedGrouped(setPath9899, bad, nil); err == nil {
				t.Errorf("quoted=%s (len %d vs path %d): expected mask-length error, got nil",
					name, len(bad), len(setPath9899))
			}
			if !treesEqual9899(tree, before) {
				t.Errorf("quoted=%s: tree mutated despite mask-length error (want atomic no-op)", name)
			}
		}
	})

	t.Run("SetPathQuotedGrouped grouped wrong length errors before mutation", func(t *testing.T) {
		ctrl := setBaseline9899(t)
		if err := ctrl.SetPathQuotedGrouped(setPath9899, nil, nil); err != nil {
			t.Fatalf("nil-mask Set control must succeed: %v", err)
		}
		for name, bad := range badMasks9899(len(setPath9899)) {
			tree := setBaseline9899(t)
			before := tree.Clone()
			if err := tree.SetPathQuotedGrouped(setPath9899, nil, bad); err == nil {
				t.Errorf("grouped=%s (len %d vs path %d): expected mask-length error, got nil",
					name, len(bad), len(setPath9899))
			}
			if !treesEqual9899(tree, before) {
				t.Errorf("grouped=%s: tree mutated despite mask-length error (want atomic no-op)", name)
			}
		}
	})

	t.Run("SetPathQuotedGrouped nil masks allowed", func(t *testing.T) {
		tree := setBaseline9899(t)
		before := tree.Clone()
		if err := tree.SetPathQuotedGrouped(setPath9899, nil, nil); err != nil {
			t.Fatalf("nil masks must stay allowed: %v", err)
		}
		if treesEqual9899(tree, before) {
			t.Fatal("nil-mask Set did not mutate; fixture proves nothing about the guard")
		}
	})

	// deletePath9899 exists in the baseline so a nil-mask Delete would remove
	// it (meaningful), and the baseline's quoted + inactive state proves the
	// unchanged check is full-state.
	deletePath9899 := []string{"system", "host-name", "quoted-base"}
	deleteBaseline9899 := func(t *testing.T) *ConfigTree {
		t.Helper()
		tree, errs := NewParser(`system {
    host-name "quoted-base";
    inactive: domain-name parked-9899;
}`).Parse()
		if len(errs) != 0 {
			t.Fatalf("baseline parse: %v", errs)
		}
		return tree
	}

	t.Run("DeletePathGrouped wrong length errors before mutation", func(t *testing.T) {
		ctrl := deleteBaseline9899(t)
		if err := ctrl.DeletePathGrouped(deletePath9899, nil); err != nil {
			t.Fatalf("nil-mask Delete control must succeed: %v", err)
		}
		if got := ctrl.FormatSet(); len(got) == 0 || strings.Contains(got, "quoted-base") {
			t.Fatalf("nil-mask Delete control did not remove the leaf:\n%s", got)
		}
		for name, bad := range badMasks9899(len(deletePath9899)) {
			tree := deleteBaseline9899(t)
			before := tree.Clone()
			if err := tree.DeletePathGrouped(deletePath9899, bad); err == nil {
				t.Errorf("grouped=%s (len %d vs path %d): expected mask-length error, got nil",
					name, len(bad), len(deletePath9899))
			}
			if !treesEqual9899(tree, before) {
				t.Errorf("grouped=%s: tree mutated despite mask-length error (want atomic no-op)", name)
			}
		}
	})

	// deactivatePath9899 is active in the baseline so a nil-mask Deactivate
	// would flip it inactive (meaningful).
	deactivatePath9899 := []string{"system", "host-name", "active-9899"}
	deactivateBaseline9899 := func(t *testing.T) *ConfigTree {
		t.Helper()
		tree, errs := NewParser("system {\n    host-name \"active-9899\";\n}").Parse()
		if len(errs) != 0 {
			t.Fatalf("baseline parse: %v", errs)
		}
		return tree
	}

	t.Run("DeactivatePathGrouped wrong length errors before mutation", func(t *testing.T) {
		ctrl := deactivateBaseline9899(t)
		if err := ctrl.DeactivatePathGrouped(deactivatePath9899, nil); err != nil {
			t.Fatalf("nil-mask Deactivate control must succeed: %v", err)
		}
		hn := ctrl.FindChild("system")
		if hn == nil {
			t.Fatal("nil-mask Deactivate control dropped the system node")
		}
		foundInactive := false
		var walk func(n *Node)
		walk = func(n *Node) {
			if n == nil {
				return
			}
			if n.Inactive {
				foundInactive = true
			}
			for _, c := range n.Children {
				walk(c)
			}
		}
		walk(hn)
		if !foundInactive {
			t.Fatal("nil-mask Deactivate control did not flip Inactive; fixture proves nothing")
		}
		for name, bad := range badMasks9899(len(deactivatePath9899)) {
			tree := deactivateBaseline9899(t)
			before := tree.Clone()
			if err := tree.DeactivatePathGrouped(deactivatePath9899, bad); err == nil {
				t.Errorf("grouped=%s (len %d vs path %d): expected mask-length error, got nil",
					name, len(bad), len(deactivatePath9899))
			}
			if !treesEqual9899(tree, before) {
				t.Errorf("grouped=%s: tree mutated despite mask-length error (want atomic no-op)", name)
			}
		}
	})

	// activatePath9899 is inactive in the baseline so a nil-mask Activate
	// would flip it active (meaningful).
	activatePath9899 := []string{"system", "host-name", "parked-9899"}
	activateBaseline9899 := func(t *testing.T) *ConfigTree {
		t.Helper()
		tree, errs := NewParser("system {\n    inactive: host-name \"parked-9899\";\n}").Parse()
		if len(errs) != 0 {
			t.Fatalf("baseline parse: %v", errs)
		}
		return tree
	}

	t.Run("ActivatePathGrouped wrong length errors before mutation", func(t *testing.T) {
		ctrl := activateBaseline9899(t)
		if err := ctrl.ActivatePathGrouped(activatePath9899, nil); err != nil {
			t.Fatalf("nil-mask Activate control must succeed: %v", err)
		}
		hn := ctrl.FindChild("system")
		if hn == nil {
			t.Fatal("nil-mask Activate control dropped the system node")
		}
		stillInactive := false
		var walk func(n *Node)
		walk = func(n *Node) {
			if n == nil {
				return
			}
			if n.Inactive {
				stillInactive = true
			}
			for _, c := range n.Children {
				walk(c)
			}
		}
		walk(hn)
		if stillInactive {
			t.Fatal("nil-mask Activate control did not clear Inactive; fixture proves nothing")
		}
		for name, bad := range badMasks9899(len(activatePath9899)) {
			tree := activateBaseline9899(t)
			before := tree.Clone()
			if err := tree.ActivatePathGrouped(activatePath9899, bad); err == nil {
				t.Errorf("grouped=%s (len %d vs path %d): expected mask-length error, got nil",
					name, len(bad), len(activatePath9899))
			}
			if !treesEqual9899(tree, before) {
				t.Errorf("grouped=%s: tree mutated despite mask-length error (want atomic no-op)", name)
			}
		}
	})
}

// treesEqual9899 reports full-state equality: Keys, KeysQuoted,
// KeysBracketed, IsLeaf, Inactive, and children in order, recursively. Unlike
// nodesEqual (KeyPath + IsLeaf + Inactive) it preserves the provenance masks,
// so a mutation that keeps display text but drops a quote/bracket bit still
// compares unequal.
func treesEqual9899(a, b *ConfigTree) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Children) != len(b.Children) {
		return false
	}
	for i := range a.Children {
		if !nodesEqual9899(a.Children[i], b.Children[i]) {
			return false
		}
	}
	return true
}

func nodesEqual9899(a, b *Node) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Keys) != len(b.Keys) {
		return false
	}
	for i := range a.Keys {
		if a.Keys[i] != b.Keys[i] {
			return false
		}
	}
	if len(a.KeysQuoted) != len(b.KeysQuoted) {
		return false
	}
	for i := range a.KeysQuoted {
		if a.KeysQuoted[i] != b.KeysQuoted[i] {
			return false
		}
	}
	if len(a.KeysBracketed) != len(b.KeysBracketed) {
		return false
	}
	for i := range a.KeysBracketed {
		if a.KeysBracketed[i] != b.KeysBracketed[i] {
			return false
		}
	}
	if a.IsLeaf != b.IsLeaf {
		return false
	}
	if a.Inactive != b.Inactive {
		return false
	}
	if len(a.Children) != len(b.Children) {
		return false
	}
	for i := range a.Children {
		if !nodesEqual9899(a.Children[i], b.Children[i]) {
			return false
		}
	}
	return true
}
