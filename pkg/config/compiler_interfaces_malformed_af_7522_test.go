package config

import (
	"strings"
	"testing"
)

// #7522: compileInterfaces indexed afNode.Keys[0] with no bounds check, so a
// family node whose CHILD carries an empty Keys slice panicked with index out
// of range.
//
// afNodes is either the family node itself — guaranteed len(Keys) >= 2 by the
// branch that selects it — or familyNode.Children, and a child's Keys are only
// structurally non-empty when the tree came from the parser or SetPath. A
// malformed persisted AST does not: pkg/configstore/db.go unmarshals the stored
// JSON with a plain json.Unmarshal and no Node validator, so a corrupted or
// hand-edited store reaches the compiler directly.
//
// A bad persisted state must ERROR on load, never panic (#1960
// fail-closed-on-load). Same fix and reasoning as #4827 on the sibling firewall
// family walkers, which is why this uses Name() rather than a length check: the
// nil-safe accessor already exists and is what those walkers adopted.
//
// The tree is hand-built on purpose. Going through ParseSetCommand/SetPath
// would be a fixture that CANNOT produce the defect — those paths guarantee
// len(Keys) >= 1, so the test would pass against the unfixed code and prove
// nothing.

// malformedAFTree7522 builds interfaces { ge-0/0/0 { unit 0 { family { <empty> } } } }
// where the address-family node has NO keys at all.
func malformedAFTree7522() *ConfigTree {
	afNode := &Node{Keys: nil} // the malformed node: no keys
	familyNode := &Node{Keys: []string{"family"}, Children: []*Node{afNode}}
	unitNode := &Node{Keys: []string{"unit", "0"}, Children: []*Node{familyNode}}
	ifNode := &Node{Keys: []string{"ge-0/0/0"}, Children: []*Node{unitNode}}
	return &ConfigTree{Children: []*Node{
		{Keys: []string{"interfaces"}, Children: []*Node{ifNode}},
	}}
}

// TestMalformedAddressFamilyNodeDoesNotPanic7522 is the defect proper. Before
// the fix this panics; the assertion is that CompileConfig RETURNS.
func TestMalformedAddressFamilyNodeDoesNotPanic7522(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CompileConfig PANICKED on a malformed persisted AST: %v — a corrupted "+
				"config store must fail the load, never take the daemon down", r)
		}
	}()

	cfg, err := CompileConfig(malformedAFTree7522())
	t.Logf("CompileConfig returned cfg=%v err=%v", cfg != nil, err)

	// The unit must still exist: an unkeyed family child is garbage, and
	// discarding the whole interface because of it would be a different bug.
	if err == nil && cfg != nil {
		ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
		if ifc == nil {
			t.Error("the interface was dropped entirely because one address-family child was " +
				"malformed; the empty node should be ignored, not poison its parent")
		}
	}
}

// TestWellFormedAddressFamiliesStillCompile7522 is the TIGHTENING control.
//
// Name() returns "" for an empty Keys slice, and "" matches no address family —
// so the malformed node is ignored. A fix that ignored MORE than that (say, an
// early `continue` on the whole family node, or treating any afName as
// unrecognised) would satisfy the test above while silently dropping real
// addresses. This pins that both AST shapes still produce their families.
func TestWellFormedAddressFamiliesStillCompile7522(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
	}{
		{"flat set shape", []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
			"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		}},
		{"hierarchical shape", []string{
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, cmd := range tc.sets {
				path, err := ParseSetCommand(cmd)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", cmd, err)
				}
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			var found bool
			for name, ifc := range cfg.Interfaces.Interfaces {
				for _, u := range ifc.Units {
					if u == nil {
						continue
					}
					if len(u.Addresses) > 0 {
						found = true
					}
				}
				_ = name
			}
			if !found {
				t.Error("no address family compiled an address: the malformed-node guard has " +
					"widened into dropping well-formed families")
			}
		})
	}
}

// TestChildShapedFamilyStillCompiles7522 is the TIGHTENING control aimed at the
// branch this fix actually changed.
//
// The test above exercises `family inet` as ONE node with two keys — which is
// what ParseSetCommand/SetPath produce today (measured: Keys=[family inet]) — so
// afNodes is the family node itself and the Children branch is never taken. A
// control built from set commands therefore CANNOT see an over-rejecting change
// to the Children branch, and passed a mutation that skipped every node with
// fewer than two keys.
//
// This builds the other shape directly: Keys=["family"] with a well-formed
// child Keys=["inet"]. That is the shape the branch exists for, and the shape a
// persisted tree from an older writer can still hold. An empty-Keys child must
// be ignored; a well-formed one must still compile its address.
func TestChildShapedFamilyStillCompiles7522(t *testing.T) {
	good := &Node{Keys: []string{"inet"}, Children: []*Node{
		{Keys: []string{"address", "10.0.9.1/24"}, IsLeaf: true},
	}}
	bad := &Node{Keys: nil} // the #7522 malformed sibling, alongside a good one
	familyNode := &Node{Keys: []string{"family"}, Children: []*Node{bad, good}}
	unitNode := &Node{Keys: []string{"unit", "0"}, Children: []*Node{familyNode}}
	ifNode := &Node{Keys: []string{"ge-0/0/9"}, Children: []*Node{unitNode}}
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"interfaces"}, Children: []*Node{ifNode}},
	}}

	// #17196: the malformed sibling is now reported, not silently
	// ignored — strict rejects, lenient warns and still compiles the
	// well-formed sibling. This cell rides the lenient path so it can
	// pin that the good family next to the bad one is not dropped.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "is not a known address family") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("lenient compile must warn on the malformed sibling, warnings=%v", cfg.Warnings)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/9"]
	if ifc == nil {
		t.Fatal("interface ge-0/0/9 did not compile at all")
	}
	var got []string
	for _, u := range ifc.Units {
		if u != nil {
			got = append(got, u.Addresses...)
		}
	}
	if len(got) != 1 || got[0] != "10.0.9.1/24" {
		t.Errorf("child-shaped family compiled addresses %v, want [10.0.9.1/24] — the "+
			"malformed sibling must be ignored WITHOUT dropping the well-formed family "+
			"next to it", got)
	}
}
