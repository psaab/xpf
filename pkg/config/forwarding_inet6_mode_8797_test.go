package config

import "testing"

// #8797: `forwarding-options family inet6 mode` compiled to nothing in every
// spelling an operator can produce.
//
// It read as "declared but unread" -- the leaf completes, validates, commits
// clean and renders back, and the compiled value stayed empty. It is not
// unread. `compileForwardingOptions` descended FindChild("family") ->
// FindChild("inet6"), a two-level lookup, while `family` is declared
// compoundKey and BOTH the parser and SetPath produce ONE node with
// Keys=["family","inet6"]. The only shape the old lookup matched is
// `family { inet6 { … } }` -- the shape the #2419 census synthesizes and
// nothing else emits.
//
// Same defect as #8763's traversal bug (a two-level lookup against a one-node
// compound key), in a compiler rather than in the normalizer.
//
// THE FLAT `set` LEG IS THE ONE THAT MATTERS HERE. It is the spelling an
// operator types, it went through the broken path, and a hierarchical-only
// test would have reported this fixed while `set forwarding-options family
// inet6 mode packet-based` still compiled to "".
func TestInet6ForwardingModeReachesTheCompiledConfig8797(t *testing.T) {
	compileText := func(t *testing.T, text string) (string, error) {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := compileTree(tree, strictCompileOpts(), nil)
		if err != nil {
			return "", err
		}
		return cfg.ForwardingOptions.FamilyInet6Mode, nil
	}
	compileFlat := func(t *testing.T, lines ...string) (string, error) {
		t.Helper()
		tree := &ConfigTree{}
		for _, l := range lines {
			path, err := ParseSetCommand(l)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", l, err)
			}
			tree.SetPath(path)
		}
		cfg, err := compileTree(tree, strictCompileOpts(), nil)
		if err != nil {
			return "", err
		}
		return cfg.ForwardingOptions.FamilyInet6Mode, nil
	}

	// The BASELINE: with no statement at all the field must be empty, or a
	// green below would be indistinguishable from a default.
	if got, err := compileText(t, "forwarding-options {\n}\n"); err != nil || got != "" {
		t.Fatalf("baseline: FamilyInet6Mode=%q err=%v, want empty -- with a non-empty default this "+
			"cell cannot tell a delivered value from one that was never read", got, err)
	}

	for _, tc := range []struct {
		name string
		text string
	}{
		{"compound braced (what NewParser produces)", "forwarding-options {\n family inet6 {\n  mode packet-based;\n }\n}\n"},
		{"compound one-liner", "forwarding-options {\n family inet6 mode packet-based;\n}\n"},
		{"split braced (the census shape)", "forwarding-options {\n family {\n  inet6 {\n   mode packet-based;\n  }\n }\n}\n"},
		{"split, elided inner", "forwarding-options {\n family {\n  inet6 mode packet-based;\n }\n}\n"},
	} {
		got, err := compileText(t, tc.text)
		if err != nil {
			t.Errorf("%s: compile: %v", tc.name, err)
			continue
		}
		if got != "packet-based" {
			t.Errorf("%s: FamilyInet6Mode = %q, want \"packet-based\". The statement commits clean and "+
				"renders back, so an operator has every signal it took effect (#8797).", tc.name, got)
		}
	}

	got, err := compileFlat(t, "set forwarding-options family inet6 mode packet-based")
	if err != nil {
		t.Fatalf("flat set: compile: %v", err)
	}
	if got != "packet-based" {
		t.Errorf("FLAT set: FamilyInet6Mode = %q, want \"packet-based\" -- this is the spelling an "+
			"operator types (#8797)", got)
	}

	// The VALUE must be carried, not just presence. `packet-based` and
	// `flow-based` compiling to the same thing was half the original symptom.
	flow, err := compileText(t, "forwarding-options {\n family inet6 {\n  mode flow-based;\n }\n}\n")
	if err != nil {
		t.Fatalf("flow-based: %v", err)
	}
	if flow != "flow-based" {
		t.Errorf("FamilyInet6Mode = %q for `mode flow-based`, want \"flow-based\"", flow)
	}
	if flow == "packet-based" {
		t.Error("`flow-based` and `packet-based` compile to the same value: the leaf's presence is " +
			"carried but its VALUE is not (#8797)")
	}
}

// The old lookup matched exactly one shape, and it is the shape the census
// synthesizes. Recorded as a cell so a future refactor back to a two-level
// FindChild is caught by the spelling it breaks rather than by the one it keeps.
func TestCompoundFamilyLookupIsNotTwoLevel8797(t *testing.T) {
	compound := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
		{Keys: []string{"family", "inet6"}, Children: []*Node{
			{Keys: []string{"mode", "packet-based"}, IsLeaf: true},
		}},
	}}
	// A two-level descent finds nothing here: `inet6` is not a CHILD.
	if fam := compound.FindChild("family"); fam == nil {
		t.Fatal("family node not found")
	} else if fam.FindChild("inet6") != nil {
		t.Fatal("the compound node has an `inet6` CHILD, so this fixture no longer represents the " +
			"compound shape and the cell below proves nothing")
	}
	fo := &ForwardingOptionsConfig{}
	if err := compileForwardingOptions(compound, fo); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if fo.FamilyInet6Mode != "packet-based" {
		t.Errorf("FamilyInet6Mode = %q, want \"packet-based\" -- the compiler is descending two levels "+
			"into a one-node compound key again (#8797)", fo.FamilyInet6Mode)
	}
}

// The `afName != "inet6"` filter is UNREACHABLE against today's schema:
// `schemaForwardingOptions` declares exactly one address family under `family`,
// so no validated commit can produce a `family inet` sibling and a mutation
// deleting the filter survives every other cell here. Correct-and-unobservable
// is a claim about the TEST, not a reason to delete the check -- so this builds
// the tree that reaches the branch.
//
// Such a tree is not hypothetical in the way a schema-only argument suggests:
// pkg/configstore/db.go unmarshals a persisted AST with no Node validator, and
// the tolerant load / peer-sync path (#1960) accepts what the strict path would
// refuse. A compiler that takes any family's `mode` as the inet6 mode would give
// two nodes different IPv6 forwarding behaviour from the same payload.
func TestOnlyTheInet6FamilySetsTheInet6Mode8797(t *testing.T) {
	for _, tc := range []struct {
		name   string
		family []string
		want   string
	}{
		{"inet6 sets it", []string{"family", "inet6"}, "packet-based"},
		{"inet must NOT set it", []string{"family", "inet"}, ""},
		{"an unmodelled family must NOT set it", []string{"family", "mpls"}, ""},
	} {
		node := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
			{Keys: tc.family, Children: []*Node{
				{Keys: []string{"mode", "packet-based"}, IsLeaf: true},
			}},
		}}
		fo := &ForwardingOptionsConfig{}
		if err := compileForwardingOptions(node, fo); err != nil {
			t.Fatalf("%s: compile: %v", tc.name, err)
		}
		if fo.FamilyInet6Mode != tc.want {
			t.Errorf("%s: FamilyInet6Mode = %q, want %q -- a `mode` under a DIFFERENT address family "+
				"is being taken as the IPv6 forwarding mode (#8797)", tc.name, fo.FamilyInet6Mode, tc.want)
		}
	}
	// The same, one level down, so the split shape is covered by the filter too.
	split := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
		{Keys: []string{"family"}, Children: []*Node{
			{Keys: []string{"inet"}, Children: []*Node{{Keys: []string{"mode", "packet-based"}, IsLeaf: true}}},
		}},
	}}
	fo := &ForwardingOptionsConfig{}
	if err := compileForwardingOptions(split, fo); err != nil {
		t.Fatalf("split: %v", err)
	}
	if fo.FamilyInet6Mode != "" {
		t.Errorf("split shape: an `inet` mode set FamilyInet6Mode = %q (#8797)", fo.FamilyInet6Mode)
	}
}
