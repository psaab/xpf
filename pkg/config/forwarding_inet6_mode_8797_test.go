package config

import (
	"strings"
	"testing"
)

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

// Only the inet6 family's `mode` may set FamilyInet6Mode. A `mode` leaf
// under any OTHER family — declared or not — must never reach the IPv6
// mode slot, or two nodes get different IPv6 forwarding behaviour from
// the same payload.
//
// #18881: the canonical Junos AF tokens (inet, mpls, ccc, …) are now
// DECLARED for `forwarding-options family` (forwardingFamilyKnown17196),
// so a validated commit CAN produce a `family inet` sibling and this cell
// no longer needs the "unreachable against today's schema" argument to
// justify its hand-built trees. The contract per family class, re-pinned
// from #17196's {inet6}-only rejection (first-bad c4e12aafc3, which also
// broke #12090's bare mpls/ccc acceptance):
//
//	inet6        consumed: `mode` sets FamilyInet6Mode
//	other known  accepted INERT with the #18881 accepted-only advisory;
//	             the `mode` is not taken (#8797)
//	unknown      strict-reject with the #17196 diagnostic — #18881 keeps
//	             genuinely unknown tokens rejected
func TestOnlyTheInet6FamilySetsTheInet6Mode8797(t *testing.T) {
	// inet6 sets it (strict seam, unchanged).
	{
		node := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
			{Keys: []string{"family", "inet6"}, Children: []*Node{
				{Keys: []string{"mode", "packet-based"}, IsLeaf: true},
			}},
		}}
		fo := &ForwardingOptionsConfig{}
		if err := compileForwardingOptions(node, fo); err != nil {
			t.Fatalf("inet6 sets it: compile: %v", err)
		}
		if fo.FamilyInet6Mode != "packet-based" {
			t.Errorf("inet6 sets it: FamilyInet6Mode = %q, want %q (#8797)", fo.FamilyInet6Mode, "packet-based")
		}
	}
	// #18881: a known-but-unconsumed family commits INERT — not the
	// #17196 rejection this arm pinned before #18881 — carrying the
	// accepted-only advisory on BOTH paths, and its `mode` is NEVER
	// taken as the IPv6 forwarding mode (#8797).
	for _, tc := range []struct {
		name   string
		family []string
	}{
		{"inet must NOT set it", []string{"family", "inet"}},
		{"an unconsumed family must NOT set it", []string{"family", "mpls"}},
	} {
		node := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
			{Keys: tc.family, Children: []*Node{
				{Keys: []string{"mode", "packet-based"}, IsLeaf: true},
			}},
		}}
		advised := func(ws []string) bool {
			for _, w := range ws {
				if strings.Contains(w, "family "+tc.family[1]) &&
					strings.Contains(w, "accepted-only") && strings.Contains(w, "#18881") {
					return true
				}
			}
			return false
		}
		fo := &ForwardingOptionsConfig{}
		var warnings []string
		if err := compileForwardingOptionsWithOpts(node, fo, strictCompileOpts(), &warnings); err != nil {
			t.Fatalf("%s: strict compile rejected a known Junos forwarding-options family, "+
				"want inert acceptance (#18881): %v", tc.name, err)
		}
		if fo.FamilyInet6Mode != "" {
			t.Errorf("%s: FamilyInet6Mode = %q, want %q -- a `mode` under a DIFFERENT address family "+
				"is being taken as the IPv6 forwarding mode (#8797)", tc.name, fo.FamilyInet6Mode, "")
		}
		if !advised(warnings) {
			t.Errorf("%s: strict acceptance carries no #18881 advisory, warnings=%v", tc.name, warnings)
		}
		foLenient := &ForwardingOptionsConfig{}
		var lenientWarnings []string
		if err := compileForwardingOptionsWithOpts(node, foLenient, lenientCompileOpts(), &lenientWarnings); err != nil {
			t.Fatalf("%s lenient: %v", tc.name, err)
		}
		if foLenient.FamilyInet6Mode != "" {
			t.Errorf("%s lenient: FamilyInet6Mode = %q, want %q (#8797)", tc.name, foLenient.FamilyInet6Mode, "")
		}
		if !advised(lenientWarnings) {
			t.Errorf("%s lenient carries no #18881 advisory, warnings=%v", tc.name, lenientWarnings)
		}
	}
	// The same, one level down, so the split shape is covered by the filter too.
	split := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
		{Keys: []string{"family"}, Children: []*Node{
			{Keys: []string{"inet"}, Children: []*Node{{Keys: []string{"mode", "packet-based"}, IsLeaf: true}}},
		}},
	}}
	foSplit := &ForwardingOptionsConfig{}
	var splitWarnings []string
	if err := compileForwardingOptionsWithOpts(split, foSplit, strictCompileOpts(), &splitWarnings); err != nil {
		t.Fatalf("split shape: strict rejected a known family, want inert acceptance (#18881): %v", err)
	}
	if foSplit.FamilyInet6Mode != "" {
		t.Errorf("split shape: an `inet` mode set FamilyInet6Mode = %q (#8797)", foSplit.FamilyInet6Mode)
	}
	foSplitLenient := &ForwardingOptionsConfig{}
	var splitLenientWarnings []string
	if err := compileForwardingOptionsWithOpts(split, foSplitLenient, lenientCompileOpts(), &splitLenientWarnings); err != nil {
		t.Fatalf("split lenient: %v", err)
	}
	if foSplitLenient.FamilyInet6Mode != "" {
		t.Errorf("split lenient: an `inet` mode set FamilyInet6Mode = %q (#8797)", foSplitLenient.FamilyInet6Mode)
	}
	// #18881 negative control: the widening must not open the world. An
	// unknown token still strict-rejects with the #17196 diagnostic.
	unknown := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
		{Keys: []string{"family", "bogus-af-18881"}, Children: []*Node{
			{Keys: []string{"mode", "packet-based"}, IsLeaf: true},
		}},
	}}
	foUnknown := &ForwardingOptionsConfig{}
	if err := compileForwardingOptions(unknown, foUnknown); err == nil ||
		!strings.Contains(err.Error(), "bogus-af-18881") || !strings.Contains(err.Error(), "#17196") {
		t.Errorf("unknown forwarding-options family must strict-reject with the #17196 diagnostic (#18881), got %v", err)
	}
	if foUnknown.FamilyInet6Mode != "" {
		t.Errorf("unknown family: FamilyInet6Mode = %q, want empty (#8797)", foUnknown.FamilyInet6Mode)
	}
}

// #18881 review fold (MF-1): a structured `forwarding-options family`
// member carrying RESIDUE — a second token after the family name, e.g.
// `family { inet6 mpls { mode … } }` — is malformed Junos (a member names
// ONE address family). The canonical-set widening let it commit and
// install the residue member as inet6 (FamilyInet6Mode flipped); at THIS
// top only, any structured residue is treated as unknown regardless of
// token set membership — restoring the pre-widening #17196 rejection —
// while the interfaces/sampling callsites keep the set-membership rule.
func TestForwardingOptionsFamilyResidueMemberIsRejected18881(t *testing.T) {
	// Authored spelling through the full strict compile path.
	text := "forwarding-options { family { inet6 mpls { mode packet-based; } } }"
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "mpls") || !strings.Contains(err.Error(), "#18881") {
		t.Fatalf("structured residue member must strict-reject naming the residue token (#18881), got %v", err)
	}
	// Strict seam: rejection AND nothing installed even on the error path.
	node := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
		{Keys: []string{"family"}, Children: []*Node{
			{Keys: []string{"inet6", "mpls"}, Children: []*Node{
				{Keys: []string{"mode", "packet-based"}, IsLeaf: true},
			}},
		}},
	}}
	fo := &ForwardingOptionsConfig{}
	if err := compileForwardingOptions(node, fo); err == nil || !strings.Contains(err.Error(), "mpls") {
		t.Fatalf("strict seam: residue member must reject naming the residue token, got %v", err)
	}
	if fo.FamilyInet6Mode != "" {
		t.Fatalf("residue member installed FamilyInet6Mode = %q behind a second token", fo.FamilyInet6Mode)
	}
	// Lenient: boots (#1960), warns + skips the member, installs nothing.
	foLenient := &ForwardingOptionsConfig{}
	var warnings []string
	if err := compileForwardingOptionsWithOpts(node, foLenient, lenientCompileOpts(), &warnings); err != nil {
		t.Fatalf("lenient must not brick (#1960): %v", err)
	}
	if foLenient.FamilyInet6Mode != "" {
		t.Errorf("lenient installed the mode behind residue: FamilyInet6Mode = %q", foLenient.FamilyInet6Mode)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "mpls") ||
		!strings.Contains(strings.Join(warnings, "\n"), "skipping that family member") {
		t.Errorf("lenient must warn naming the residue token and skip the member, warnings=%v", warnings)
	}
	// CLEAN CONTROL: the same member with no residue still installs the mode.
	ctl := &Node{Keys: []string{"forwarding-options"}, Children: []*Node{
		{Keys: []string{"family", "inet6"}, Children: []*Node{
			{Keys: []string{"mode", "packet-based"}, IsLeaf: true},
		}},
	}}
	foCtl := &ForwardingOptionsConfig{}
	if err := compileForwardingOptions(ctl, foCtl); err != nil {
		t.Fatalf("clean control: %v", err)
	}
	if foCtl.FamilyInet6Mode != "packet-based" {
		t.Fatalf("clean control must still install the mode (#8797), got %q", foCtl.FamilyInet6Mode)
	}
}
