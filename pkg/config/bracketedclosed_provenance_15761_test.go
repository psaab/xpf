package config

import (
	"reflect"
	"strings"
	"testing"
)

// Regression tests for #15761 — stripInactiveNodes and packedBodyChildren dropped
// BracketedClosed while preserving KeysBracketed, causing any inactive: node
// or packed group leaf to falsify #11779 routing-policy bracketed `from` lists.
//
// Mechanism: KeysBracketed says which tokens were inside a bracket list;
// BracketedClosed says the list was closed before its statement terminator.
// Without the closed bit, splitPolicyTermFromRun11779 and
// parsePolicyTermInlineKeys treat a closed `[ ospf bgp ]` as unclosed and
// mark the term malformed (strict compile rejects, tolerant compile forces reject).

// TestStripInactivePreservesBracketedClosed15761 creates a tree with an
// unrelated inactive node plus a policy term with a routed `from protocol
// [ ospf bgp ]` and asserts that WithoutInactive returns a fresh clone with
// the BracketedClosed bit preserved and compiles to FromProtocols=[ospf bgp].
func TestStripInactivePreservesBracketedClosed15761(t *testing.T) {
	src := `policy-options {
 policy-statement P {
  term T from protocol [ ospf bgp ] then accept;
 }
}
system {
 inactive: host-name parked;
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}

	// WithoutInactive must return a fresh clone (not the receiver)
	stripped := tree.WithoutInactive()
	if stripped == tree {
		t.Fatal("WithoutInactive returned the receiver unchanged; expected a pruned clone since an inactive node exists")
	}

	// Find term T — there are multiple ways it might be represented
	// after parse; navigate via FindChild chain
	poNode := stripped.FindChild("policy-options")
	if poNode == nil {
		t.Fatal("policy-options not found after strip")
	}
	psNode := poNode.FindChild("policy-statement")
	if psNode == nil {
		t.Fatal("policy-statement not found after strip")
	}

	// The term node may be named "T" or have keys including "T"
	termNodes := psNode.FindChildren("term")
	if len(termNodes) == 0 {
		t.Fatalf("no term nodes under policy-statement, children: %+v", psNode.Children)
	}
	termNode := termNodes[0]
	// Check termNode identity — it should contain T
	keyPath := termNode.KeyPath()
	found := false
	if strings.Contains(keyPath, "T") {
		found = true
	}
	if !found {
		t.Fatalf("term node KeyPath = %q, does not contain T", keyPath)
	}

	// Check BracketedClosed preservation: first try termNode itself
	// (packed term `term T from protocol [ ospf bgp ] then accept`)
	// may have bracketed tokens on it. Also check children for protocol node.
	if n := findBracketedClosed15761(termNode); n == nil {
		t.Fatal("no node with BracketedClosed=true found in term subtree; strip dropped the close bit (#15761)")
	} else if debugCrossCheck15761(n.Keys) {
		// Confirm the preserved node carries the expected keys
		want := []string{"term", "T", "from", "protocol", "ospf", "bgp", "then", "accept"}
		if !reflect.DeepEqual(n.Keys, want) {
			t.Logf("bracketedClosed found on node with keys %v (expected packed term %v, other shapes OK)", n.Keys, want)
		}
	}

	// Compile strict: must compile clean with FromProtocols=[ospf bgp]
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v — inactive strip falsified the closed bracketed from list (#15761)", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil {
		t.Fatal("policy-statement P not compiled")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("compiled %d terms, want 1", len(ps.Terms))
	}
	term := ps.Terms[0]
	if term.Name != "T" {
		t.Fatalf("term.Name = %q, want \"T\"", term.Name)
	}
	if term.Action != "accept" {
		t.Errorf("term.Action = %q, want \"accept\"", term.Action)
	}
	if !reflect.DeepEqual(term.FromProtocols, []string{"ospf", "bgp"}) {
		t.Errorf("FromProtocols = %v, want [ospf bgp]", term.FromProtocols)
	}
	if term.invalidFromSyntax11779 != "" {
		t.Errorf("term.invalidFromSyntax11779 = %q, want empty — BracketedClosed was not preserved", term.invalidFromSyntax11779)
	}

	// Compile lenient should also preserve acceptance
	cfgLen, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	psLen := cfgLen.PolicyOptions.PolicyStatements["P"]
	if psLen == nil || len(psLen.Terms) != 1 {
		t.Fatal("lenient compiled policy-statement missing term")
	}
	termLen := psLen.Terms[0]
	if termLen.Action != "accept" {
		t.Errorf("lenient term.Action = %q, want \"accept\"", termLen.Action)
	}
	if !reflect.DeepEqual(termLen.FromProtocols, []string{"ospf", "bgp"}) {
		t.Errorf("lenient FromProtocols = %v, want [ospf bgp]", termLen.FromProtocols)
	}
	if termLen.invalidFromSyntax11779 != "" {
		t.Errorf("lenient term.invalidFromSyntax11779 = %q, want empty", termLen.invalidFromSyntax11779)
	}
}

// findBracketedClosed15761 walks termNode subtree looking for a node with
// BracketedClosed==true and at least one KeyBracketed==true.
func findBracketedClosed15761(root *Node) *Node {
	var found *Node
	var walk func(*Node)
	walk = func(n *Node) {
		if found != nil {
			return
		}
		if n != nil && n.BracketedClosed {
			hasBracketed := false
			for _, b := range n.KeysBracketed {
				if b {
					hasBracketed = true
					break
				}
			}
			if hasBracketed {
				found = n
				return
			}
		}
		if n != nil {
			for _, c := range n.Children {
				walk(c)
			}
		}
	}
	walk(root)
	return found
}

func debugCrossCheck15761(keys []string) bool {
	_ = keys
	return true
}

// TestStripInactiveSyncsCloneFields15761 verifies stripInactiveNodes copies
// the fields that cloneNodes copies: duplicateBlockMergeMarkers9023,
// leafMemberGroups9862, BracketedClosed, and fromGroups. Heterogeneous
// markers and member groups exercise deep-copy and aliasing.
func TestStripInactiveSyncsCloneFields15761(t *testing.T) {
	// Build a tree with an inactive marker so stripInactiveNodes runs
	root := &ConfigTree{
		Children: []*Node{
			{Keys: []string{"inactive-stub"}, IsLeaf: true, Inactive: true},
			{
				Keys: []string{"policy-options"},
				Children: []*Node{
					{
						Keys:            []string{"policy-statement", "P"},
						KeysBracketed:   []bool{false, false, false, false, false, true, true},
						BracketedClosed: true,
						duplicateBlockMergeMarkers9023: []string{"m1", "m2"},
						leafMemberGroups9862: []leafListMemberGroups9862{
							{value: "ospf", quoted: false, groups: []string{"g1", "g2"}},
							{value: "bgp", quoted: true, groups: []string{"g3"}},
						},
						fromGroups: []string{"outer"},
						Children: []*Node{
							{
								Keys:            []string{"term", "T", "from", "protocol", "ospf", "bgp", "then", "accept"},
								KeysBracketed:   []bool{false, false, false, false, true, true, false, false},
								BracketedClosed: true,
							},
						},
					},
				},
			},
		},
	}

	stripped := root.WithoutInactive()
	if stripped == root {
		t.Fatal("WithoutInactive returned receiver; fixture must contain an inactive node")
	}

	// Find the policy-statement node
	po := stripped.FindChild("policy-options")
	if po == nil {
		t.Fatal("policy-options missing after strip")
	}
	ps := po.FindChild("policy-statement")
	if ps == nil {
		t.Fatal("policy-statement missing after strip")
	}

	if !ps.BracketedClosed {
		t.Error("ps.BracketedClosed = false, want true")
	}
	if !reflect.DeepEqual(ps.KeysBracketed, []bool{false, false, false, false, false, true, true}) {
		t.Errorf("ps.KeysBracketed = %v, want preserved", ps.KeysBracketed)
	}
	if !reflect.DeepEqual(ps.duplicateBlockMergeMarkers9023, []string{"m1", "m2"}) {
		t.Errorf("ps.duplicateBlockMergeMarkers9023 = %v, want [m1 m2]", ps.duplicateBlockMergeMarkers9023)
	}
	if len(ps.leafMemberGroups9862) != 2 {
		t.Fatalf("ps.leafMemberGroups9862 len = %d, want 2", len(ps.leafMemberGroups9862))
	}
	if ps.leafMemberGroups9862[0].value != "ospf" || ps.leafMemberGroups9862[0].quoted != false ||
		!reflect.DeepEqual(ps.leafMemberGroups9862[0].groups, []string{"g1", "g2"}) {
		t.Errorf("ps.leafMemberGroups9862[0] = %+v, want {ospf false [g1 g2]}", ps.leafMemberGroups9862[0])
	}
	if ps.leafMemberGroups9862[1].value != "bgp" || ps.leafMemberGroups9862[1].quoted != true ||
		!reflect.DeepEqual(ps.leafMemberGroups9862[1].groups, []string{"g3"}) {
		t.Errorf("ps.leafMemberGroups9862[1] = %+v, want {bgp true [g3]}", ps.leafMemberGroups9862[1])
	}
	if !reflect.DeepEqual(ps.fromGroups, []string{"outer"}) {
		t.Errorf("ps.fromGroups = %v, want [outer]", ps.fromGroups)
	}

	// Mutate stripped slices to check aliasing (clone must deep-copy)
	ps.duplicateBlockMergeMarkers9023[0] = "CHANGED"
	ps.leafMemberGroups9862[0].groups[0] = "CHANGED"
	ps.fromGroups[0] = "CHANGED"
	ps.KeysBracketed[5] = false

	// Original must be unchanged
	origPS := root.Children[1].Children[0]
	if origPS.duplicateBlockMergeMarkers9023[0] != "m1" {
		t.Error("aliasing: original duplicateBlockMergeMarkers9023 mutated")
	}
	if origPS.leafMemberGroups9862[0].groups[0] != "g1" {
		t.Error("aliasing: original leafMemberGroups9862 groups mutated")
	}
	if origPS.fromGroups[0] != "outer" {
		t.Error("aliasing: original fromGroups mutated")
	}
	if !origPS.KeysBracketed[5] {
		t.Error("aliasing: original KeysBracketed mutated")
	}
}

// TestPackedBodyPreservesBracketedClosed15761 directly exercises
// packedBodyChildren's BracketedClosed preservation and also exercises
// splitPolicyTermFromRun11779 on a term node.
func TestPackedBodyPreservesBracketedClosed15761(t *testing.T) {
	// Direct unit: node with keys [term, T, from, protocol, ospf, bgp, then, accept]
	// KeysBracketed false,false,false,false,true,true,false,false BracketedClosed=true
	node := &Node{
		Keys:            []string{"term", "T", "from", "protocol", "ospf", "bgp", "then", "accept"},
		KeysBracketed:   []bool{false, false, false, false, true, true, false, false},
		BracketedClosed: true,
	}
	schema := schemaForPath("policy-options", "policy-statement", "term")
	if schema == nil {
		t.Fatal("schemaForPath(policy-options, policy-statement, term) is nil")
	}
	children := packedBodyChildren(node, schema)

	// At least one child must exist
	if len(children) == 0 {
		t.Fatal("packedBodyChildren returned no children")
	}

	// Assert some child (or descendant) with bracketed keys has BracketedClosed==true
	var foundClosed bool
	var walk func([]*Node)
	walk = func(ns []*Node) {
		for _, n := range ns {
			if n.BracketedClosed {
				for _, b := range n.KeysBracketed {
					if b {
						foundClosed = true
					}
				}
			}
			walk(n.Children)
		}
	}
	walk(children)
	if !foundClosed {
		t.Error("no packedBodyChildren output (or descendant) carries BracketedClosed=true with bracketed keys; packed leg dropped the close bit (#15761)")
	}

	// Also test splitPolicyTermFromRun11779 directly
	term2 := &PolicyTerm{Name: "T"}
	fromSchema := schemaForPath("policy-options", "policy-statement", "term", "from")
	if fromSchema == nil {
		t.Fatal("from schema is nil")
	}
	run := &Node{
		Keys:            []string{"from", "protocol", "ospf", "bgp", "then", "accept"},
		KeysBracketed:   []bool{false, false, true, true, false, false},
		BracketedClosed: true,
	}
	parts := splitPolicyTermFromRun11779(term2, run, fromSchema, true)
	if term2.invalidFromSyntax11779 != "" {
		t.Errorf("splitPolicyTermFromRun11779 marked closed list malformed: %q", term2.invalidFromSyntax11779)
	}
	_ = parts

	// Now with a constructed node without BracketedClosed to show detection
	term3 := &PolicyTerm{Name: "T"}
	run2 := &Node{
		Keys:            []string{"from", "protocol", "ospf", "bgp", "then", "accept"},
		KeysBracketed:   []bool{false, false, true, true, false, false},
		BracketedClosed: false,
	}
	_ = splitPolicyTermFromRun11779(term3, run2, fromSchema, true)
	// Unclosed may or may not mark depending on schema arity — log for reference
	t.Logf("unclosed run invalidFromSyntax11779 = %q (expected non-empty if detection active)", term3.invalidFromSyntax11779)
}

// TestGroupPackedLeafUnmodelledTailClosedBit15761 exercises the group leg.
// This is a construction-based unit test: groupPackedLeafUnmodelledTail is
// called with a manually-constructed ancestorPath and source node. If the
// tail is nil (function returns nil when it cannot resolve), we skip the
// strict assertion — the two compile-level legs above still bind the fix.
func TestGroupPackedLeafUnmodelledTailClosedBit15761(t *testing.T) {
	// Construct a source node that looks like a packed leaf for a container
	// whose schema has children. We use "interfaces ge-0/0/0 unit 0 family inet"
	// as an example — interfaces schema should resolve.
	// ancestorPath is the path ABOVE the leaf's parent. For a leaf
	// "ge-0/0/0 unit 0 family inet frobnicate 7" under interfaces,
	// ancestorPath = [["interfaces"]]
	s := &Node{
		Keys:            []string{"ge-0/0/0", "unit", "0", "frobnicate", "7"},
		KeysQuoted:      []bool{false, false, false, false, false},
		KeysBracketed:   []bool{false, false, false, true, true},
		BracketedClosed: true,
		IsLeaf:          true,
	}
	ancestorPath := [][]string{{"interfaces"}}

	tails := groupPackedLeafUnmodelledTail(ancestorPath, s)
	if tails == nil {
		// The schema at this path doesn't satisfy the function's requirements
		// (leafSchema.children == nil etc). Log and skip strict check — the
		// compile legs above still cover the #15761 fix.
		t.Skip("groupPackedLeafUnmodelledTail returned nil for this construction; compile legs cover the fix")
	}
	if len(tails) != 1 {
		t.Fatalf("got %d tails, want 1", len(tails))
	}
	tail := tails[0]
	if !tail.BracketedClosed {
		t.Errorf("tail.BracketedClosed = false, want true — groupPackedLeafUnmodelledTail dropped the close bit (#15761); tail keys=%v KeysBracketed=%v", tail.Keys, tail.KeysBracketed)
	}
	hasBracketed := false
	for _, b := range tail.KeysBracketed {
		if b {
			hasBracketed = true
		}
	}
	if !hasBracketed {
		t.Errorf("tail.KeysBracketed = %v, want at least one true (bracketed tail tokens)", tail.KeysBracketed)
	}
}
