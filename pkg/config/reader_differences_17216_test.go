package config

import (
	"reflect"
	"testing"
)

// TestReaderDifferences17216PinDocClaims pins the three real
// distinguishing properties of firewallMatchValues, plainListValues and
// multiLeafAuthoredValues, so the doc claims at ast.go (plainListValues),
// compiler_interfaces.go (fabricMemberValues),
// compiler_fabric_members_6694_test.go and docs/config-schema.md can fail:
//
//   - descent depth: plainListValues descends to grandchildren;
//     firewallMatchValues reads direct children only;
//     multiLeafAuthoredValues takes only Name() (Keys[0]) of each child.
//   - bare self-repeat on the node's own tail: firewallMatchValues skips a
//     bare (unquoted) repeat of Keys[0]; the other two keep it. A quoted
//     repeat is a value for firewallMatchValues.
//   - empty-token policy: multiLeafAuthoredValues keeps empties (and
//     synthesizes [""] for a valueless node); the other two drop them.
//
// It also pins that firewallMatchValues reads EVERY key of each direct
// child (since #6714), so reverting it to first-key-only fails here.
func TestReaderDifferences17216PinDocClaims(t *testing.T) {
	rows := []struct {
		name string
		node *Node
		fw   []string
		pl   []string
		ml   []string
	}{
		{
			name: "every key of each direct child",
			node: &Node{Keys: []string{"leaf"}, Children: []*Node{
				{Keys: []string{"a", "b"}}, {Keys: []string{"c"}},
			}},
			fw: []string{"a", "b", "c"},
			pl: []string{"a", "b", "c"},
			ml: []string{"a", "c"},
		},
		{
			name: "grandchild descent",
			node: &Node{Keys: []string{"leaf"}, Children: []*Node{
				{Keys: []string{"a"}, Children: []*Node{{Keys: []string{"b", "c"}}}},
			}},
			fw: []string{"a"},
			pl: []string{"a", "b", "c"},
			ml: []string{"a"},
		},
		{
			name: "child sub-block tokens",
			node: &Node{Keys: []string{"leaf"}, Children: []*Node{
				{Keys: []string{"a", "x"}, Children: []*Node{{Keys: []string{"y", "z"}}}},
			}},
			fw: []string{"a", "x"},
			pl: []string{"a", "x", "y", "z"},
			ml: []string{"a"},
		},
		{
			name: "bare self-repeat on own tail",
			node: &Node{Keys: []string{"leaf", "leaf", "a"}},
			fw:   []string{"a"},
			pl:   []string{"leaf", "a"},
			ml:   []string{"leaf", "a"},
		},
		{
			name: "quoted self-repeat is a value",
			node: &Node{Keys: []string{"leaf", "leaf", "a"},
				KeysQuoted: []bool{false, true, false}},
			fw: []string{"leaf", "a"},
			pl: []string{"leaf", "a"},
			ml: []string{"leaf", "a"},
		},
		{
			name: "self-repeat on child keys is kept by all",
			node: &Node{Keys: []string{"leaf"}, Children: []*Node{
				{Keys: []string{"leaf", "a"}},
			}},
			fw: []string{"leaf", "a"},
			pl: []string{"leaf", "a"},
			ml: []string{"leaf"},
		},
		{
			name: "empty tokens",
			node: &Node{Keys: []string{"leaf", "", "a"}, Children: []*Node{
				{Keys: []string{"", "b"}},
			}},
			fw: []string{"a", "b"},
			pl: []string{"a", "b"},
			ml: []string{"", "a", ""},
		},
		{
			name: "valueless node",
			node: &Node{Keys: []string{"leaf"}},
			fw:   nil,
			pl:   nil,
			ml:   []string{""},
		},
		{
			name: "empty child contributes one slot only to multiLeaf",
			node: &Node{Keys: []string{"leaf"}, Children: []*Node{
				{Keys: []string{""}}, {Keys: []string{"a", "b"}},
			}},
			fw: []string{"a", "b"},
			pl: []string{"a", "b"},
			ml: []string{"", "a"},
		},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			if got := firewallMatchValues(tc.node); !reflect.DeepEqual(got, tc.fw) {
				t.Errorf("firewallMatchValues = %q, want %q", got, tc.fw)
			}
			if got := plainListValues(tc.node); !reflect.DeepEqual(got, tc.pl) {
				t.Errorf("plainListValues = %q, want %q", got, tc.pl)
			}
			if got := multiLeafAuthoredValues(tc.node); !reflect.DeepEqual(got, tc.ml) {
				t.Errorf("multiLeafAuthoredValues = %q, want %q", got, tc.ml)
			}
		})
	}
}
