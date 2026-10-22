package config

import (
	"sort"
	"strings"
	"testing"
)

func ripSchemaVerdict9206(t *testing.T, line string) error {
	t.Helper()
	tree := &ConfigTree{}
	p, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	tree.SetPath(p)
	return SchemaValidateWithDefinitions(tree, tree)
}

// #9206: the absorbed statement is now refused at the leaf that absorbs it.
//
// RED ON REVERT: drop ValidateRIPNeighborInterface from the schema and the
// first case ACCEPTS again, putting `authentication-key` and `secret1` into the
// neighbour list as two non-existent interfaces named to FRR.
func TestRIPNeighborAbsorptionRefused9206(t *testing.T) {
	if err := ripSchemaVerdict9206(t,
		"set protocols rip group g1 neighbor ge-0/0/0 authentication-key secret1"); err == nil {
		t.Error("#9206: an absorbed `authentication-key` is still accepted as a neighbour " +
			"interface. Two non-existent interfaces reach FRR.")
	}
	// The CONTROL that makes the rejection mean something: the same neighbour
	// WITHOUT the absorbed statement must still commit. A validator that
	// refused everything would satisfy the assertion above.
	if err := ripSchemaVerdict9206(t, "set protocols rip group g1 neighbor ge-0/0/0"); err != nil {
		t.Errorf("#9206: a plain neighbour was rejected: %v", err)
	}
}

// Every interface name this repo actually uses must survive. Tightening a name
// validator risks rejecting a legitimate name, and that risk is the reason the
// shape was censused before it was chosen rather than after.
func TestRIPNeighborAcceptsRealInterfaceNames9206(t *testing.T) {
	for _, n := range []string{
		"ge-0/0/0", "ge-0-0-0", "ge-0/0/0.0", "ge-0-0-0.0", "ge-7/0/1", "ge-7/0/3",
		"xe-1/0/0", "gr-0/0/0", "ip-0/0/0.0",
		"reth0", "reth1", "reth0.50", "reth0.100", "reth1.0", "reth10",
		"st0", "st0.0", "st0.1", "st5.3", "fab0", "fab1",
		"em0", "fxp0", "fxp0.0", "fxp1", "lo0", "irb", "irb.100",
		"vlan100", "eth0", "eth3.0", "ae0", "wg0", "enp5s0", "enp101s0f1np1",
	} {
		if err := ValidateRIPNeighborInterface(n); err != nil {
			t.Errorf("#9206: legitimate interface name %q was REJECTED: %v", n, err)
		}
	}
}

// THE RESIDUAL, PINNED. A bare single-word keyword is shape-indistinguishable
// from a bare interface name -- `irb` is a real one this repo configures -- so
// no shape rejects `export` without also rejecting `irb`. Those still absorb.
//
// This cell exists so the fix cannot be mistaken for a complete one. A landed
// partial fix removes the reason anyone looks again, and the marker going green
// is exactly how that happens. RED here means someone closed the residual --
// good news, and this cell should then be rewritten rather than deleted.
func TestRIPNeighborBareKeywordStillAbsorbs9206(t *testing.T) {
	if err := ripSchemaVerdict9206(t,
		"set protocols rip group g1 neighbor ge-0/0/0 metric 5"); err != nil {
		t.Logf("#9206 residual CLOSED: a bare keyword is now refused too (%v). "+
			"Rewrite this cell to assert the stronger property.", err)
		t.Errorf("#9206: this cell pins a KNOWN-OPEN residual and it is no longer open — " +
			"update it deliberately rather than leaving a cell that documents a gap that " +
			"has been fixed.")
	}
	// And the shape rule's boundary, stated as a fact rather than left implicit.
	if err := ValidateRIPNeighborInterface("export"); err != nil {
		t.Errorf("#9206: `export` is rejected by shape, which would mean bare `irb` is too — "+
			"re-check the corpus before tightening: %v", err)
	}
	if err := ValidateRIPNeighborInterface("irb"); err != nil {
		t.Errorf("#9206: bare `irb` REJECTED (%v). It is a real interface name this repo "+
			"configures (`set interfaces irb`), and it is why the bare-keyword residual "+
			"cannot be closed by shape.", err)
	}
}

// A VALIDATOR ALONE DOES NOT RUN. The schema walk's typed-leaf branch is a
// CONJUNCTION -- `isTypedLeaf() && (validator != nil || treeValidator != nil)`
// -- and `isTypedLeaf()` is `valueType != ValueAny`. So a leaf that carries a
// validator and no valueType is NEVER VALIDATED, and nothing says so: the
// validator is present, referenced, compiles, and is dead.
//
// Found by walking into it. #9206's validator was wired onto `rip group
// neighbor` and the absorbed `authentication-key` was still accepted, because
// the leaf declared a valueHint but no valueType. Adding ValueInterfaceName is
// what made it live.
//
// Censused when found: ZERO other leaves are in that state, so this guard is
// born green and exists to keep it that way. The next person to wire a
// validator gets told here instead of shipping one that does nothing.
func TestNoLeafCarriesADeadValidator9206(t *testing.T) {
	var dead []string
	seen := map[string]bool{}
	var walk func(path []string, n *schemaNode)
	walk = func(path []string, n *schemaNode) {
		if n == nil || len(path) > 8 {
			return
		}
		for k, c := range n.children {
			if c == nil {
				continue
			}
			p := append(append([]string{}, path...), k)
			key := strings.Join(p, " ")
			if seen[key] {
				continue
			}
			seen[key] = true
			if c.validator != nil && c.valueType == ValueAny {
				dead = append(dead, key)
			}
			walk(p, c)
			if c.wildcard != nil {
				walk(append(p, "<name>"), c.wildcard)
			}
		}
	}
	for k, c := range setSchema.children {
		walk([]string{k}, c)
	}
	// NON-VACUITY: the walk must actually reach leaves, or an empty `dead`
	// proves nothing. A typed-and-validated leaf is known to exist.
	if !seen["protocols rip group <name> neighbor"] && !seen["protocols rip group neighbor"] {
		t.Fatal("#9206: the walk did not reach `protocols rip group neighbor`, so an empty " +
			"result below would be vacuous")
	}
	if len(dead) != 0 {
		sort.Strings(dead)
		t.Errorf("#9206: %d leaf/leaves carry a validator with no valueType, so the "+
			"validator NEVER RUNS (the walk's branch is isTypedLeaf() && validator != nil, "+
			"and isTypedLeaf() is valueType != ValueAny):\n  %s\n\n"+
			"Give each a valueType, or remove the validator so nobody believes the value "+
			"is checked.", len(dead), strings.Join(dead, "\n  "))
	}
}
