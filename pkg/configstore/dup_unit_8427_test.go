package configstore

import (
	"strings"
	"testing"
)

const dupUnitBase8427 = "system { host-name p; }\n" +
	"security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }\n"

// #8427. compileInterfaces writes `ifc.Units[unitNum] = unit` unconditionally,
// so two hierarchical `unit 0 { ... }` blocks under one interface are
// last-writer-wins for the unit's filter/addresses/flags while the
// interface-level tunnel-address collection APPENDS from every block. The
// #5631/#5878 alias gate cannot see it: that gate fires on two DISTINCT
// spellings canonicalizing to one unit, and these are the SAME spelling.
func TestDuplicateHierarchicalUnitRejected_8427(t *testing.T) {
	dup := dupUnitBase8427 + `interfaces { ge-0/0/0 {
		unit 0 { family inet { address 10.0.1.1/24; } }
		unit 0 { family inet { address 10.0.9.1/24; } } } }`
	err := checkText8427(t, dup)
	if err == nil {
		t.Fatal("two hierarchical `unit 0` blocks committed clean — the later block " +
			"silently replaces the earlier one's filter and flags")
	}
	if !strings.Contains(err.Error(), "declared 2 times") {
		t.Errorf("rejected, but by a different gate: %v", err)
	}
}

// The controls are the whole safety argument for this gate, because the
// detection counts INSTANCES and the alias gate's three views deliberately
// overlap. Each of these is a shape a naive count rejects.
func TestDuplicateUnitGateControls_8427(t *testing.T) {
	cases := map[string]string{
		"a single unit": `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }`,
		"two DIFFERENT units on one interface": `interfaces { ge-0/0/0 {
			vlan-tagging;
			unit 0 { family inet { address 10.0.1.1/24; } }
			unit 1 { vlan-id 1; family inet { address 10.0.2.1/24; } } } }`,
		"the same unit on two DIFFERENT interfaces": `interfaces {
			ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } }
			ge-0/0/1 { unit 0 { family inet { address 10.0.3.1/24; } } } }`,
		// THE control that matters. `groups node0` and `groups node1` each
		// declaring the same interface+unit with that node's own address is the
		// normal HA pattern, and only one applies per node. Counting across
		// groups rejected ALL FOUR shipped cluster configs before the fold was
		// corrected to take the max per collection pass.
		"per-node groups declaring the same unit": `groups {
			node0 { interfaces { em0 { unit 0 { family inet { address 10.99.12.1/30; } } } } }
			node1 { interfaces { em0 { unit 0 { family inet { address 10.99.12.2/30; } } } } } }
			apply-groups [ node0 node1 ];
			interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }`,
	}
	for name, body := range cases {
		if err := checkText8427(t, dupUnitBase8427+body); err != nil {
			t.Errorf("%s REJECTED: %v", name, strings.SplitN(err.Error(), "\n", 2)[0])
		}
	}
}

// The #5631/#5878 alias gate must keep its own diagnostic. A shared loop that
// silently reclassified an alias as a duplicate would lose the message that
// tells an operator the two spellings are the SAME unit.
func TestAliasGateKeepsItsOwnMessage_8427(t *testing.T) {
	alias := dupUnitBase8427 + `interfaces { ge-0/0/0 {
		unit 0 { family inet { address 10.0.1.1/24; } }
		unit 00 { family inet { address 10.0.9.1/24; } } } }`
	err := checkText8427(t, alias)
	if err == nil {
		t.Fatal("the #5631 alias case now commits — this change broke the older gate")
	}
	if !strings.Contains(err.Error(), "name the same logical unit") {
		t.Errorf("the alias case is rejected by the #8427 message, not #5631's: %v", err)
	}
}

func checkText8427(t *testing.T, text string) error {
	t.Helper()
	_, err := CheckText(text, 0)
	return err
}
