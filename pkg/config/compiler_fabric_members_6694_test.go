package config

import (
	"strings"
	"testing"
)

// #6694: `interfaces { fab0 { fabric-options { member-interfaces [ a b ]; } } }`
// compiled an EMPTY member list. The compiler descended miNode.Children only,
// and the hierarchical bracket spelling carries every name on the node's own
// Keys with no children at all.
//
// The same Children-only descent also emptied the plain single-value
// hierarchical spelling `member-interfaces ge-0/0/7;`, which the issue did not
// describe: a one-member fab0 authored in a config FILE (load merge, day-0
// import, rescue config) lost its member too.
//
// fab0 is the chassis-cluster fabric — session sync, config sync, IPsec SA
// sync and the cross-chassis forwarding path that keeps TCP alive across a
// VRRP failback all ride it. A fabric with zero compiled members cannot form,
// and the failure is silent at commit.

func fabricMembersFromBlock(t *testing.T, body string) []string {
	t.Helper()
	p := NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", body, errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig %q: %v", body, err)
	}
	ifc := cfg.Interfaces.Interfaces["fab0"]
	if ifc == nil {
		t.Fatalf("fab0 absent from compiled config for %q", body)
	}
	return ifc.FabricMembers
}

// fabricMembersFromSet drives the flat-set path the way CLAUDE.md requires —
// ParseSetCommand + SetPath, never NewParser.
func fabricMembersFromSet(t *testing.T, cmds ...string) []string {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
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
	ifc := cfg.Interfaces.Interfaces["fab0"]
	if ifc == nil {
		t.Fatal("fab0 absent from compiled config")
	}
	return ifc.FabricMembers
}

func assertFabricMembers6694(t *testing.T, spelling string, got, want []string) {
	t.Helper()
	if len(got) != len(want) || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s: FabricMembers = %v, want %v", spelling, got, want)
	}
}

// Test_6694_FabricMembersEveryHierarchicalSpelling covers the brace-parsed
// spellings. The bracket list and the repeated-statement form both compiled
// to an empty slice.
func Test_6694_FabricMembersEveryHierarchicalSpelling(t *testing.T) {
	want := []string{"ge-0/0/7", "ge-7/0/7"}

	assertFabricMembers6694(t, "nested block `member-interfaces { a; b; }`",
		fabricMembersFromBlock(t,
			`interfaces { fab0 { fabric-options { member-interfaces { ge-0/0/7; ge-7/0/7; } } } }`), want)

	assertFabricMembers6694(t, "bracket list `member-interfaces [ a b ];`",
		fabricMembersFromBlock(t,
			`interfaces { fab0 { fabric-options { member-interfaces [ ge-0/0/7 ge-7/0/7 ]; } } }`), want)

	// Repeated hierarchical statements land as SIBLING member-interfaces
	// nodes; the old FindChild read only the first.
	assertFabricMembers6694(t, "repeated `member-interfaces a; member-interfaces b;`",
		fabricMembersFromBlock(t,
			`interfaces { fab0 { fabric-options { member-interfaces ge-0/0/7; member-interfaces ge-7/0/7; } } }`), want)
}

// Test_6694_FabricMembersSingleHierarchicalMember is the case the issue did
// not describe: one member, authored in a config file, compiled to ZERO.
func Test_6694_FabricMembersSingleHierarchicalMember(t *testing.T) {
	assertFabricMembers6694(t, "single `member-interfaces a;`",
		fabricMembersFromBlock(t,
			`interfaces { fab0 { fabric-options { member-interfaces ge-0/0/7; } } }`),
		[]string{"ge-0/0/7"})
}

// Test_6694_FabricMembersEveryFlatSetSpelling covers the flat-set path. The
// bracket list keeps every name on ONE child node's Keys; since #6714
// firewallMatchValues reads every key of each direct child, so that shape
// alone no longer discriminates it from plainListValues — the pinned
// difference is descent (and the bare self-repeat skip), see
// TestReaderDifferences17216PinDocClaims. This leaf still needs the
// descending reader.
func Test_6694_FabricMembersEveryFlatSetSpelling(t *testing.T) {
	want := []string{"ge-0/0/7", "ge-7/0/7"}

	assertFabricMembers6694(t, "flat-set repeated",
		fabricMembersFromSet(t,
			"set interfaces fab0 fabric-options member-interfaces ge-0/0/7",
			"set interfaces fab0 fabric-options member-interfaces ge-7/0/7"), want)

	assertFabricMembers6694(t, "flat-set bracket list",
		fabricMembersFromSet(t,
			"set interfaces fab0 fabric-options member-interfaces [ ge-0/0/7 ge-7/0/7 ]"), want)

	// A three-member list keeps all three, so the fix is not a two-element
	// special case.
	assertFabricMembers6694(t, "flat-set bracket list, three members",
		fabricMembersFromSet(t,
			"set interfaces fab0 fabric-options member-interfaces [ ge-0/0/7 ge-7/0/7 ge-1/0/1 ]"),
		[]string{"ge-0/0/7", "ge-7/0/7", "ge-1/0/1"})
}

// Test_6694_FabricMembersDriveBondMode pins the downstream consequence: the
// `len(FabricMembers) > 0` branch that sets BondMode never fired for the
// broken spellings, so the compiled fab0 was not even marked as a bond.
func Test_6694_FabricMembersDriveBondMode(t *testing.T) {
	p := NewParser(`interfaces { fab0 { fabric-options { member-interfaces [ ge-0/0/7 ge-7/0/7 ]; } } }`)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := cfg.Interfaces.Interfaces["fab0"].BondMode; got != "active-backup" {
		t.Errorf("fab0 BondMode = %q, want %q", got, "active-backup")
	}
}
