package config

import (
	"reflect"
	"testing"
)

// #16541: a group leaf-list member was spliced into the FIRST of several
// same-key inline statements. Inline BGP export written as two `set` lines
// `a`, `b` plus group `c` compiled as [a c b] — neither union-append
// [a b c] nor override [a b] — because leafListPeer returned the first
// sibling and mergeLeafListInto computed `seen` from that node alone.
// Ordered policy chains (#5277, first terminal wins) then evaluated the
// template policy ahead of later inline policies. The fix deduplicates
// over ALL same-key siblings and appends new group members to the LAST.
//
// TestVA03ExportOrder is the acceptance test named by the issue: all
// three inline spellings give [a b c], a group member equal to a later
// inline member is not duplicated, and the sibling spelling matches the
// bracket spelling as a control.

func va03Policies16541() []string {
	return []string{
		"set policy-options policy-statement a term t then accept",
		"set policy-options policy-statement b term t then accept",
		"set policy-options policy-statement c term t then accept",
	}
}

func TestVA03ExportOrder(t *testing.T) {
	base := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ext neighbor 192.0.2.1 peer-as 65002",
	}
	groupC := []string{
		"set groups G protocols bgp group ext export c",
		"set apply-groups G",
	}
	withPolicies := func(cmds []string) []string {
		return append(append([]string(nil), cmds...), va03Policies16541()...)
	}

	t.Run("two set lines plus group", func(t *testing.T) {
		cmds := append(append([]string(nil), base...),
			"set protocols bgp group ext export a",
			"set protocols bgp group ext export b")
		cmds = append(cmds, groupC...)
		cfg, err := compileSet(t, withPolicies(cmds))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got, want := bgpNeighbor(t, cfg, "192.0.2.1").Export, []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Export = %v, want %v (group member spliced into first sibling gives [a c b])", got, want)
		}
	})

	t.Run("bracket inline plus group control", func(t *testing.T) {
		cmds := append(append([]string(nil), base...),
			"set protocols bgp group ext export [ a b ]")
		cmds = append(cmds, groupC...)
		cfg, err := compileSet(t, withPolicies(cmds))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got, want := bgpNeighbor(t, cfg, "192.0.2.1").Export, []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Export = %v, want %v (bracket control)", got, want)
		}
	})

	t.Run("block inline plus group", func(t *testing.T) {
		src := `protocols {
    bgp {
        local-as 65001;
        group ext {
            neighbor 192.0.2.1 { peer-as 65002; }
            export { a; b; }
        }
    }
}
groups { G { protocols { bgp { group ext { export c; } } } } }
apply-groups G;
policy-options {
    policy-statement a { term t { then accept; } }
    policy-statement b { term t { then accept; } }
    policy-statement c { term t { then accept; } }
}`
		cfg := mustCompile(t, src)
		if got, want := bgpNeighbor(t, cfg, "192.0.2.1").Export, []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Export = %v, want %v (block control)", got, want)
		}
	})

	t.Run("hierarchical two leaves plus group", func(t *testing.T) {
		src := `protocols {
    bgp {
        local-as 65001;
        group ext {
            neighbor 192.0.2.1 { peer-as 65002; }
            export a;
            export b;
        }
    }
}
groups { G { protocols { bgp { group ext { export c; } } } } }
apply-groups G;
policy-options {
    policy-statement a { term t { then accept; } }
    policy-statement b { term t { then accept; } }
    policy-statement c { term t { then accept; } }
}`
		cfg := mustCompile(t, src)
		if got, want := bgpNeighbor(t, cfg, "192.0.2.1").Export, []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Export = %v, want %v (hierarchical sibling leaves)", got, want)
		}
	})

	t.Run("group member equal to later inline member not duplicated", func(t *testing.T) {
		cmds := append(append([]string(nil), base...),
			"set protocols bgp group ext export a",
			"set protocols bgp group ext export b",
			"set groups G protocols bgp group ext export b",
			"set apply-groups G")
		cfg, err := compileSet(t, withPolicies(cmds))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got, want := bgpNeighbor(t, cfg, "192.0.2.1").Export, []string{"a", "b"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Export = %v, want %v (later inline member duplicated as [a b b])", got, want)
		}
	})

	t.Run("no group control", func(t *testing.T) {
		cmds := append(append([]string(nil), base...),
			"set protocols bgp group ext export a",
			"set protocols bgp group ext export b")
		cfg, err := compileSet(t, withPolicies(cmds))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got, want := bgpNeighbor(t, cfg, "192.0.2.1").Export, []string{"a", "b"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Export = %v, want %v (no-group control)", got, want)
		}
	})

	t.Run("import symmetric", func(t *testing.T) {
		cmds := append(append([]string(nil), base...),
			"set protocols bgp group ext import a",
			"set protocols bgp group ext import b")
		cmds = append(cmds,
			"set groups G protocols bgp group ext import c",
			"set apply-groups G")
		cfg, err := compileSet(t, withPolicies(cmds))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got, want := bgpNeighbor(t, cfg, "192.0.2.1").Import, []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Import = %v, want %v", got, want)
		}
	})
}

// TestGroupLeafListSiblingUnionNameServer16541 proves the fix is in the
// shared leaf-list union, not a BGP special case: repeated flat-set
// name-server statements keep group members after every inline member.
func TestGroupLeafListSiblingUnionNameServer16541(t *testing.T) {
	cmds := []string{
		"set groups g system name-server 9.9.9.9",
		"set apply-groups g",
		"set system name-server 1.1.1.1",
		"set system name-server 2.2.2.2",
	}
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got, want := cfg.System.NameServers, []string{"1.1.1.1", "2.2.2.2", "9.9.9.9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("NameServers = %v, want %v (spliced union gives [1.1.1.1 9.9.9.9 2.2.2.2])", got, want)
	}
}

// TestMergeLeafListIntoSiblings16541 pins the sibling union directly,
// including the mixed shape (collapsed sibling + block sibling) and the
// per-sibling #9862 bookkeeping staying aligned for later filtering.
func TestMergeLeafListIntoSiblings16541(t *testing.T) {
	first := &Node{Keys: []string{"export", "a"}, IsLeaf: true}
	last := &Node{Keys: []string{"export"}, Children: []*Node{
		{Keys: []string{"b"}, IsLeaf: true},
	}}
	src := &Node{Keys: []string{"export", "b", "c"}, IsLeaf: true}
	mergeLeafListIntoSiblings16541([]*Node{first, last}, src)

	if got := firewallMatchValues(first); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("first sibling = %v, want [a] (group members must not splice here)", got)
	}
	if got := firewallMatchValues(last); !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Fatalf("last sibling = %v, want [b c] (dup b skipped, new c appended)", got)
	}
	var order []string
	for _, n := range []*Node{first, last} {
		order = append(order, firewallMatchValues(n)...)
	}
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("sibling order = %v, want %v", order, want)
	}
	for _, p := range []*Node{first, last} {
		if members := leafListMemberGroupsForNode9862(p); len(members) != len(leafListMembers9627(p)) {
			t.Fatalf("sibling %v member provenance misaligned: %d groups vs %d members", p.Keys, len(members), len(leafListMembers9627(p)))
		}
	}
}

// TestMergeLeafListIntoSiblingsCarriesSelfRepeat16541 pins that the
// multi-sibling union does not hide the #9627 bare self-repeat from the
// #9027 gate: the repeat is carried onto the last sibling exactly as
// mergeLeafListInto carries it onto a single target.
func TestMergeLeafListIntoSiblingsCarriesSelfRepeat16541(t *testing.T) {
	first := &Node{Keys: []string{"export", "A"}, IsLeaf: true}
	last := &Node{Keys: []string{"export", "B"}, IsLeaf: true}
	src := &Node{Keys: []string{"export", "C", "export"}, IsLeaf: true}
	mergeLeafListIntoSiblings16541([]*Node{first, last}, src)

	if got := firewallMatchValues(first); len(got) != 1 || got[0] != "A" {
		t.Fatalf("first sibling = %v, want [A]", got)
	}
	carried := false
	for _, k := range last.Keys[1:] {
		if k == "export" {
			carried = true
		}
	}
	if !carried {
		t.Fatalf("multi-sibling union hid the inherited self-repeat: last keys %v", last.Keys)
	}
	if got := firewallMatchValues(last); len(got) != 2 || got[0] != "B" || got[1] != "C" {
		t.Fatalf("last sibling values = %v, want [B C] (plus the carried repeat on Keys)", got)
	}
}
