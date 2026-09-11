package config

import (
	"strings"
	"testing"
)

// #9627: a self-repeating multi-value run inherited from a group reached the
// #9027 gate only when no inline leaf of the same name existed. The leaf-list
// union read the group's members through firewallMatchValues, which drops a
// repeat of the leaf's own keyword, so an inline leaf made the ambiguity vanish
// before the gate could see it.

const selfRepeatRefusal9627 = "repeats its own keyword"

func groupUnionText9627(groupExport, inlineExport string) string {
	var b strings.Builder
	b.WriteString(`routing-options { autonomous-system 65001; }
policy-options {
    policy-statement A { then accept; }
    policy-statement B { then accept; }
    policy-statement export { then accept; }
}
`)
	if groupExport != "" {
		b.WriteString("groups { gg { protocols { bgp { group g1 { export " + groupExport + "; } } } } }\napply-groups gg;\n")
	}
	b.WriteString("protocols { bgp { group g1 { type external; peer-as 65002; neighbor 192.0.2.1;")
	if inlineExport != "" {
		b.WriteString(" export " + inlineExport + ";")
	}
	b.WriteString(" } } }\n")
	return b.String()
}

func TestGroupInheritedSelfRepeatIsRefusedBesideAnInlineLeaf9627(t *testing.T) {
	for _, tc := range []struct {
		name, group, inline string
		wantRefuse          bool
	}{
		{"inline run (control)", "", "[ A export B ]", true},
		{"group run, no inline leaf (control)", "[ A export ]", "", true},
		{"group run beside an inline leaf (the gap)", "[ A export ]", "B", true},
		{"quoted repeat beside an inline leaf is a value", `[ A "export" ]`, "B", false},
		{"no repeat at all (control)", "[ A ]", "B", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(selfRepeatTree9027(t, groupUnionText9627(tc.group, tc.inline)))
			refused := err != nil && strings.Contains(err.Error(), selfRepeatRefusal9627)
			if refused != tc.wantRefuse {
				t.Fatalf("refused by #9027 = %v, want %v (err: %v)", refused, tc.wantRefuse, err)
			}
			if !tc.wantRefuse && err != nil {
				t.Fatalf("an unambiguous config must compile, got: %v", err)
			}
		})
	}
}

func TestGroupInheritedSelfRepeatWarnsLeniently9627(t *testing.T) {
	cfg, err := CompileConfigLenient(selfRepeatTree9027(t, groupUnionText9627("[ A export ]", "B")))
	if err != nil {
		t.Fatalf("the lenient path must load the config: %v", err)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), selfRepeatRefusal9627) {
		t.Fatalf("the lenient path must warn about the inherited self-repeat, got: %v", cfg.Warnings)
	}
}

func TestQuotedInheritedSelfNamedValueSurvivesTheUnion9627(t *testing.T) {
	tr := selfRepeatTree9027(t, groupUnionText9627(`[ A "export" ]`, "B"))
	if err := tr.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	var export *Node
	for _, p := range tr.Children {
		if len(p.Keys) == 0 || p.Keys[0] != "protocols" {
			continue
		}
		for _, bgp := range p.Children {
			for _, g := range bgp.Children {
				for _, leaf := range g.Children {
					if len(leaf.Keys) > 0 && leaf.Keys[0] == "export" {
						export = leaf
					}
				}
			}
		}
	}
	if export == nil {
		t.Fatal("premise: the merged export leaf was not found")
	}
	found := false
	for i := 1; i < len(export.Keys); i++ {
		if export.Keys[i] == "export" {
			found = true
			if !export.KeyQuoted(i) {
				t.Fatalf("the inherited quoted value lost its quote in the union: %v %v", export.Keys, export.KeysQuoted)
			}
		}
	}
	if !found {
		t.Fatalf("the union silently dropped the quoted value named `export`: %v", export.Keys)
	}
	if export.KeysQuoted != nil && len(export.KeysQuoted) != len(export.Keys) {
		t.Fatalf("quote mask %v breaks the one-bit-per-key invariant for %v", export.KeysQuoted, export.Keys)
	}
}

func TestUnionCarriesTheSelfRepeatOntoABlockFormLeaf9627(t *testing.T) {
	dst := &Node{Keys: []string{"export"}, Children: []*Node{{Keys: []string{"B"}, IsLeaf: true}}}
	src := &Node{Keys: []string{"export", "A", "export"}, IsLeaf: true}
	mergeLeafListInto(dst, src)
	carried := false
	for _, k := range dst.Keys[1:] {
		if k == "export" {
			carried = true
		}
	}
	if !carried {
		t.Fatalf("a block-form inline leaf hid the inherited self-repeat from the #9027 gate: keys %v", dst.Keys)
	}
	if len(dst.Children) != 2 || dst.Children[1].Keys[0] != "A" {
		t.Fatalf("the ordinary member must still join as a child leaf: %+v", dst.Children)
	}
}
