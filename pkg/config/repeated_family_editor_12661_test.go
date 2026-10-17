package config

import (
	"fmt"
	"testing"
)

// flags12661 composes the #12508 repeated-binding shapes but repeats the
// FAMILY block itself: filter A + sampling input in the first family block,
// filter B + sampling output in the second. The compiler accumulates across
// both (filter last-wins, sampling unions), so on master the editor edits or
// toggles only the first family and B / sampling output stays in force.
var familyShapes12661 = []struct{ name, fams string }{
	{"compound repeats", `
    family %[1]s { address %[2]s; filter { input A; } sampling { input; } }
    family %[1]s { filter { input B; } sampling { output; } }`},
	{"split repeats", `
    family { %[1]s { address %[2]s; filter { input A; } sampling { input; } } }
    family { %[1]s { filter { input B; } sampling { output; } } }`},
	{"mixed shapes", `
    family { %[1]s { address %[2]s; filter { input A; } sampling { input; } } }
    family %[1]s { filter { input B; } sampling { output; } }`},
	{"mixed reversed", `
    family %[1]s { address %[2]s; filter { input A; } sampling { input; } }
    family { %[1]s { filter { input B; } sampling { output; } } }`},
	{"intra-split repeats", `
    family { %[1]s { address %[2]s; filter { input A; } sampling { input; } } %[1]s { filter { input B; } sampling { output; } } }`},
}

func TestSplitOnlyFamilySetStaysInSplit12661(t *testing.T) {
	for _, fam := range []string{"inet", "inet6"} {
		tree := tree12661(t, fam, `family { %[1]s { address %[2]s; filter { input A; } } }`)
		if err := tree.SetPath(path12661(fam, "filter", "input", "C")); err != nil {
			t.Fatalf("%s SetPath: %v", fam, err)
		}
		if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", fam); got != "C" {
			t.Errorf("%s: effective filter = %q, want C", fam, got)
		}
		var unit *Node
		var findUnit func(nodes []*Node)
		findUnit = func(nodes []*Node) {
			for _, n := range nodes {
				if n == nil {
					continue
				}
				if keysEqual(n.Keys, []string{"unit", "0"}) {
					unit = n
					return
				}
				findUnit(n.Children)
				if unit != nil {
					return
				}
			}
		}
		findUnit(tree.Children)
		if unit == nil {
			t.Fatalf("%s: unit not found", fam)
		}
		unitFamilies := 0
		for _, n := range unit.Children {
			if n != nil && len(n.Keys) > 0 && n.Keys[0] == "family" {
				unitFamilies++
			}
		}
		if unitFamilies != 1 {
			t.Errorf("%s: unit has %d family nodes after set, want 1", fam, unitFamilies)
		}
	}
}

func TestSetPathSkipsInactiveSplitFamilyParent12661(t *testing.T) {
	tree := tree12661(t, "inet", `
    family %[1]s { address %[2]s; filter { input A; } }
    inactive: family { %[1]s { filter { input B; } } }`)
	if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != "A" {
		t.Fatalf("control: effective filter = %q, want A", got)
	}
	if err := tree.SetPath(path12661("inet", "filter", "input", "C")); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != "C" {
		t.Fatalf("after set C, effective filter = %q, want C", got)
	}
}

func TestRepeatedSplitFamilyRefusesPartialPackedDelete12661(t *testing.T) {
	tree := tree12661(t, "inet", `
    family { %[1]s { address %[2]s; filter { input A; } } %[1]s { filter input B output C; } }`)
	before := tree.Format()
	if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != "B" {
		t.Fatalf("control: effective filter = %q, want B", got)
	}
	if err := tree.DeletePath(path12661("inet", "filter", "input")); err == nil {
		t.Fatal("DeletePath filter input succeeded despite packed sibling refusal")
	}
	if after := tree.Format(); after != before {
		t.Fatalf("refused delete partially mutated the tree:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != "B" {
		t.Fatalf("after refused delete, effective filter = %q, want unchanged B", got)
	}
}

func tree12661(t *testing.T, family, fams string) *ConfigTree {
	t.Helper()
	addr := "10.0.0.1/24"
	if family == "inet6" {
		addr = "2001:db8::1/64"
	}
	body := fmt.Sprintf(fams, family, addr)
	return hierTree(t, fmt.Sprintf(`interfaces {
    ge-0/0/0 {
        unit 0 {%s
        }
    }
}
firewall {
    family inet { filter A { term t { then accept; } } filter B { term t { then accept; } } filter C { term t { then accept; } } }
    family inet6 { filter A { term t { then accept; } } filter B { term t { then accept; } } filter C { term t { then accept; } } }
}`, body))
}

func path12661(family string, tail ...string) []string {
	return append([]string{"interfaces", "ge-0/0/0", "unit", "0", "family", family}, tail...)
}

// B1: an elided packed sibling is one leaf carrying >1 statement. Mutations
// must refuse atomically rather than silently skip it while a structured
// sibling commits.
func TestElidedPackedFamilySiblingRefuses12661(t *testing.T) {
	build := func(reverse bool) *ConfigTree {
		tr := tree12661(t, "inet", `family { %[1]s { address %[2]s; filter { input A; } } }`)
		var unit *Node
		var find func([]*Node)
		find = func(nodes []*Node) {
			for _, n := range nodes {
				if n == nil {
					continue
				}
				if keysEqual(n.Keys, []string{"unit", "0"}) {
					unit = n
					return
				}
				find(n.Children)
				if unit != nil {
					return
				}
			}
		}
		find(tr.Children)
		packed := &Node{Keys: []string{"family", "inet", "filter", "input", "B", "mtu", "1500"}, IsLeaf: true}
		if reverse {
			unit.Children = append([]*Node{packed}, unit.Children...)
		} else {
			unit.Children = append(unit.Children, packed)
		}
		return tr
	}
	ops := []struct {
		name string
		run  func(*ConfigTree) error
	}{
		{"delete family", func(tr *ConfigTree) error { return tr.DeletePath(path12661("inet")) }},
		{"delete filter input", func(tr *ConfigTree) error { return tr.DeletePath(path12661("inet", "filter", "input")) }},
		{"set filter input C", func(tr *ConfigTree) error { return tr.SetPath(path12661("inet", "filter", "input", "C")) }},
		{"deactivate family", func(tr *ConfigTree) error { return tr.DeactivatePath(path12661("inet")) }},
		{"deactivate filter", func(tr *ConfigTree) error { return tr.DeactivatePath(path12661("inet", "filter")) }},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			tr := build(false)
			before := tr.Format()
			if err := op.run(tr); err == nil {
				t.Fatalf("%s succeeded with elided packed sibling; want refusal", op.name)
			}
			if after := tr.Format(); after != before {
				t.Fatalf("%s mutated tree on refusal:\nbefore:\n%s\nafter:\n%s", op.name, before, after)
			}
		})
	}
	t.Run("elided first", func(t *testing.T) {
		tr := build(true)
		before := tr.Format()
		if err := tr.DeletePath(path12661("inet")); err == nil {
			t.Fatal("delete family succeeded with elided-first packed sibling; want refusal")
		}
		if after := tr.Format(); after != before {
			t.Fatalf("mutated on refusal:\n%s", after)
		}
	})
}

// The split spelling has a second sibling level: a packed `inet ...` leaf
// lives inside `family { ... }`, not beside the unit-level family container.
func TestSplitElidedPackedFamilySiblingRefuses12661(t *testing.T) {
	build := func(packedFamily string) *ConfigTree {
		tr := tree12661(t, "inet", `family { %[1]s { address %[2]s; filter { input A; } } }`)
		var unit, family *Node
		var find func([]*Node)
		find = func(nodes []*Node) {
			for _, n := range nodes {
				if n == nil {
					continue
				}
				if keysEqual(n.Keys, []string{"unit", "0"}) {
					unit = n
					break
				}
				find(n.Children)
				if unit != nil {
					break
				}
			}
		}
		find(tr.Children)
		for _, n := range unit.Children {
			if n != nil && keysEqual(n.Keys, []string{"family"}) {
				family = n
				break
			}
		}
		family.Children = append(family.Children, &Node{
			Keys: []string{packedFamily, "filter", "input", "B", "mtu", "1500"}, IsLeaf: true,
		})
		return tr
	}
	ops := []struct {
		name string
		run  func(*ConfigTree) error
	}{
		{"delete family", func(tr *ConfigTree) error { return tr.DeletePath(path12661("inet")) }},
		{"delete filter input", func(tr *ConfigTree) error { return tr.DeletePath(path12661("inet", "filter", "input")) }},
		{"set filter input C", func(tr *ConfigTree) error { return tr.SetPath(path12661("inet", "filter", "input", "C")) }},
		{"deactivate family", func(tr *ConfigTree) error { return tr.DeactivatePath(path12661("inet")) }},
		{"deactivate filter", func(tr *ConfigTree) error { return tr.DeactivatePath(path12661("inet", "filter")) }},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			tr := build("inet")
			before := tr.Format()
			if err := op.run(tr); err == nil {
				t.Fatalf("%s succeeded with split packed sibling; want refusal", op.name)
			}
			if after := tr.Format(); after != before {
				t.Fatalf("%s mutated split tree on refusal:\nbefore:\n%s\nafter:\n%s", op.name, before, after)
			}
		})
	}
	t.Run("inet6 packed sibling does not block inet set", func(t *testing.T) {
		tr := build("inet6")
		if err := tr.SetPath(path12661("inet", "filter", "input", "C")); err != nil {
			t.Fatalf("SetPath inet beside packed inet6 sibling: %v", err)
		}
		if got := interfaceFilterValue12508(t, tr, "ge-0/0/0", "inet"); got != "C" {
			t.Fatalf("inet filter = %q, want C", got)
		}
	})
}

// B2: refuse repeated family blocks under groups rather than writing a possibly
// shadowed sibling based on a false first-wins premise.
func TestGroupsRepeatedFamilySetRefuses12661(t *testing.T) {
	tree := hierTree(t, `groups {
    G1 {
        interfaces { ge-0/0/0 {
            unit 0 {
                family inet { filter { input A; } }
                family inet { filter { input B; } }
            }
        } }
    }
}
apply-groups G1;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
firewall { family inet { filter A { term t { then accept; } } filter B { term t { then accept; } } filter C { term t { then accept; } } } }`)
	p := []string{"groups", "G1", "interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "filter", "input", "C"}
	before := tree.Format()
	if err := tree.SetPath(p); err == nil {
		t.Fatal("SetPath under groups silently edited one repeated family sibling; want refusal")
	}
	if after := tree.Format(); after != before {
		t.Fatalf("refused groups set mutated tree:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestRepeatedFamilyEditor12661(t *testing.T) {
	for _, fam := range []string{"inet", "inet6"} {
		for _, shape := range familyShapes12661 {
			t.Run(fam+"/"+shape.name+"/set", func(t *testing.T) {
				tree := tree12661(t, fam, shape.fams)
				if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", fam); got != "B" {
					t.Fatalf("control: effective filter = %q, want B", got)
				}
				if err := tree.SetPath(path12661(fam, "filter", "input", "C")); err != nil {
					t.Fatalf("SetPath: %v", err)
				}
				if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", fam); got != "C" {
					t.Errorf("after set C, effective filter = %q, want C (stale sibling in force)", got)
				}
			})
			t.Run(fam+"/"+shape.name+"/set-sampling", func(t *testing.T) {
				tree := tree12661(t, fam, shape.fams)
				if err := tree.SetPath(path12661(fam, "sampling", "output")); err != nil {
					t.Fatalf("SetPath: %v", err)
				}
				unit := compileInterfaceUnit12508(t, tree, "ge-0/0/0", fam)
				if sIn, sOut := samplingPair12508(unit, fam); !sIn || !sOut {
					t.Errorf("after set sampling output = %v/%v, want true/true", sIn, sOut)
				} else if oIn, oOut := otherSamplingPair12508(unit, fam); oIn || oOut {
					t.Errorf("other-family sampling leaked: %v/%v", oIn, oOut)
				}
			})
			for _, op := range []struct {
				name       string
				run        func(*ConfigTree, []string) error
				path       []string
				what       string
				wantSample func(*InterfaceUnit) bool
			}{
				{"delete filter", (*ConfigTree).DeletePath, []string{"filter"}, "filter after delete", nil},
				{"delete filter input", (*ConfigTree).DeletePath, []string{"filter", "input"}, "filter after delete input", nil},
				{"deactivate filter", (*ConfigTree).DeactivatePath, []string{"filter"}, "filter after deactivate", nil},
				{"deactivate filter input", (*ConfigTree).DeactivatePath, []string{"filter", "input"}, "filter after deactivate input", nil},
				{"delete sampling", (*ConfigTree).DeletePath, []string{"sampling"}, "sampling after delete", func(u *InterfaceUnit) bool { in, out := samplingPair12508(u, fam); return !in && !out }},
				{"deactivate sampling", (*ConfigTree).DeactivatePath, []string{"sampling"}, "sampling after deactivate", func(u *InterfaceUnit) bool { in, out := samplingPair12508(u, fam); return !in && !out }},
				{"delete sampling output", (*ConfigTree).DeletePath, []string{"sampling", "output"}, "sampling after delete output", func(u *InterfaceUnit) bool { in, out := samplingPair12508(u, fam); return in && !out }},
				{"deactivate sampling output", (*ConfigTree).DeactivatePath, []string{"sampling", "output"}, "sampling after deactivate output", func(u *InterfaceUnit) bool { in, out := samplingPair12508(u, fam); return in && !out }},
				{"delete family", (*ConfigTree).DeletePath, nil, "filter after delete family", func(u *InterfaceUnit) bool { in, out := samplingPair12508(u, fam); return !in && !out }},
				{"deactivate family", (*ConfigTree).DeactivatePath, nil, "filter after deactivate family", func(u *InterfaceUnit) bool { in, out := samplingPair12508(u, fam); return !in && !out }},
			} {
				t.Run(fam+"/"+shape.name+"/"+op.name, func(t *testing.T) {
					tree := tree12661(t, fam, shape.fams)
					p := path12661(fam, op.path...)
					if op.path == nil {
						p = path12661(fam)
					}
					if err := op.run(tree, p); err != nil {
						t.Fatalf("%s: %v", op.name, err)
					}
					unit := compileInterfaceUnit12508(t, tree, "ge-0/0/0", fam)
					if op.what == "filter after delete" || op.what == "filter after delete input" || op.what == "filter after deactivate" || op.what == "filter after deactivate input" || op.what == "filter after delete family" || op.what == "filter after deactivate family" {
						got := unit.FilterInputV4
						if fam == "inet6" {
							got = unit.FilterInputV6
						}
						if got != "" {
							t.Errorf("%s = %q, want \"\" (stale sibling in force)", op.what, got)
						}
					}
					if op.wantSample != nil && !op.wantSample(unit) {
						func() {
							sIn, sOut := samplingPair12508(unit, fam)
							t.Errorf("%s: samplingInput=%v samplingOutput=%v, stale sibling remains active", op.what, sIn, sOut)
						}()
					}
				})
			}
		}
	}
}
