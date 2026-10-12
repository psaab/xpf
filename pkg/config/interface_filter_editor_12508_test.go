package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestInterfaceFilterEditorLastWins12508(t *testing.T) {
	shapes := []struct {
		name     string
		bindings string
	}{
		{"hierarchical repeats", `filter { input A; } filter { input B; }`},
		{"compact repeats", `filter input A; filter input B;`},
		{"compact then block", `filter input A; filter { input B; }`},
		{"block then compact", `filter { input A; } filter input B;`},
	}
	for _, family := range []string{"inet", "inet6"} {
		for _, shape := range shapes {
			family, shape := family, shape
			t.Run(family+"/"+shape.name, func(t *testing.T) {
				tree := interfaceFilterTree12508(t, "ge-0/0/0", family, shape.bindings)
				if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", family); got != "B" {
					t.Fatalf("initial effective filter = %q, want last sibling B", got)
				}
				if err := tree.SetPath([]string{
					"interfaces", "ge-0/0/0", "unit", "0", "family", family, "filter", "input", "C",
				}); err != nil {
					t.Fatalf("SetPath filter input C: %v", err)
				}
				if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", family); got != "C" {
					t.Fatalf("effective filter after set = %q, want C", got)
				}
			})
		}
	}
}

func TestInterfaceFilterEditorDeleteAndDeactivate12508(t *testing.T) {
	shapes := []struct {
		name     string
		bindings string
	}{
		{"hierarchical repeats", `filter { input A; } filter { input B; }`},
		{"compact repeats", `filter input A; filter input B;`},
		{"compact then block", `filter input A; filter { input B; }`},
		{"block then compact", `filter { input A; } filter input B;`},
	}
	operations := []struct {
		name                                  string
		path                                  []string
		run                                   func(*ConfigTree, []string) error
		wantFilter                            string
		wantSamplingInput, wantSamplingOutput bool
	}{
		{"delete filter", []string{"filter"}, (*ConfigTree).DeletePath, "", true, true},
		{"delete filter input", []string{"filter", "input"}, (*ConfigTree).DeletePath, "", true, true},
		{"deactivate filter", []string{"filter"}, (*ConfigTree).DeactivatePath, "", true, true},
		{"deactivate filter input", []string{"filter", "input"}, (*ConfigTree).DeactivatePath, "", true, true},
		{"delete sampling", []string{"sampling"}, (*ConfigTree).DeletePath, "B", false, false},
		{"delete sampling output", []string{"sampling", "output"}, (*ConfigTree).DeletePath, "B", true, false},
		{"deactivate sampling", []string{"sampling"}, (*ConfigTree).DeactivatePath, "B", false, false},
		{"deactivate sampling output", []string{"sampling", "output"}, (*ConfigTree).DeactivatePath, "B", true, false},
	}
	for _, family := range []string{"inet", "inet6"} {
		for _, shape := range shapes {
			for _, operation := range operations {
				family, shape, operation := family, shape, operation
				t.Run(family+"/"+shape.name+"/"+operation.name, func(t *testing.T) {
					bindings := shape.bindings + ` sampling { input; } sampling { output; }`
					tree := interfaceFilterTree12508(t, "ge-0/0/0", family, bindings)
					unit := compileInterfaceUnit12508(t, tree, "ge-0/0/0", family)
					if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", family); got != "B" ||
						!unit.SamplingInput || !unit.SamplingOutput {
						t.Fatalf("initial bindings = filter:%q sample:%v/%v, want B/true/true",
							got, unit.SamplingInput, unit.SamplingOutput)
					}
					path := append([]string{
						"interfaces", "ge-0/0/0", "unit", "0", "family", family,
					}, operation.path...)
					if err := operation.run(tree, path); err != nil {
						t.Fatalf("%s: %v", operation.name, err)
					}
					unit = compileInterfaceUnit12508(t, tree, "ge-0/0/0", family)
					if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", family); got != operation.wantFilter {
						t.Errorf("effective filter after %s = %q, want %q",
							operation.name, got, operation.wantFilter)
					}
					if unit.SamplingInput != operation.wantSamplingInput ||
						unit.SamplingOutput != operation.wantSamplingOutput {
						t.Errorf("sampling after %s = input:%v output:%v, want %v/%v",
							operation.name, unit.SamplingInput, unit.SamplingOutput,
							operation.wantSamplingInput, operation.wantSamplingOutput)
					}
				})
			}
		}
	}
}

func TestInterfaceSamplingEditorTargetsCompilerVisibleSiblings12508(t *testing.T) {
	tree := interfaceFilterTree12508(t, "ge-0/0/0", "inet",
		`sampling { input; } sampling { }`)
	if err := tree.SetPath([]string{
		"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "sampling", "output",
	}); err != nil {
		t.Fatalf("SetPath sampling output: %v", err)
	}
	unit := compileInterfaceUnit12508(t, tree, "ge-0/0/0", "inet")
	if !unit.SamplingInput || !unit.SamplingOutput {
		t.Fatalf("sampling after set = input:%v output:%v, want both true", unit.SamplingInput, unit.SamplingOutput)
	}

	family := interfaceFamilyNode12508(tree, "ge-0/0/0", "inet")
	if family == nil {
		t.Fatal("interface family node missing after SetPath")
	}
	siblings := family.FindChildren("sampling")
	if len(siblings) != 2 || siblings[0].FindChild("output") != nil || siblings[1].FindChild("output") == nil {
		t.Fatalf("set did not target the last sampling sibling: %#v", siblings)
	}

	path := []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "sampling", "output"}
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("DeletePath sampling output in later sibling: %v", err)
	}
	unit = compileInterfaceUnit12508(t, tree, "ge-0/0/0", "inet")
	if !unit.SamplingInput || unit.SamplingOutput {
		t.Fatalf("sampling after targeted delete = input:%v output:%v, want true/false", unit.SamplingInput, unit.SamplingOutput)
	}

	path = path[:len(path)-1]
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("DeletePath sampling: %v", err)
	}
	unit = compileInterfaceUnit12508(t, tree, "ge-0/0/0", "inet")
	if unit.SamplingInput || unit.SamplingOutput {
		t.Fatalf("sampling after container delete = input:%v output:%v, want both false", unit.SamplingInput, unit.SamplingOutput)
	}
}

func TestInterfaceSamplingDeactivateAllSiblings12508(t *testing.T) {
	tree := interfaceFilterTree12508(t, "ge-0/0/0", "inet",
		`sampling { input; } sampling { output; }`)
	path := []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "sampling"}
	if err := tree.DeactivatePath(path); err != nil {
		t.Fatalf("DeactivatePath sampling: %v", err)
	}
	unit := compileInterfaceUnit12508(t, tree, "ge-0/0/0", "inet")
	if unit.SamplingInput || unit.SamplingOutput {
		t.Fatalf("sampling after deactivate = input:%v output:%v, want both false", unit.SamplingInput, unit.SamplingOutput)
	}
	if err := tree.ActivatePath(path); err != nil {
		t.Fatalf("ActivatePath sampling: %v", err)
	}
	unit = compileInterfaceUnit12508(t, tree, "ge-0/0/0", "inet")
	if !unit.SamplingInput || !unit.SamplingOutput {
		t.Fatalf("sampling after activate = input:%v output:%v, want both true", unit.SamplingInput, unit.SamplingOutput)
	}
}

func TestInterfaceSamplingDeactivateTargetedSibling12508(t *testing.T) {
	tree := interfaceFilterTree12508(t, "ge-0/0/0", "inet",
		`sampling { input; } sampling { output; }`)
	path := []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "sampling", "output"}
	if err := tree.DeactivatePath(path); err != nil {
		t.Fatalf("DeactivatePath sampling output in later sibling: %v", err)
	}
	unit := compileInterfaceUnit12508(t, tree, "ge-0/0/0", "inet")
	if !unit.SamplingInput || unit.SamplingOutput {
		t.Fatalf("sampling after targeted deactivate = input:%v output:%v, want true/false",
			unit.SamplingInput, unit.SamplingOutput)
	}
}

func TestInterfaceFilterLo0Consolidation12508(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		t.Run(family, func(t *testing.T) {
			tree := interfaceFilterTree12508(t, "lo0", family,
				`filter { input A; } filter { input B; }`)
			filterPath := []string{"interfaces", "lo0", "unit", "0", "family", family, "filter"}
			if got := interfaceFilterValue12508(t, tree, "lo0", family); got != "B" {
				t.Fatalf("initial lo0 %s filter input = %q, want B", family, got)
			}
			if err := tree.DeletePath(filterPath); err != nil {
				t.Fatalf("DeletePath lo0 filter: %v", err)
			}
			afterDelete, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig after lo0 delete: %v", err)
			}
			deletedBinding := afterDelete.System.Lo0FilterInputV4
			if family == "inet6" {
				deletedBinding = afterDelete.System.Lo0FilterInputV6
			}
			if deletedBinding != "" {
				t.Fatalf("compiled lo0 %s filter after delete = %q, want empty", family, deletedBinding)
			}
			setPath := append(append([]string(nil), filterPath...), "input", "C")
			if err := tree.SetPath(setPath); err != nil {
				t.Fatalf("SetPath lo0 filter input C: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig lo0: %v", err)
			}
			got := cfg.System.Lo0FilterInputV4
			if family == "inet6" {
				got = cfg.System.Lo0FilterInputV6
			}
			if got != "C" {
				t.Fatalf("compiled lo0 %s filter input = %q, want C", family, got)
			}
			familyNode := interfaceFamilyNode12508(tree, "lo0", family)
			filters := familyNode.FindChildren("filter")
			if len(filters) != 1 || filters[0].FindChild("input") == nil ||
				nodeVal(filters[0].FindChild("input")) != "C" {
				t.Fatalf("lo0 %s filter was not consolidated to one input C sibling: %#v",
					family, filters)
			}
		})
	}
}
func TestInterfaceFilterGroupsEditorPreservesFirstCompilerSibling12508(t *testing.T) {
	shapes := []struct {
		name, bindings string
	}{
		{"hierarchical repeats", `filter { input A; } filter { input B; }`},
		{"block then compact", `filter { input A; } filter input B;`},
	}
	operations := []struct {
		name, want string
		run        func(*ConfigTree, []string) error
	}{
		{"set", "C", func(tree *ConfigTree, path []string) error {
			return tree.SetPath(append(path, "input", "C"))
		}},
		{"delete", "", (*ConfigTree).DeletePath},
		{"deactivate", "", (*ConfigTree).DeactivatePath},
	}
	for _, shape := range shapes {
		for _, operation := range operations {
			shape, operation := shape, operation
			t.Run(shape.name+"/"+operation.name, func(t *testing.T) {
				tree := interfaceFilterGroupsTree12508(t, "inet", shape.bindings)
				if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != "A" {
					t.Fatalf("initial group filter = %q, want first sibling A", got)
				}
				path := []string{
					"groups", "G", "interfaces", "<*>", "unit", "<*>", "family", "inet", "filter",
				}
				if err := operation.run(tree, path); err != nil {
					t.Fatalf("%s group filter: %v", operation.name, err)
				}
				if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != operation.want {
					t.Fatalf("effective group filter after %s = %q, want %q",
						operation.name, got, operation.want)
				}
			})
		}
	}
}

func interfaceFilterGroupsTree12508(t *testing.T, family, bindings string) *ConfigTree {
	t.Helper()
	address := "10.0.0.1/24"
	if family == "inet6" {
		address = "2001:db8::1/64"
	}
	return hierTree(t, fmt.Sprintf(`groups {
    G {
        interfaces {
            <*> {
                unit <*> {
                    family %s { %s }
                }
            }
        }
    }
}
apply-groups G;
interfaces {
    ge-0/0/0 {
        unit 0 {
            family %s { address %s; }
        }
    }
}
firewall {
    family inet {
        filter A { term t { then accept; } }
        filter B { term t { then accept; } }
        filter C { term t { then accept; } }
    }
    family inet6 {
        filter A { term t { then accept; } }
        filter B { term t { then accept; } }
        filter C { term t { then accept; } }
    }
}`, family, bindings, family, address))
}

func TestInterfaceFilterSetIntoInactiveKeepsLo0Disabled12508(t *testing.T) {
	tree := interfaceFilterTree12508(t, "lo0", "inet", `filter { input A; }`)
	filterPath := []string{"interfaces", "lo0", "unit", "0", "family", "inet", "filter"}
	if err := tree.DeactivatePath(filterPath); err != nil {
		t.Fatalf("DeactivatePath filter: %v", err)
	}
	if err := tree.SetPath(append(append([]string(nil), filterPath...), "input", "C")); err != nil {
		t.Fatalf("SetPath filter input C: %v", err)
	}
	filters := interfaceFamilyNode12508(tree, "lo0", "inet").FindChildren("filter")
	if len(filters) != 1 {
		t.Fatalf("set did not preserve one inactive filter: %#v", filters)
	}
	input := filters[0].FindChild("input")
	if !filters[0].Inactive || input == nil || nodeVal(input) != "C" {
		t.Fatalf("set did not update the sole inactive filter: %#v", filters)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig lo0: %v", err)
	}
	if cfg.System.Lo0FilterInputV4 != "" {
		t.Fatalf("compiled lo0 filter after edit = %q, want deactivated filter off", cfg.System.Lo0FilterInputV4)
	}
}
func TestInterfaceFilterSetIntoInactiveCompactKeepsLo0Disabled12508(t *testing.T) {
	tree := interfaceFilterTree12508(t, "lo0", "inet", `filter input A;`)
	path := []string{"interfaces", "lo0", "unit", "0", "family", "inet", "filter"}
	if err := tree.DeactivatePath(path); err != nil {
		t.Fatalf("DeactivatePath compact filter: %v", err)
	}
	if err := tree.SetPath(append(append([]string(nil), path...), "input", "C")); err != nil {
		t.Fatalf("SetPath compact filter input C: %v", err)
	}
	filters := interfaceFamilyNode12508(tree, "lo0", "inet").FindChildren("filter")
	if len(filters) != 1 {
		t.Fatalf("set did not preserve one compact inactive filter: %#v", filters)
	}
	input := filters[0].FindChild("input")
	if !filters[0].Inactive || input == nil || nodeVal(input) != "C" {
		t.Fatalf("set did not replace the compact inactive filter: %#v", filters)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig compact lo0: %v", err)
	}
	if cfg.System.Lo0FilterInputV4 != "" {
		t.Fatalf("compiled lo0 compact filter after edit = %q, want empty", cfg.System.Lo0FilterInputV4)
	}
}

func TestInterfaceSamplingSetIntoInactiveStaysInactive12508(t *testing.T) {
	tree := interfaceFilterTree12508(t, "ge-0/0/0", "inet", `sampling input;`)
	path := []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "sampling"}
	if err := tree.DeactivatePath(path); err != nil {
		t.Fatalf("DeactivatePath sampling: %v", err)
	}
	if err := tree.SetPath(append(append([]string(nil), path...), "output")); err != nil {
		t.Fatalf("SetPath sampling output: %v", err)
	}
	siblings := interfaceFamilyNode12508(tree, "ge-0/0/0", "inet").FindChildren("sampling")
	if len(siblings) != 1 || !siblings[0].Inactive || siblings[0].FindChild("output") == nil {
		t.Fatalf("set did not update the sole inactive sampling statement: %#v", siblings)
	}
	unit := compileInterfaceUnit12508(t, tree, "ge-0/0/0", "inet")
	if unit.SamplingInput || unit.SamplingOutput {
		t.Fatalf("sampling after set into inactive statement = %v/%v, want off",
			unit.SamplingInput, unit.SamplingOutput)
	}
}

func TestInterfaceFilterActivateTargetedValue12508(t *testing.T) {
	tree := interfaceFilterTree12508(t, "ge-0/0/0", "inet",
		`filter { input A; } filter { input B; }`)
	path := []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "filter", "input", "B"}
	if err := tree.DeactivatePath(path); err != nil {
		t.Fatalf("DeactivatePath targeted filter input B: %v", err)
	}
	if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != "A" {
		t.Fatalf("effective filter after targeted deactivate = %q, want A", got)
	}
	if err := tree.ActivatePath(path); err != nil {
		t.Fatalf("ActivatePath targeted filter input B: %v", err)
	}
	if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", "inet"); got != "B" {
		t.Fatalf("effective filter after targeted activate = %q, want B", got)
	}
}

func TestInterfaceFilterDeleteTargetedValueExposesEarlierSibling12508(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		t.Run(family, func(t *testing.T) {
			tree := interfaceFilterTree12508(t, "ge-0/0/0", family,
				`filter { input A; } filter { input B; }`)
			path := []string{
				"interfaces", "ge-0/0/0", "unit", "0", "family", family,
				"filter", "input", "B",
			}
			if err := tree.DeletePath(path); err != nil {
				t.Fatalf("DeletePath targeted filter input B: %v", err)
			}
			if got := interfaceFilterValue12508(t, tree, "ge-0/0/0", family); got != "A" {
				t.Fatalf("effective filter after deleting later value B = %q, want earlier value A", got)
			}
		})
	}
}

func interfaceFilterTree12508(t *testing.T, iface, family, bindings string) *ConfigTree {
	t.Helper()
	address := "10.0.0.1/24"
	if family == "inet6" {
		address = "2001:db8::1/64"
	}
	return hierTree(t, fmt.Sprintf(`interfaces {
    %s {
        unit 0 {
            family %s {
                address %s;
                %s
            }
        }
    }
}
firewall {
    family inet {
        filter A { term t { then accept; } }
        filter B { term t { then accept; } }
        filter C { term t { then accept; } }
    }
    family inet6 {
        filter A { term t { then accept; } }
        filter B { term t { then accept; } }
        filter C { term t { then accept; } }
    }
}`, iface, family, address, bindings))
}

func interfaceFilterValue12508(t *testing.T, tree *ConfigTree, iface, family string) string {
	t.Helper()
	unit := compileInterfaceUnit12508(t, tree, iface, family)
	if family == "inet6" {
		return unit.FilterInputV6
	}
	return unit.FilterInputV4
}

func compileInterfaceUnit12508(t *testing.T, tree *ConfigTree, ifaceName, family string) *InterfaceUnit {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	iface := cfg.Interfaces.Interfaces[ifaceName]
	if iface == nil || len(iface.Units) != 1 || iface.Units[0] == nil {
		t.Fatalf("compiled interface %q has no unit 0: %#v", ifaceName, iface)
	}
	return iface.Units[0]
}

func interfaceFamilyNode12508(tree *ConfigTree, ifaceName, family string) *Node {
	interfaces := tree.FindChild("interfaces")
	if interfaces == nil {
		return nil
	}
	iface := interfaces.FindChild(ifaceName)
	if iface == nil {
		return nil
	}
	unit := iface.FindChild("unit")
	if unit == nil {
		return nil
	}
	for _, familyNode := range unit.FindChildren("family") {
		if len(familyNode.Keys) > 1 && familyNode.Keys[1] == family {
			return familyNode
		}
		if len(familyNode.Keys) == 1 {
			if af := familyNode.FindChild(family); af != nil {
				return af
			}
		}
	}
	return nil
}
func TestInterfaceFilterSamplingDeleteRejectsPackedStatements12508(t *testing.T) {
	tests := []struct {
		name, bindings string
		path           []string
	}{
		{"filter", `filter input A output B;`, []string{"filter", "input"}},
		{"sampling", `sampling input output;`, []string{"sampling", "input"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			tree := interfaceFilterTree12508(t, "ge-0/0/0", "inet", test.bindings)
			before := tree.Format()
			path := append([]string{
				"interfaces", "ge-0/0/0", "unit", "0", "family", "inet",
			}, test.path...)
			err := tree.DeletePath(path)
			if err == nil || !strings.Contains(err.Error(), "#8992") {
				t.Fatalf("packed delete error = %v, want #8992 refusal", err)
			}
			if got := tree.Format(); got != before {
				t.Fatalf("refused packed delete changed the tree:\nbefore:\n%s\nafter:\n%s", before, got)
			}
		})
	}
}
