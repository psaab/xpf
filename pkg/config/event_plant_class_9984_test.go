package config

import (
	"testing"
)

// flatPolicyTree9984 builds the FLAT-set AST shape for an event-options policy:
// `commands` files as Keys=["commands"] with the command in a child leaf (not
// on the tail). Every SetFromInput mutation in the store produces this shape,
// so the stamper's raw fallback must read it — not just the braced shape.
func flatPolicyTree9984(t *testing.T) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	if err := tree.SetPath([]string{"event-options", "policy", "p", "events", "ping_test_failed"}); err != nil {
		t.Fatalf("seed flat events: %v", err)
	}
	if err := tree.SetPath([]string{"event-options", "policy", "p", "then", "change-configuration", "commands", "set system host-name stamped"}); err != nil {
		t.Fatalf("seed flat commands: %v", err)
	}
	return tree
}

func compiledPlantClass9984(t *testing.T, tree *ConfigTree) *EventPolicy {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	for _, pol := range cfg.EventOptions {
		if pol != nil && pol.Name == "p" {
			return pol
		}
	}
	t.Fatal("compiled config has no event policy p")
	return nil
}

// A plant-class-only edit is invisible to the compiled diff by design
// (eventPolicyExecutionEqual9984 zeroes PlantClass), so the raw fallback is
// the ONLY detector. Before the fix it required len(Keys)>1 on the commands
// node, which the flat shape never has — so one flat set persisted a forged
// super-user marker that fires as root.
func TestFlatPlantClassForgeryIsRestamped9984(t *testing.T) {
	before := flatPolicyTree9984(t)
	if err := before.SetPath([]string{"event-options", "policy", "p", "plant-class", "alice"}); err != nil {
		t.Fatalf("seed existing class: %v", err)
	}
	if pol := compiledPlantClass9984(t, before); pol.PlantClass != "alice" {
		t.Fatalf("fixture existing PlantClass=%q, want alice", pol.PlantClass)
	}
	after := before.Clone()
	if err := after.SetPath([]string{"event-options", "policy", "p", "plant-class", "super-user"}); err != nil {
		t.Fatalf("forge flat plant-class: %v", err)
	}
	StampChangedEventPlantClasses(before, after, "mallory")
	pol := compiledPlantClass9984(t, after)
	if pol.PlantClass != "mallory" {
		t.Fatalf("flat plant-class forgery persisted PlantClass=%q, want mallory (the mutating class)", pol.PlantClass)
	}
	if len(pol.ThenCommands) != 1 || pol.ThenCommands[0] != "set system host-name stamped" {
		t.Fatalf("restamp disturbed ThenCommands=%q", pol.ThenCommands)
	}
}

// The sharpest exploit: a LEGACY payload (no marker at all, as persisted
// before #9984) laundered into root execution by a single flat set. The
// stamper must bind the forging class, never the forged value.
func TestFlatLegacyLaunderingIsRestamped9984(t *testing.T) {
	before := flatPolicyTree9984(t)
	if pol := compiledPlantClass9984(t, before); pol.PlantClass != "" {
		t.Fatalf("fixture is not legacy: PlantClass=%q, want empty", pol.PlantClass)
	}
	after := before.Clone()
	if err := after.SetPath([]string{"event-options", "policy", "p", "plant-class", "super-user"}); err != nil {
		t.Fatalf("launder legacy payload: %v", err)
	}
	StampChangedEventPlantClasses(before, after, "mallory")
	if pol := compiledPlantClass9984(t, after); pol.PlantClass != "" {
		t.Fatalf("legacy laundering persisted PlantClass=%q, want empty quarantine marker", pol.PlantClass)
	}
}

// fileChildPlantClass9984 files plant-class in the block value-in-child shape
// (`plant-class { <value>; }`): Keys=["plant-class"] with the value as a
// child. The compiler reads it via nodeVal (Children[0].Name()); the raw
// fallback must agree, or a forgery in this shape is invisible to it while
// the compiled marker changes.
func fileChildPlantClass9984(t *testing.T, tree *ConfigTree, value string) {
	t.Helper()
	for _, top := range tree.Children {
		if top == nil || top.Name() != "event-options" {
			continue
		}
		for _, pol := range top.Children {
			if pol == nil || pol.Name() != "policy" || len(pol.Keys) < 2 || pol.Keys[1] != "p" {
				continue
			}
			pol.Children = append(pol.Children, &Node{
				Keys:     []string{"plant-class"},
				Children: []*Node{{Keys: []string{value}, IsLeaf: true}},
			})
			return
		}
	}
	t.Fatal("flat fixture has no event-options policy p to file plant-class under")
}

func TestChildShapePlantClassForgeryIsRestamped9984(t *testing.T) {
	before := flatPolicyTree9984(t)
	fileChildPlantClass9984(t, before, "alice")
	if pol := compiledPlantClass9984(t, before); pol.PlantClass != "alice" {
		t.Fatalf("fixture premise broken: child-shape plant-class compiled to %q, want alice", pol.PlantClass)
	}
	after := flatPolicyTree9984(t)
	fileChildPlantClass9984(t, after, "super-user")
	StampChangedEventPlantClasses(before, after, "mallory")
	if pol := compiledPlantClass9984(t, after); pol.PlantClass != "mallory" {
		t.Fatalf("child-shape forgery persisted PlantClass=%q, want mallory", pol.PlantClass)
	}
}

// The predicate directly: children OR tail, mirroring
// eventChangeConfigCommands. A bare `commands;` (no tail, no children)
// compiles to zero commands and must stay false.
func TestEventPolicyHasCommands9984Shapes(t *testing.T) {
	cases := []struct {
		name string
		node *Node
		want bool
	}{
		{"flat child shape", &Node{Keys: []string{"commands"}, Children: []*Node{{Keys: []string{"set system host-name x"}, IsLeaf: true}}}, true},
		{"block tail shape", &Node{Keys: []string{"commands", "set system host-name x"}, IsLeaf: true}, true},
		{"tail plus children", &Node{Keys: []string{"commands", "bogus"}, Children: []*Node{{Keys: []string{"set system host-name x"}, IsLeaf: true}}}, true},
		{"bare commands", &Node{Keys: []string{"commands"}, IsLeaf: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &Node{Keys: []string{"policy", "p"}, Children: []*Node{{
				Keys: []string{"then"}, Children: []*Node{{
					Keys: []string{"change-configuration"}, Children: []*Node{tc.node},
				}},
			}}}
			if got := eventPolicyHasCommands9984([]*Node{policy}); got != tc.want {
				t.Fatalf("eventPolicyHasCommands9984 = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyGroupsEventPolicyStamp9984(t *testing.T) {
	const source = `groups {
    event-remediation {
        event-options {
            policy p {
                events ping_test_failed;
                then { change-configuration { commands "set system host-name grouped"; } }
            }
        }
    }
}
apply-groups event-remediation;`
	tree, errs := NewParser(source).Parse()
	if len(errs) != 0 {
		t.Fatalf("grouped event policy parse failed: %v", errs)
	}
	StampChangedEventPlantClasses(nil, tree, "alice")
	nodes := eventPolicyNodes9984(tree)["p"]
	if len(nodes) != 1 || eventPolicyPlantClass9984(nodes) != "alice\x00" {
		t.Fatalf("grouped raw policy marker=%q nodes=%d, want alice on the group-owned policy", eventPolicyPlantClass9984(nodes), len(nodes))
	}
	for _, node := range tree.Children {
		if node != nil && node.Name() == "event-options" {
			t.Fatal("grouped stamp created a duplicate top-level event-options policy")
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("grouped event policy compile failed: %v", err)
	}
	if len(cfg.EventOptions) != 1 || cfg.EventOptions[0].PlantClass != "alice" {
		t.Fatalf("grouped compiled policy=%+v, want PlantClass alice", cfg.EventOptions)
	}
}

func setUncompileableCommandProvenance9984(t *testing.T, tree *ConfigTree, quoted []bool) {
	t.Helper()
	for _, policy := range eventPolicyNodes9984(tree)["p"] {
		var walk func([]*Node) bool
		walk = func(nodes []*Node) bool {
			for _, node := range nodes {
				if node == nil {
					continue
				}
				if node.Name() == "commands" && len(node.Children) > 0 {
					child := node.Children[0]
					child.Keys = []string{"set", "system", "host-name", "provenance"}
					child.KeysQuoted = append([]bool(nil), quoted...)
					return true
				}
				if walk(node.Children) {
					return true
				}
			}
			return false
		}
		if walk(policy.Children) {
			return
		}
	}
	t.Fatal("uncompileable fixture has no event command child")
}

func TestUncompileableCommandProvenanceRestamps9984(t *testing.T) {
	const source = `apply-groups missing-event-group;
event-options {
    policy p {
        events ping_test_failed;
        then { change-configuration { commands { set system host-name provenance; } } }
    }
}`
	before, errs := NewParser(source).Parse()
	if len(errs) != 0 {
		t.Fatalf("uncompileable fixture parse failed: %v", errs)
	}
	setUncompileableCommandProvenance9984(t, before, nil)
	if got := compiledEventPolicies9984(before); got != nil {
		t.Fatalf("fixture unexpectedly compiled before provenance change: %+v", got)
	}
	after := before.Clone()
	setUncompileableCommandProvenance9984(t, after, []bool{true, false, false, false})
	if got := compiledEventPolicies9984(after); got != nil {
		t.Fatalf("fixture unexpectedly compiled after provenance change: %+v", got)
	}
	StampChangedEventPlantClasses(before, after, "alice")
	if got := eventPolicyPlantClass9984(eventPolicyNodes9984(after)["p"]); got != "alice\x00" {
		t.Fatalf("uncompileable provenance change did not restamp PlantClass=%q, want alice", got)
	}
}
