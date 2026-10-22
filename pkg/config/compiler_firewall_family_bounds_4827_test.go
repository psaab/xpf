package config

import "testing"

// #4827: validateFirewallFilterFamilyCollisionsAST (and its sibling
// validateFirewallFilterFamilyAnyMatchesAST, plus compileFirewall itself)
// indexed into a family node's Keys with no length guard:
//
//	af = afNode.Keys[0]
//
// Every Node produced by the live parser or by ConfigTree.SetPath
// structurally guarantees len(Keys) >= 1, so this is not reachable through
// normal config parsing — buildTree/ParseSetCommand cannot construct the
// malformed shape. The one path that bypasses those invariants is
// pkg/configstore/db.go's plain json.Unmarshal of the persisted
// ConfigTree, which has no Node validator: a corrupted or hand-edited
// on-disk DB file could produce a persisted Node{Keys: []string{}} under a
// `firewall family { ... }` block, which panics with an out-of-range index
// when that store is next loaded and re-validated (both AST prewalk
// validators run on load, before compileFirewall's own occurrence of the
// same bug would even be reached).
//
// These tests hand-construct exactly that malformed shape (impossible via
// the production parser) and drive it directly through the three vulnerable
// functions, matching the project's fail-closed-on-load stance (#1960):
// a bad persisted state must error/skip gracefully, never panic.

// malformedFirewallFamilyTree builds:
//
//	firewall { family { <empty-keys-node> { filter f1 { term t1 { then accept; } } } } }
//
// The set-command AST shape (`family { <af> { ... } }`, familyNode.Keys ==
// ["family"], len 1) routes afNodes through familyNode.Children, so afName
// stays "" and the empty-Keys child is exactly the afNode that used to be
// indexed unconditionally.
func malformedFirewallFamilyTree() []*Node {
	filterTerm := &Node{
		Keys: []string{"term", "t1"},
		Children: []*Node{
			{Keys: []string{"then"}, Children: []*Node{{Keys: []string{"accept"}, IsLeaf: true}}},
		},
	}
	filterNode := &Node{
		Keys:     []string{"filter", "f1"},
		Children: []*Node{filterTerm},
	}
	malformedAF := &Node{
		Keys:     []string{}, // the malformed shape: no identity at all
		Children: []*Node{filterNode},
	}
	familyNode := &Node{
		Keys:     []string{"family"},
		Children: []*Node{malformedAF},
	}
	fwNode := &Node{
		Keys:     []string{"firewall"},
		Children: []*Node{familyNode},
	}
	return []*Node{fwNode}
}

func TestValidateFirewallFilterFamilyCollisionsAST_EmptyKeysNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("validateFirewallFilterFamilyCollisionsAST panicked on an empty-Keys "+
				"family node (#4827 regression): %v", r)
		}
	}()
	nodes := malformedFirewallFamilyTree()
	if _, _, err := validateFirewallFilterFamilyCollisionsAST(nodes, false); err != nil {
		// A malformed node producing an error is fine — the requirement is
		// "no panic", not "no error".
		t.Logf("validator returned an error for the malformed node (acceptable): %v", err)
	}
}

func TestValidateFirewallFilterFamilyAnyMatchesAST_EmptyKeysNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("validateFirewallFilterFamilyAnyMatchesAST panicked on an empty-Keys "+
				"family node (#4827 regression): %v", r)
		}
	}()
	nodes := malformedFirewallFamilyTree()
	if _, err := validateFirewallFilterFamilyAnyMatchesAST(nodes, false); err != nil {
		t.Logf("validator returned an error for the malformed node (acceptable): %v", err)
	}
}

// compileFirewall carries the identical unguarded-index pattern as the two
// AST prewalk validators above (it walks the same family/afNode shape). The
// prewalk validators run first in compileExpanded and would already error
// or warn on a corrupted store, but compileFirewall is reachable directly
// (e.g. from any future caller that skips the prewalk phase) and should not
// panic either — same #1960 fail-closed-on-load doctrine, defense in depth.
func TestCompileFirewall_EmptyKeysNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("compileFirewall panicked on an empty-Keys family node "+
				"(#4827 regression): %v", r)
		}
	}()
	nodes := malformedFirewallFamilyTree()
	fw := &FirewallConfig{}
	if err := compileFirewall(nodes[0], fw); err != nil {
		t.Logf("compileFirewall returned an error for the malformed node (acceptable): %v", err)
	}
}

// TestFirewallFilterFamilyCollisions_ValidTreeStillWorks confirms the fix
// does not change behavior for a well-formed tree: the pre-existing #3884
// same-name-cross-family collision is still detected. `family any` only
// reaches a structured filter subtree via a hierarchical parse (the flat
// `set` schema collapses it into an unstructured leaf — see
// compiler_firewall_family_collision_3884_test.go), so this uses parseHierText.
func TestFirewallFilterFamilyCollisions_ValidTreeStillWorks(t *testing.T) {
	tree := parseHierText(t, `
firewall {
    family inet {
        filter blockX {
            term t1 {
                then {
                    discard;
                }
            }
        }
    }
    family any {
        filter blockX {
            term t1 {
                then {
                    accept;
                }
            }
        }
    }
}
`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("cross-family filter-name reuse (inet + any) must still be rejected (#3884)")
	}
}
