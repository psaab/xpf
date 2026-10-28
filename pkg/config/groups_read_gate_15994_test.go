package config

import (
	"strings"
	"testing"
)

// #15994 fold (onto #15995's Rendered gate): group bodies are
// effective config. A `groups <name> …` read must be priced on every
// effective spelling — the authored definition path and the
// recursively unwrapped body path — on BOTH regex pairs, and the
// ancestor spellings `groups` / `groups <name>` must price every
// path the render contains (definitions included). Whole renders
// keep the op verdict (fold B1). Unrestricted classes never fail
// closed (fold M1).

func cfgOp15994(t *testing.T, allowConf, denyConf, allowCmd, denyCmd string) *Config {
	t.Helper()
	var b strings.Builder
	b.WriteString("system { login { class limited { permissions [ configure view ]; ")
	if allowConf != "" {
		b.WriteString("allow-configuration \"" + allowConf + "\"; ")
	}
	if denyConf != "" {
		b.WriteString("deny-configuration \"" + denyConf + "\"; ")
	}
	if allowCmd != "" {
		b.WriteString("allow-commands \"" + allowCmd + "\"; ")
	}
	if denyCmd != "" {
		b.WriteString("deny-commands \"" + denyCmd + "\"; ")
	}
	b.WriteString("} } }")
	tree, errs := NewParser(b.String()).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture class does not parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture class does not compile: %v", err)
	}
	return cfg
}

const groupsTree15994 = `
groups {
    G {
        security {
            zones {
                security-zone trust {
                    description GROUP-SEC-15994;
                }
            }
        }
        interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
    }
    H {
        system { host-name group-h; }
    }
}
security {
    zones {
        security-zone dmz { description DIRECT-SEC-15994; }
    }
}
apply-groups G;
`

func tree15994(t *testing.T) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(groupsTree15994).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture tree does not parse: %v", errs)
	}
	// Premise: the group body materializes at the effective path.
	lines, err := ExpandedMutationLines(tree)
	if err != nil {
		t.Fatalf("ExpandedMutationLines: %v", err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "security-zone trust description GROUP-SEC-15994") {
		t.Fatalf("premise broken: group body does not materialize: %v", lines)
	}
	return tree
}

func TestGroupsReadScopedGateRefuses15994(t *testing.T) {
	cfgSec := cfgOp15994(t, "", "^security", "", "")
	tree := tree15994(t)

	// Config arm: literal + unwrapped + ancestors all refuse.
	for _, path := range [][]string{
		{"groups", "G", "security"},
		{"groups"},
		{"groups", "G"},
	} {
		if err := AuthorizeConfigShowPathRendered(cfgSec, "limited", path, "", []*ConfigTree{tree}); err == nil {
			t.Errorf("ShowConfigRendered %v ALLOWED for deny-configuration ^security (#15994)", path)
		}
		if err := AuthorizeConfigShowCompareAtPathRendered(cfgSec, "limited", path, []*ConfigTree{tree}); err == nil {
			t.Errorf("ShowCompareRendered %v ALLOWED (#15994)", path)
		}
		if err := AuthorizeConfigShowRollbackAtPathRendered(cfgSec, "limited", path, "", []*ConfigTree{tree}); err == nil {
			t.Errorf("ShowRollbackRendered %v ALLOWED (#15994)", path)
		}
	}
	// Controls stay admitted.
	for _, path := range [][]string{
		{"groups", "H", "system"},
		{"groups", "H", "system", "host-name"},
		{"system", "host-name"},
		{"groups", "G", "system"},
	} {
		if err := AuthorizeConfigShowPathRendered(cfgSec, "limited", path, "", []*ConfigTree{tree}); err != nil {
			// groups G system is under G whose sibling is security;
			// the descendant walk prices descendants of the scope,
			// not siblings — but G's body also carries interfaces.
			// [groups G system] itself must stay admitted.
			if strings.Join(path, " ") != "groups G system" {
				t.Errorf("ShowConfigRendered %v must stay admitted: %v", path, err)
			}
		}
	}
	if err := AuthorizeConfigShowPathRendered(cfgSec, "limited", []string{"groups", "G", "system"}, "", []*ConfigTree{tree}); err != nil {
		t.Errorf("groups G system (allowed sibling of body) refused: %v", err)
	}

	// Directed baseline still refused, and the literal spelling alone
	// does NOT catch it (premise of the original bug).
	if err := AuthorizeConfigShowPath(cfgSec, "limited", []string{"security"}, ""); err == nil {
		t.Fatal("premise broken: direct [security] admitted")
	}
	if err := AuthorizeConfigShowPath(cfgSec, "limited", []string{"groups", "G"}, ""); err != nil {
		t.Fatalf("path-free ancestor must stay admitted (premise): %v", err)
	}

	// Nested groups: innermost body priced.
	nested := parseHierText(t, "groups { H { system { host-name h15994; } } G { apply-groups H; } } apply-groups G;")
	inner := parseHierText(t, "groups { H { security { zones { security-zone trust { description NESTED-15994; } } } } G { apply-groups H; } } apply-groups G;")
	if err := AuthorizeConfigShowPathRendered(cfgSec, "limited", []string{"groups", "G", "system"}, "", []*ConfigTree{nested}); err != nil {
		t.Errorf("nested allowed path refused: %v", err)
	}
	if err := AuthorizeConfigShowPathRendered(cfgSec, "limited", []string{"groups", "G", "security"}, "", []*ConfigTree{inner}); err == nil {
		t.Errorf("nested denied path ALLOWED (#15994)")
	}
	if err := AuthorizeConfigShowPathRendered(cfgSec, "limited", []string{"groups"}, "", []*ConfigTree{inner}); err == nil {
		t.Errorf("nested ancestor ALLOWED (#15994)")
	}
}

func TestGroupsReadOpArm15994(t *testing.T) {
	// Op-only class: deny-commands on the effective command.
	cfg := cfgOp15994(t, "", "", "", "^show configuration security")
	tree := tree15994(t)
	for _, path := range [][]string{
		{"groups", "G", "security"},
		{"groups"},
		{"groups", "G"},
	} {
		if err := AuthorizeConfigShowPathRendered(cfg, "limited", path, "", []*ConfigTree{tree}); err == nil {
			t.Errorf("op-arm escaped via %v (#15994 fold 2)", path)
		}
	}
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"groups", "G", "interfaces"}, "", []*ConfigTree{tree}); err != nil {
		t.Errorf("op-arm priced wrong subtree: %v", err)
	}
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"groups", "H", "system"}, "", []*ConfigTree{tree}); err != nil {
		t.Errorf("op-arm allowed sibling refused: %v", err)
	}
	// display set form of the denied effective command also refuses.
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", []string{"groups", "G", "security"}, "display set", []*ConfigTree{tree}); err == nil {
		t.Errorf("op-arm display set escaped (#15994)")
	}
}

func TestGroupsReadWhole15994(t *testing.T) {
	tree := tree15994(t)
	plain := parseHierText(t, "system { host-name plain-15994; }")

	// deny-configuration ^security: group body refuses whole.
	cfgSec := cfgOp15994(t, "", "^security", "", "")
	if err := AuthorizeConfigShowWholeAtTree(cfgSec, "limited", "", []*ConfigTree{tree}); err == nil {
		t.Error("whole tree with denied group body ALLOWED (#15994)")
	}
	if err := AuthorizeConfigShowWholeAtTree(cfgSec, "limited", "", []*ConfigTree{plain}); err == nil {
		t.Error("groupless whole tree admitted (must keep #14707 refusal)")
	}
	if err := AuthorizeConfigShowCompareAtTree(cfgSec, "limited", plain, tree); err == nil {
		t.Error("unscoped compare with denied candidate ALLOWED (#15994)")
	}
	if err := AuthorizeConfigShowRollbackAtTree(cfgSec, "limited", tree, ""); err == nil {
		t.Error("unscoped rollback with denied group body ALLOWED (#15994)")
	}
	// Scoped controls stay admitted.
	if err := AuthorizeConfigShowWholeAtTree(cfgSec, "limited", "", []*ConfigTree{parseHierText(t,
		"groups { H { system { host-name ok15994; } } } system { host-name top15994; }")}); err != nil {
		t.Errorf("allowed-only groups whole refused: %v", err)
	}

	// deny-configuration ^groups: authored definition refuses whole
	// even though the effective body is allowed (fold 3).
	cfgGroups := cfgOp15994(t, "", "^groups", "", "")
	if err := AuthorizeConfigShowWholeAtTree(cfgGroups, "limited", "", []*ConfigTree{tree}); err == nil {
		t.Error("whole tree with denied group definition ALLOWED (#15994 fold 3)")
	}

	// Op-only denies are NEVER substituted away (fold B1).
	cfgSet := cfgOp15994(t, "", "", "", "display set")
	if err := AuthorizeConfigShowWholeAtTree(cfgSet, "limited", "display set", []*ConfigTree{tree}); err == nil {
		t.Error("whole display set escaped op-only deny (#15994 fold B1)")
	}
	if err := AuthorizeConfigShowWholeAtTree(cfgSet, "limited", "display set", []*ConfigTree{plain}); err == nil {
		t.Error("groupless whole display set escaped op-only deny")
	}
	cfgBare := cfgOp15994(t, "", "", "", "^show configuration$")
	if err := AuthorizeConfigShowWholeAtTree(cfgBare, "limited", "", []*ConfigTree{tree}); err == nil {
		t.Error("whole bare denied command escaped (#15994 fold B1)")
	}
	if err := AuthorizeConfigShowCompareAtTree(cfgBare, "limited", plain, tree); err == nil {
		t.Error("unscoped compare bare denied command escaped (#15994 fold B1)")
	}
	if err := AuthorizeConfigShowRollbackAtTree(cfgBare, "limited", tree, ""); err == nil {
		t.Error("unscoped rollback bare denied command escaped (#15994 fold B1)")
	}
	// But the same op-only class with no matching deny admits.
	cfgOpen := cfgOp15994(t, "", "", "", "^show something-else$")
	if err := AuthorizeConfigShowWholeAtTree(cfgOpen, "limited", "", []*ConfigTree{tree}); err != nil {
		t.Errorf("whole tree refused for unrelated op deny: %v", err)
	}
	// Fold3: path-scoped op deny on CONTENT supplied only as a group
	// body refuses every whole render; groupless tree unaffected.
	cfgScoped := cfgOp15994(t, "", "", "", "^show configuration security")
	if err := AuthorizeConfigShowWholeAtTree(cfgScoped, "limited", "", []*ConfigTree{tree}); err == nil {
		t.Error("whole tree with group-supplied security ALLOWED despite ^show configuration security (#15994 fold3)")
	}
	if err := AuthorizeConfigShowCompareAtTree(cfgScoped, "limited", plain, tree); err == nil {
		t.Error("unscoped compare with group-supplied security ALLOWED (#15994 fold3)")
	}
	if err := AuthorizeConfigShowRollbackAtTree(cfgScoped, "limited", tree, ""); err == nil {
		t.Error("unscoped rollback with group-supplied security ALLOWED (#15994 fold3)")
	}
	if err := AuthorizeConfigShowWholeAtTree(cfgScoped, "limited", "", []*ConfigTree{plain}); err != nil {
		t.Errorf("groupless whole refused for scoped op deny: %v", err)
	}
}

func TestGroupsReadUnrestricted15994(t *testing.T) {
	tree := tree15994(t)
	// Zero-regex class: unresolvable groups scope must NOT fail
	// closed (fold M1).
	open := cfgOp15994(t, "", "", "", "")
	groupless := parseHierText(t, "system { host-name plain-15994; }")
	if err := AuthorizeConfigShowPathRendered(open, "limited", []string{"groups"}, "", []*ConfigTree{groupless}); err != nil {
		t.Errorf("unrestricted [groups] on groupless tree refused (fold M1): %v", err)
	}
	if err := AuthorizeConfigShowPathRendered(open, "limited", []string{"groups", "MISSING"}, "", []*ConfigTree{groupless}); err != nil {
		t.Errorf("unrestricted [groups MISSING] refused (fold M1): %v", err)
	}
	if err := AuthorizeConfigShowPathRendered(open, "limited", []string{"groups", "G", "security"}, "", []*ConfigTree{tree}); err != nil {
		t.Errorf("unrestricted groups read refused: %v", err)
	}
	if err := AuthorizeConfigShowPathRendered(open, "", []string{"groups"}, "", []*ConfigTree{groupless}); err != nil {
		t.Errorf("empty class refused: %v", err)
	}
	// Restricted class on an unresolvable scope DOES fail closed.
	restricted := cfgOp15994(t, "", "^security", "", "")
	if err := AuthorizeConfigShowPathRendered(restricted, "limited", []string{"groups", "MISSING"}, "", []*ConfigTree{groupless}); err == nil {
		t.Error("restricted [groups MISSING] admitted (must fail closed)")
	}
	if err := AuthorizeConfigShowPathRendered(restricted, "limited", []string{"groups"}, "", []*ConfigTree{groupless}); err == nil {
		t.Error("restricted [groups] on groupless tree admitted (must fail closed)")
	}
}

// Fold2-4: display inheritance runs the groups walk even when
// config rules exist; nested applied-group content priced.
func TestGroupsExpandedInheritance15994(t *testing.T) {
	inner := parseHierText(t, "groups { H { security { zones { security-zone trust { description NESTED-15994; } } } } G { apply-groups H; } } apply-groups G;")
	sec := cfgOp15994(t, "", "^security", "", "")
	if err := AuthorizeExpandedConfigShowPathRendered(sec, "limited", []string{"groups", "G", "security"}, "display inheritance", -1, []*ConfigTree{inner}); err == nil {
		t.Fatal("nested expanded denied path ALLOWED (fold2-4)")
	}
	if err := AuthorizeExpandedConfigShowPathRendered(sec, "limited", []string{"groups"}, "display inheritance", -1, []*ConfigTree{inner}); err == nil {
		t.Fatal("nested expanded ancestor ALLOWED (fold2-4)")
	}
	op := cfgOp15994(t, "", "", "", "^show configuration security")
	if err := AuthorizeExpandedConfigShowPathRendered(op, "limited", []string{"groups", "G", "security"}, "display inheritance", -1, []*ConfigTree{inner}); err == nil {
		t.Fatal("op nested expanded denied ALLOWED (fold2-4)")
	}
	if err := AuthorizeExpandedConfigShowPathRendered(sec, "limited", []string{"security"}, "display inheritance", -1, []*ConfigTree{inner}); err == nil {
		t.Fatal("expanded effective security ALLOWED")
	}
	allowed := parseHierText(t, "groups { G { system { host-name ok15994; } } } apply-groups G;")
	if err := AuthorizeExpandedConfigShowPathRendered(sec, "limited", []string{"groups"}, "display inheritance", -1, []*ConfigTree{allowed}); err != nil {
		t.Fatalf("allowed expanded groups refused: %v", err)
	}
	if err := AuthorizeExpandedConfigShowPathRendered(sec, "limited", []string{"groups", "G", "system"}, "display inheritance", -1, []*ConfigTree{allowed}); err != nil {
		t.Fatalf("allowed expanded path refused: %v", err)
	}
}

// #16428: the read gate shares ExpandedMutationLines, so a whole-config
// read of a ${node} cluster tree by a restricted class must adjudicate
// the node views instead of refusing with "group expansion cannot be
// resolved". Allowed node content admits; a denied leaf in either node
// group refuses.
func TestGroupsReadNodeVarWhole16428(t *testing.T) {
	allowed := parseHierText(t, `groups { node0 { system { host-name fw0; } } node1 { system { host-name fw1; } } } apply-groups "${node}"; system { host-name top16428; }`)
	cfgSec := cfgOp15994(t, "", "^security", "", "")
	if err := AuthorizeConfigShowWholeAtTree(cfgSec, "limited", "", []*ConfigTree{allowed}); err != nil {
		t.Fatalf("whole read of allowed ${node} cluster refused: %v (#16428)", err)
	}
	for name, text := range map[string]string{
		"node0-denied": `groups { node0 { security { zones { security-zone trust { description EVIL16428; } } } } node1 { system { host-name fw1; } } } apply-groups "${node}";`,
		"node1-denied": `groups { node0 { system { host-name fw0; } } node1 { security { zones { security-zone trust { description EVIL16428; } } } } } apply-groups "${node}";`,
	} {
		t.Run(name, func(t *testing.T) {
			tree := parseHierText(t, text)
			if err := authorizeConfigReadExpanded15994(cfgSec, "limited", tree); err == nil {
				t.Fatal("denied leaf via node group admitted on read (#16428)")
			}
			if err := AuthorizeConfigShowWholeAtTree(cfgSec, "limited", "", []*ConfigTree{tree}); err == nil {
				t.Fatal("whole read with denied node-group leaf ALLOWED (#16428)")
			}
		})
	}
}
