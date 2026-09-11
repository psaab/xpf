package config

import (
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #9685: a flat `set <container> apply-groups <g>` placed where the schema has a
// WILDCARD name slot (routing-instances, interfaces, ...) was filed with the
// group name one level down: the wildcard took `apply-groups` as an instance
// name, so SetPath stored Keys=["apply-groups"] with a child ["g1"]. Group
// expansion reads names from the statement's own Keys[1:], found none, and
// stripped the node, so the inheritance (or the #9422 exclusion) silently did
// not happen on a clean commit. The hierarchical spelling was unaffected.

var applyStatements9685 = []string{"apply-groups", "apply-groups-except"}

// wildcardSlotPaths9685 returns a set path to every schema node that carries a
// wildcard name slot. The top-level `groups` subtree is skipped because its
// wildcard mirrors the whole root.
func wildcardSlotPaths9685() [][]string {
	var out [][]string
	var walk func(n *schemaNode, path []string, depth int)
	walk = func(n *schemaNode, path []string, depth int) {
		if n == nil || depth > 8 {
			return
		}
		if n.wildcard != nil {
			out = append(out, append([]string(nil), path...))
		}
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c := n.children[k]
			if c == nil || c.multi || (depth == 0 && (k == "groups" || k == "apply-groups")) {
				continue
			}
			p := append(append([]string(nil), path...), k)
			for a := 0; a < c.args; a++ {
				p = append(p, "a"+strconv.Itoa(a))
			}
			walk(c, p, depth+1)
		}
		if w := n.wildcard; w != nil && !w.multi {
			p := append(append([]string(nil), path...), "w1")
			for a := 0; a < w.args; a++ {
				p = append(p, "a"+strconv.Itoa(a))
			}
			walk(w, p, depth+1)
		}
	}
	walk(setSchema, nil, 0)
	return out
}

func findStatement9685(nodes []*Node, keyword string) *Node {
	for _, n := range nodes {
		if len(n.Keys) > 0 && n.Keys[0] == keyword {
			return n
		}
		if f := findStatement9685(n.Children, keyword); f != nil {
			return f
		}
	}
	return nil
}

// TestFlatApplyStatementKeepsItsNamesAtEveryWildcardSlot_9685 is the census:
// every wildcard name slot in the schema, for both apply statements.
func TestFlatApplyStatementKeepsItsNamesAtEveryWildcardSlot_9685(t *testing.T) {
	paths := wildcardSlotPaths9685()
	if len(paths) == 0 {
		t.Fatal("precondition: the schema walk found no wildcard slots")
	}
	sawRoutingInstances := false
	var broken []string
	voids := 0
	for _, p := range paths {
		if len(p) == 1 && p[0] == "routing-instances" {
			sawRoutingInstances = true
		}
		for _, kw := range applyStatements9685 {
			tree := &ConfigTree{}
			line := append(append([]string(nil), p...), kw, "g1")
			if err := tree.SetPath(line); err != nil {
				voids++
				continue
			}
			n := findStatement9685(tree.Children, kw)
			if n == nil {
				voids++
				continue
			}
			if len(n.Keys) != 2 || n.Keys[1] != "g1" {
				broken = append(broken, strings.Join(line, " "))
			}
		}
	}
	if !sawRoutingInstances {
		t.Fatal("precondition: routing-instances must be among the wildcard slots walked")
	}
	t.Logf("walked %d wildcard slots x %d statements; %d not settable at that path", len(paths), len(applyStatements9685), voids)
	if len(broken) > 0 {
		sort.Strings(broken)
		show := broken
		if len(show) > 25 {
			show = show[:25]
		}
		t.Errorf("%d flat apply statement(s) lost their group name to a wildcard slot, e.g.:\n  %s",
			len(broken), strings.Join(show, "\n  "))
	}
}

func routingInstanceNames9685(t *testing.T, cmds []string) []string {
	t.Helper()
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var names []string
	for _, ri := range cfg.RoutingInstances {
		names = append(names, ri.Name)
	}
	sort.Strings(names)
	return names
}

// TestFlatRoutingInstancesApplyStatementsCompileLikeHierarchical_9685 pins the
// issue's rows A and D against their hierarchical controls C and E.
func TestFlatRoutingInstancesApplyStatementsCompileLikeHierarchical_9685(t *testing.T) {
	group := "set groups g1 routing-instances ri1 instance-type virtual-router"

	t.Run("row_A_apply_groups_inherits", func(t *testing.T) {
		got := routingInstanceNames9685(t, []string{group, "set routing-instances apply-groups g1"})
		if strings.Join(got, ",") != "ri1" {
			t.Errorf("flat `set routing-instances apply-groups g1` compiled instances %v, want [ri1]", got)
		}
	})
	t.Run("row_C_hierarchical_control", func(t *testing.T) {
		tree, errs := NewParser("groups { g1 { routing-instances { ri1 { instance-type virtual-router; } } } }\nrouting-instances { apply-groups g1; }\n").Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs[0])
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != "ri1" {
			t.Fatalf("control: hierarchical apply-groups must inherit ri1, got %d instances", len(cfg.RoutingInstances))
		}
	})
	t.Run("row_D_apply_groups_except_excludes", func(t *testing.T) {
		got := routingInstanceNames9685(t, []string{group, "set apply-groups g1", "set routing-instances apply-groups-except g1"})
		if len(got) != 0 {
			t.Errorf("flat `set routing-instances apply-groups-except g1` compiled instances %v, want none (the exclusion must be honoured)", got)
		}
	})
}

// TestFlatRoutingInstancesApplyGroupsRendersAsAStatement_9685 covers `show
// configuration`: the flat-set result must render as the statement, not as a
// container named apply-groups holding a child g1.
func TestFlatRoutingInstancesApplyGroupsRendersAsAStatement_9685(t *testing.T) {
	tree := buildTree(t, []string{"set routing-instances apply-groups g1"})
	out := tree.Format()
	if !strings.Contains(out, "apply-groups g1;") || strings.Contains(out, "apply-groups {") {
		t.Errorf("flat apply-groups under routing-instances must render as `apply-groups g1;`:\n%s", out)
	}
}

// TestFlatApplyGroupsListAtWildcardSlotKeepsEveryName_9685: a bracket list at a
// wildcard slot. After the first name the remaining tokens used to be treated as
// siblings, because a wildcard slot accepts any keyword; they are group names.
func TestFlatApplyGroupsListAtWildcardSlotKeepsEveryName_9685(t *testing.T) {
	cmds := []string{
		"set groups g1 routing-instances ri1 instance-type virtual-router",
		"set groups g2 routing-instances ri2 instance-type virtual-router",
		"set routing-instances apply-groups [ g1 g2 ]",
	}
	tree := buildTree(t, cmds[2:])
	n := findStatement9685(tree.Children, "apply-groups")
	if n == nil || strings.Join(n.Keys, " ") != "apply-groups g1 g2" {
		t.Fatalf("flat bracket list must be one statement Keys=[apply-groups g1 g2], got %+v", n)
	}
	if got := routingInstanceNames9685(t, cmds); strings.Join(got, ",") != "ri1,ri2" {
		t.Errorf("both groups must be inherited, got %v", got)
	}
}

// TestDeleteAndDeactivateReachTheApplyStatementAtWildcardSlot_9685: the delete
// and deactivate walkers resolve the path the same way SetPath does, or the
// statement SetPath now builds could not be removed or deactivated by its own
// flat spelling.
func TestDeleteAndDeactivateReachTheApplyStatementAtWildcardSlot_9685(t *testing.T) {
	path := []string{"routing-instances", "apply-groups", "g1"}

	t.Run("delete", func(t *testing.T) {
		tree := buildTree(t, []string{"set routing-instances apply-groups g1"})
		if err := tree.DeletePath(path); err != nil {
			t.Fatalf("DeletePath: %v", err)
		}
		if n := findStatement9685(tree.Children, "apply-groups"); n != nil {
			t.Errorf("`delete routing-instances apply-groups g1` left the statement: %+v", n)
		}
	})
	t.Run("deactivate", func(t *testing.T) {
		tree := buildTree(t, []string{"set routing-instances apply-groups g1"})
		if err := tree.DeactivatePath(path); err != nil {
			t.Fatalf("DeactivatePath: %v", err)
		}
		n := findStatement9685(tree.Children, "apply-groups")
		if n == nil || !n.Inactive {
			t.Errorf("`deactivate routing-instances apply-groups g1` did not mark the statement inactive: %+v", n)
		}
	})
}

// TestCompactNormalizerLeavesApplyStatementAtWildcardSlot_9685: the brace-elided
// normalizer resolves child schemas with the same lookup. Driven with every
// container in scope, so the cell does not depend on today's #8662 scope list.
// The groups are named after routing-instance body keywords: read through the
// wildcard, `apply-groups interface protocols` looks like an instance named
// apply-groups with a packed `interface` tail, and the normalizer folds it into
// a container, which is the #9685 shape again.
func TestCompactNormalizerLeavesApplyStatementAtWildcardSlot_9685(t *testing.T) {
	tree, errs := NewParser("routing-instances { apply-groups [ interface protocols ]; }\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	normalizeCompactStanzasWithScope(tree, func(string, string) bool { return true })
	n := findStatement9685(tree.Children, "apply-groups")
	if n == nil || strings.Join(n.Keys, " ") != "apply-groups interface protocols" || len(n.Children) != 0 {
		t.Errorf("the normalizer must leave `apply-groups [ interface protocols ]` as one statement, got %+v", n)
	}
}

// TestDeleteOneGroupFromApplyListAtWildcardSlot_9685: deleting one member of a
// flat apply list at a wildcard slot removes that member only, as the top-level
// `delete apply-groups g1` does. The #8992 elided-delete guard resolves schema
// children through resolveSchemaChild, and used to read the statement as a
// packed run and refuse.
func TestDeleteOneGroupFromApplyListAtWildcardSlot_9685(t *testing.T) {
	tree := buildTree(t, []string{"set routing-instances apply-groups [ g1 g2 ]"})
	if err := tree.DeletePath([]string{"routing-instances", "apply-groups", "g1"}); err != nil {
		t.Fatalf("DeletePath: %v", err)
	}
	n := findStatement9685(tree.Children, "apply-groups")
	if n == nil || strings.Join(n.Keys, " ") != "apply-groups g2" {
		t.Errorf("deleting g1 must leave `apply-groups g2`, got %+v", n)
	}
}
