package config

import (
	"regexp"
	"strings"
	"testing"
)

// #9657: the #3855 routing-instance table-id gate's pre-expansion view counted
// instances in EVERY `groups` block, applied or not. Group expansion drops a
// group nothing applies, so an instance declared only there never compiles and
// never takes a table, yet the gate refused a config whose effective instances
// do not collide, and the lenient warning named an ACTIVE instance as
// quarantined. The pre-expansion view now counts only groups an apply-groups
// statement reaches. ri7 and ri116 fold to one stable table id.

func compile9657(t *testing.T, text string, lenient bool) (*Config, error) {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v\n%s", errs, text)
	}
	if lenient {
		return CompileConfigLenient(tree)
	}
	return CompileConfig(tree)
}

func riNames9657(cfg *Config) []string {
	var names []string
	for _, ri := range cfg.RoutingInstances {
		names = append(names, ri.Name)
	}
	return names
}

const activeRI7_9657 = "routing-instances {\n    ri7 {\n        instance-type virtual-router;\n    }\n}\n"

const braced116_9657 = "routing-instances {\n            ri116 {\n                instance-type virtual-router;\n            }\n        }\n"

// group9657 declares group `name` holding ri116, braced or brace-elided.
func group9657(name string, packed bool) string {
	body := braced116_9657
	if packed {
		body = "routing-instances {\n            ri116 instance-type virtual-router;\n        }\n"
	}
	return "groups {\n    " + name + " {\n        " + body + "    }\n}\n"
}

func assertFixtureCollides9657(t *testing.T) {
	t.Helper()
	if a, b := StableRoutingInstanceTableID("ri7"), StableRoutingInstanceTableID("ri116"); a != b {
		t.Fatalf("fixture: ri7 and ri116 must fold to one table id, got %d and %d", a, b)
	}
}

func TestTableIDGateIgnoresAGroupNothingApplies_9657(t *testing.T) {
	assertFixtureCollides9657(t)
	for _, packed := range []bool{false, true} {
		text := group9657("unused", packed) + activeRI7_9657
		if _, err := compile9657(t, text, false); err != nil {
			t.Errorf("#9657 (packed=%v): ri116 sits in a group nothing applies and never compiles, but the strict "+
				"path refused the config: %v", packed, err)
		}
		cfg, err := compile9657(t, text, true)
		if err != nil {
			t.Fatalf("lenient compile (packed=%v): %v", packed, err)
		}
		if names := riNames9657(cfg); len(names) != 1 || names[0] != "ri7" {
			t.Errorf("control (packed=%v): the effective instances must be [ri7], got %v", packed, names)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "table-id collision") || strings.Contains(w, "QUARANTINE") {
				t.Errorf("#9657 (packed=%v): the lenient path warns about a collision no node has: %q", packed, w)
			}
		}
	}
}

// The same two configs in flat `set` form, which builds the groups subtree
// through SetPath rather than the hierarchical parser.
func TestTableIDGateReachabilityInFlatSetForm_9657(t *testing.T) {
	assertFixtureCollides9657(t)
	base := []string{
		"set groups unused routing-instances ri116 instance-type virtual-router",
		"set routing-instances ri7 instance-type virtual-router",
	}
	if _, err := CompileConfig(setTree9622(t, base...)); err != nil {
		t.Errorf("#9657 flat set: ri116 sits in a group nothing applies, but the strict path refused the config: %v", err)
	}
	applied := append(append([]string{}, base...), "set apply-groups unused")
	if _, err := CompileConfig(setTree9622(t, applied...)); err == nil || !strings.Contains(err.Error(), "table-id collision") {
		t.Errorf("#9657 flat set: once the group is applied the collision must be refused, got %v", err)
	}
	failing := append(append([]string{}, base...), "set apply-groups unused", "set apply-groups missing9657")
	if _, err := CompileConfig(setTree9622(t, failing...)); err == nil || !strings.Contains(err.Error(), "table-id collision") {
		t.Errorf("#9657 flat set: a reachable group must be counted when no expansion succeeds, got %v", err)
	}
}

func TestTableIDGateStillRejectsAReachableGroup_9657(t *testing.T) {
	assertFixtureCollides9657(t)
	nodeGroups := "groups {\n    node0 {\n        system {\n            host-name fw0;\n        }\n    }\n" +
		"    node1 {\n        " + braced116_9657 + "    }\n}\n"
	for _, tc := range []struct{ name, text string }{
		{"applied at top level", group9657("g1", false) + "apply-groups g1;\n" + activeRI7_9657},
		{"applied at top level, brace-elided", group9657("g1", true) + "apply-groups g1;\n" + activeRI7_9657},
		{"applied inside the routing-instances stanza", group9657("g1", false) +
			"routing-instances {\n    apply-groups g1;\n    ri7 {\n        instance-type virtual-router;\n    }\n}\n"},
		{"the peer's node group via ${node}", nodeGroups + "apply-groups \"${node}\";\n" + activeRI7_9657},
	} {
		if _, err := compile9657(t, tc.text, false); err == nil || !strings.Contains(err.Error(), "table-id collision") {
			t.Errorf("#9657 %s: ri116 is reachable, so the collision with ri7 must still be refused on the strict "+
				"path, got %v", tc.name, err)
		}
	}
}

// When no node's expansion succeeds, the pre-expansion view is the only one that
// sees a group. Each case applies an undefined group as well, and the gate runs
// before expansion, so a collision error here can only come from that view: it
// must still count a group reached directly, through ${node}, transitively, or
// from a nested apply-groups.
func TestTableIDGateCountsReachableGroupsWhenExpansionFails_9657(t *testing.T) {
	assertFixtureCollides9657(t)
	for _, tc := range []struct{ name, text string }{
		{"direct", group9657("g1", false) + "apply-groups [ g1 missing9657 ];\n" + activeRI7_9657},
		{"through ${node} to node0", group9657("node0", false) + "apply-groups [ \"${node}\" missing9657 ];\n" + activeRI7_9657},
		{"through ${node} to node1", group9657("node1", false) + "apply-groups [ \"${node}\" missing9657 ];\n" + activeRI7_9657},
		{"transitively", "groups {\n    g1 {\n        apply-groups g2;\n    }\n    g2 {\n        " + braced116_9657 +
			"    }\n}\napply-groups [ g1 missing9657 ];\n" + activeRI7_9657},
		{"from a nested apply-groups", group9657("g1", false) +
			"routing-instances {\n    apply-groups [ g1 missing9657 ];\n    ri7 {\n        instance-type virtual-router;\n    }\n}\n"},
	} {
		_, err := compile9657(t, tc.text, false)
		if err == nil || !strings.Contains(err.Error(), "table-id collision") {
			t.Errorf("#9657 %s: the group holding ri116 is reachable but no expansion succeeds; the pre-expansion "+
				"view must still report the collision, got %v", tc.name, err)
		}
		// Control: without the colliding instance the same config fails on the
		// undefined group, so the collision above is the pre-expansion view's.
		ctl := strings.Replace(tc.text, "ri116", "ri9657control", 1)
		if _, err := compile9657(t, ctl, false); err == nil || strings.Contains(err.Error(), "table-id collision") {
			t.Errorf("control %s: without ri116 the config must fail on something other than a collision, got %v", tc.name, err)
		}
	}
}

// The pre-expansion scan runs before apply-groups statements are removed. Under
// a routing-instances stanza they are two-key leaves, the same shape as a
// brace-elided instance, and must not be counted as instance names.
func TestRoutingInstanceNameScanSkipsApplyStatements_9657(t *testing.T) {
	text := "groups {\n    g1 {\n        system {\n            host-name fw;\n        }\n    }\n}\n" +
		"routing-instances {\n    apply-groups g1;\n    apply-groups-except g2;\n    ri7 {\n        instance-type virtual-router;\n    }\n}\n"
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v", errs)
	}
	names := routingInstanceNameUnionAST(tree)
	for _, kw := range []string{"apply-groups", "apply-groups-except"} {
		if _, ok := names[kw]; ok {
			t.Errorf("#9657: the routing-instance name union counts the statement %q as an instance: %v", kw, names)
		}
	}
	if _, ok := names["ri7"]; !ok {
		t.Errorf("control: ri7 is missing from the union %v", names)
	}
}

// The lenient table-id warning is computed from a union that spans BOTH nodes'
// views, so it cannot know which instance this node drops. Here ri116 is in
// effect only on node1; node0 keeps ri7. No warning may claim that an instance
// this node kept is quarantined.
func TestLenientCollisionWarningNeverNamesAKeptInstance_9657(t *testing.T) {
	assertFixtureCollides9657(t)
	text := "groups {\n    node0 {\n        system {\n            host-name fw0;\n        }\n    }\n" +
		"    node1 {\n        " + braced116_9657 + "    }\n}\napply-groups \"${node}\";\n" + activeRI7_9657
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v", errs)
	}
	cfg, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil {
		t.Fatalf("lenient node0 compile: %v", err)
	}
	kept := map[string]bool{}
	for _, n := range riNames9657(cfg) {
		kept[n] = true
	}
	if !kept["ri7"] || kept["ri116"] {
		t.Fatalf("fixture: node0 must keep ri7 and not have ri116, got %v", riNames9657(cfg))
	}
	collision := false
	claim := regexp.MustCompile(`"([^"]+)"( is)? QUARANTINED`)
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "table-id collision") {
			collision = true
		}
		for _, m := range claim.FindAllStringSubmatch(w, -1) {
			if kept[m[1]] {
				t.Errorf("#9657: a warning claims %q is quarantined, but node0 kept it: %q", m[1], w)
			}
		}
	}
	if !collision {
		t.Errorf("control: the collision across the two nodes' views must still be reported; warnings=%v", cfg.Warnings)
	}
}

// The union also accepts a groups node that carries the group name in its own
// Keys (Node{Keys:["groups","g1"]}). Neither the hierarchical parser nor
// SetPath builds that shape for these spellings (both nest the group name as a
// child), so it is constructed directly and the reachability check on that
// branch is exercised rather than assumed.
func TestRoutingInstanceUnionFiltersTheMergedGroupShape_9657(t *testing.T) {
	body, errs := NewParser("routing-instances {\n    ri116 {\n        instance-type virtual-router;\n    }\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v", errs)
	}
	build := func(apply bool) *ConfigTree {
		active, errs := NewParser(activeRI7_9657).Parse()
		if len(errs) > 0 {
			t.Fatalf("fixture must parse: %v", errs)
		}
		tree := &ConfigTree{}
		tree.Children = append(tree.Children, &Node{Keys: []string{"groups", "g1"}, Children: body.Clone().Children})
		if apply {
			tree.Children = append(tree.Children, &Node{Keys: []string{"apply-groups", "g1"}, IsLeaf: true})
		}
		tree.Children = append(tree.Children, active.Children...)
		return tree
	}
	if _, ok := routingInstanceNameUnionAST(build(false))["ri116"]; ok {
		t.Errorf("#9657: the merged groups shape counts an instance from a group nothing applies")
	}
	if _, ok := routingInstanceNameUnionAST(build(true))["ri116"]; !ok {
		t.Errorf("#9657: the merged groups shape drops an instance from an applied group")
	}
}
