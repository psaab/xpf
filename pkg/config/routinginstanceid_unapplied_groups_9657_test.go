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
		"routing-instances {\n    apply-groups g1;\n    apply-groups-except g2;\n    apply-macro M {\n        k v;\n    }\n    ri7 {\n        instance-type virtual-router;\n    }\n}\n"
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v", errs)
	}
	names := routingInstanceNameUnionAST(tree)
	for _, kw := range []string{"apply-groups", "apply-groups-except", "apply-macro"} {
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

// An apply statement under routing-instances is not a routing instance, for the
// compiler as well as the collision scan. Group expansion strips only
// apply-groups; apply-groups-except and apply-macro stay in the tree. Before
// #9657 the compiler built an instance, and a VRF, named after the keyword, and
// that phantom quarantined a real instance whose stable table id collided with
// it while the strict gate saw nothing. apply-macro folds to the same table as
// ri486364, and apply-groups-except to the same as ri402839.
func TestApplyStatementsAreNotRoutingInstances_9657(t *testing.T) {
	if StableRoutingInstanceTableID("apply-macro") != StableRoutingInstanceTableID("ri486364") ||
		StableRoutingInstanceTableID("apply-groups-except") != StableRoutingInstanceTableID("ri402839") {
		t.Fatalf("fixture: each keyword and its sibling must fold to one table id")
	}
	for _, tc := range []struct{ name, text, want string }{
		{"apply-macro beside a colliding instance",
			"routing-instances {\n    apply-macro M {\n        k v;\n    }\n    ri486364 {\n        instance-type virtual-router;\n    }\n}\n", "ri486364"},
		{"apply-groups-except beside a colliding instance",
			"groups {\n    g2 {\n        system {\n            host-name x;\n        }\n    }\n}\n" +
				"routing-instances {\n    apply-groups-except g2;\n    ri402839 {\n        instance-type virtual-router;\n    }\n}\n", "ri402839"},
	} {
		if _, err := compile9657(t, tc.text, false); err != nil {
			t.Errorf("#9657 %s: the apply statement is not an instance, so nothing collides; strict refused: %v", tc.name, err)
		}
		cfg, err := compile9657(t, tc.text, true)
		if err != nil {
			t.Fatalf("lenient %s: %v", tc.name, err)
		}
		if names := riNames9657(cfg); len(names) != 1 || names[0] != tc.want {
			t.Errorf("#9657 %s: want exactly [%s], got %v; the apply statement became a routing instance", tc.name, tc.want, names)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "QUARANTINE") {
				t.Errorf("#9657 %s: a real instance was quarantined against the apply statement: %q", tc.name, w)
			}
		}
	}
	// Quoting does not make the keyword an instance name. The #9323 validator
	// skips these statements by name, and a quote does not survive rendering,
	// which an HA peer reparses. The quoted spelling must compile like the
	// unquoted one, before and after a render and reparse. A quoted
	// "apply-groups" never reaches this predicate: group expansion takes it as
	// the statement by name, so expansion owns that case.
	for _, kw := range []string{"apply-macro", "apply-groups-except"} {
		quoted := "routing-instances {\n    \"" + kw + "\" {\n        instance-type virtual-router;\n    }\n" +
			"    ri7 {\n        instance-type virtual-router;\n    }\n}\n"
		cfg, err := compile9657(t, quoted, true)
		if err != nil {
			t.Fatalf("lenient quoted %s: %v", kw, err)
		}
		if names := riNames9657(cfg); len(names) != 1 || names[0] != "ri7" {
			t.Errorf("#9657: a quoted %q stanza must not compile as a routing instance, got %v", kw, names)
		}
		scfg, err := compile9657(t, quoted, false)
		if err != nil {
			t.Errorf("#9657: the shape cannot prove an instance was meant, so strict must not refuse the %q stanza: %v", kw, err)
		}
		for _, c := range []struct {
			path string
			cfg  *Config
		}{{"strict", scfg}, {"lenient", cfg}} {
			if c.cfg == nil {
				continue
			}
			if !keywordNameWarned9657(c.cfg) {
				t.Errorf("#9657: the %s path must warn that %q cannot name a routing instance, or the instance vanishes "+
					"silently; got %v", c.path, kw, c.cfg.Warnings)
			}
		}
		tree, errs := NewParser(quoted).Parse()
		if len(errs) > 0 {
			t.Fatalf("fixture must parse: %v", errs)
		}
		rendered := tree.Format()
		rcfg, err := compile9657(t, rendered, true)
		if err != nil {
			t.Fatalf("lenient rendered %s: %v\n%s", kw, err, rendered)
		}
		if a, b := strings.Join(riNames9657(cfg), ","), strings.Join(riNames9657(rcfg), ","); a != b {
			t.Errorf("#9657: quoted %q compiles to [%s] but its rendered text reparses to [%s]; an HA peer would disagree",
				kw, a, b)
		}
	}
}

// Group expansion walks an applied group only down to the context of its
// apply-groups statement. A group applied under system contributes its system
// subtree; its routing-instances never land, so they are not counted.
func TestTableIDGateIgnoresAGroupAppliedUnderAnotherStanza_9657(t *testing.T) {
	assertFixtureCollides9657(t)
	text := group9657("g1", false) + "system {\n    apply-groups g1;\n    host-name fw;\n}\n" + activeRI7_9657
	if _, err := compile9657(t, text, false); err != nil {
		t.Errorf("#9657: g1 is applied only under system, so its ri116 never lands; the strict path refused: %v", err)
	}
	cfg, err := compile9657(t, text, true)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if names := riNames9657(cfg); len(names) != 1 || names[0] != "ri7" {
		t.Errorf("fixture: the runtime must confirm that ri116 never lands, got %v", names)
	}
}

func keywordNameWarned9657(c *Config) bool {
	for _, w := range c.Warnings {
		if strings.Contains(w, "cannot name a routing instance") {
			return true
		}
	}
	return false
}

// Every real spelling of the statements commits, in both compiler cores. A
// two-key statement is never warned, including a macro whose key is a
// routing-instance keyword. A one-key stanza carrying a routing-instance
// keyword is warned but never refused: a flat statement whose macro or group is
// named after a routing-instance keyword has exactly that shape, so for those
// spellings only "commits" is asserted.
func TestApplyStatementSpellingsStillCommit_9657(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"braced macro", "routing-instances {\n    apply-macro M {\n        k v;\n    }\n}\n"},
		{"braced macro with an interface key", "routing-instances {\n    apply-macro M {\n        interface ge-0/0/0.0;\n    }\n}\n"},
		{"packed macro", "routing-instances {\n    apply-macro M k v;\n}\n"},
	} {
		cfg, err := compile9657(t, tc.text, false)
		if err != nil {
			t.Errorf("#9657 %s: a valid apply statement must commit, got %v", tc.name, err)
			continue
		}
		if keywordNameWarned9657(cfg) {
			t.Errorf("#9657 %s: a two-key apply statement is always the statement and must not be warned: %v", tc.name, cfg.Warnings)
		}
	}
	const any, yes, no = "any", "yes", "no"
	for _, tc := range []struct {
		name string
		cmds []string
		warn string
	}{
		{"flat macro", []string{"set routing-instances apply-macro M k v"}, no},
		{"flat apply-groups-except", []string{"set groups g2 system host-name x", "set routing-instances apply-groups-except g2"}, no},
		{"flat macro named after a routing-instance keyword", []string{"set routing-instances apply-macro interface k v"}, any},
		{"flat apply-groups-except naming a keyword-named group", []string{"set groups interface system host-name x", "set routing-instances apply-groups-except interface"}, any},
		{"flat instance written under the apply-macro name", []string{"set routing-instances apply-macro instance-type virtual-router"}, yes},
	} {
		for _, core := range []string{"CompileConfig", "CompileConfigForNode"} {
			var cfg *Config
			var err error
			if core == "CompileConfig" {
				cfg, err = CompileConfig(setTree9622(t, tc.cmds...))
			} else {
				cfg, err = CompileConfigForNode(setTree9622(t, tc.cmds...), 0)
			}
			if err != nil {
				t.Errorf("#9657 %s (%s): an apply statement must never be refused, got %v", tc.name, core, err)
				continue
			}
			if got := keywordNameWarned9657(cfg); (tc.warn == yes && !got) || (tc.warn == no && got) {
				t.Errorf("#9657 %s (%s): keyword-name warning = %v, want %s; warnings=%v", tc.name, core, got, tc.warn, cfg.Warnings)
			}
		}
	}
}

// A compile without node variables expands a reference unresolved, so a group
// literally named "${node}" applied by `apply-groups "${node}"` lands as is.
// Neither node0's nor node1's expansion finds that group, so the pre-expansion
// view must count the unresolved reference or the collision passes strict.
func TestTableIDGateCountsALiteralNodeVariableGroup_9657(t *testing.T) {
	assertFixtureCollides9657(t)
	text := group9657("\"${node}\"", false) + "apply-groups \"${node}\";\n" + activeRI7_9657
	if _, err := compile9657(t, text, false); err == nil || !strings.Contains(err.Error(), "table-id collision") {
		t.Errorf("#9657: the group literally named ${node} lands on a compile without node variables, so ri116 "+
			"collides with ri7 and the strict path must refuse, got %v", err)
	}
	cfg, err := compile9657(t, text, true)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	quarantined := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "QUARANTINED") {
			quarantined = true
		}
	}
	if !quarantined {
		t.Errorf("control: the runtime must see both instances and quarantine one; instances=%v warnings=%v",
			riNames9657(cfg), cfg.Warnings)
	}
}
