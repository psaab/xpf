package config

import (
	"fmt"
	"strings"
	"testing"
)

// #9622: a routing instance may not take a name the daemon reserves for its own
// VRF. Before this gate, `routing-instances mgmt` committed clean and every
// apply planned two vrf-mgmt specs with different tables.

func setTree9622(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		p, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", cmd, err)
		}
	}
	return tree
}

var riBase9622 = []string{
	"set interfaces ge-0/0/1 unit 0 family inet address 10.1.1.1/24",
}

func TestReservedRoutingInstanceNameIsRejectedStrict_9622(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"top-level", []string{
			"set routing-instances mgmt instance-type virtual-router",
			"set routing-instances mgmt interface ge-0/0/1.0",
		}},
		{"applied group", []string{
			"set groups g1 routing-instances mgmt instance-type virtual-router",
			"set groups g1 routing-instances mgmt interface ge-0/0/1.0",
			"set apply-groups g1",
		}},
		{"node group via ${node}", []string{
			"set groups node0 routing-instances mgmt instance-type virtual-router",
			"set groups node1 routing-instances blue instance-type virtual-router",
			`set apply-groups "${node}"`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := setTree9622(t, append(append([]string{}, riBase9622...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("#9622: a routing instance named %q committed clean on the strict path; the daemon "+
					"creates that VRF itself, and an operator instance of the same name merges with it", ManagementVRFInstanceName)
			}
			if !strings.Contains(err.Error(), "reserved for") || !strings.Contains(err.Error(), "management VRF") {
				t.Errorf("#9622: the rejection must say the name is reserved for the management VRF: %v", err)
			}
		})
	}
}

func TestReservedRoutingInstanceNameIsQuarantinedLenient_9622(t *testing.T) {
	tree := setTree9622(t, append(append([]string{}, riBase9622...),
		"set routing-instances mgmt instance-type virtual-router",
		"set routing-instances mgmt interface ge-0/0/1.0",
		"set routing-instances blue instance-type virtual-router",
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("#9622: the tolerant path must still boot a persisted config with a reserved instance name: %v", err)
	}
	var names []string
	for _, ri := range cfg.RoutingInstances {
		names = append(names, ri.Name)
	}
	for _, n := range names {
		if n == ManagementVRFInstanceName {
			t.Errorf("#9622: the lenient compile kept routing instance %q; it must be QUARANTINED so the daemon never plans a second vrf-mgmt (instances: %v)", n, names)
		}
	}
	if len(names) != 1 || names[0] != "blue" {
		t.Errorf("#9622 control: the unreserved sibling must survive untouched, got %v", names)
	}
	if n := countReservedWarnings9622(cfg.Warnings); n != 1 {
		t.Errorf("#9622: the quarantine must be reported exactly once in cfg.Warnings, got %d: %v", n, cfg.Warnings)
	}
}

// Controls: names that only LOOK like the reserved one are ordinary instances.
// Instance names are case-sensitive, and the VRF device is "vrf-"+name, so
// neither "MGMT" nor "vrf-mgmt" (device "vrf-vrf-mgmt") collides.
func TestNearReservedRoutingInstanceNamesStillCommit_9622(t *testing.T) {
	for _, name := range []string{"mgmt1", "vrf-mgmt", "MGMT", "oob-mgmt"} {
		tree := setTree9622(t, append(append([]string{}, riBase9622...),
			"set routing-instances "+name+" instance-type virtual-router",
			"set routing-instances "+name+" interface ge-0/0/1.0",
		)...)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Errorf("#9622 control: routing instance %q must commit clean: %v", name, err)
			continue
		}
		if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != name {
			t.Errorf("#9622 control: routing instance %q did not compile as an ordinary instance", name)
		}
	}
}

// countReservedWarnings9622 counts the warnings that report the reserved
// management instance name.
func countReservedWarnings9622(warnings []string) int {
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, "reserved") && strings.Contains(w, fmt.Sprintf("%q", ManagementVRFInstanceName)) {
			n++
		}
	}
	return n
}

func parseText9622(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v\n%s", perrs, text)
	}
	return tree
}

// The hierarchical spellings, parsed from text the way a loaded, peer-synced or
// day-0 config file is. The brace-elided form is a LEAF whose Keys tail carries
// the body (#8787). compileRoutingInstances builds an instance from it, so the
// gate must see it: the shared name scan used to skip every leaf, and this
// spelling committed clean with only the quarantine warning.
func TestReservedRoutingInstanceNameIsRejectedHierarchical_9622(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"braced", "routing-instances {\n    mgmt {\n        instance-type virtual-router;\n    }\n}\n"},
		{"brace-elided leaf", "routing-instances {\n    mgmt instance-type virtual-router;\n}\n"},
		{"brace-elided in an applied group", "groups {\n    g1 {\n        routing-instances {\n" +
			"            mgmt instance-type virtual-router;\n        }\n    }\n}\napply-groups g1;\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Positive control: the lenient compile builds the instance and
			// quarantines it, so the strict reject below is about a real
			// instance and not a stanza that never compiled.
			lcfg, err := CompileConfigLenient(parseText9622(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if countReservedWarnings9622(lcfg.Warnings) != 1 {
				t.Fatalf("fixture: the lenient compile did not quarantine %q exactly once, so this spelling "+
					"may never have become an instance: %v", ManagementVRFInstanceName, lcfg.Warnings)
			}
			if _, err := CompileConfig(parseText9622(t, tc.text)); err == nil || !strings.Contains(err.Error(), "reserved for") {
				t.Fatalf("#9622: the %s spelling of routing instance %q must be rejected on the strict path, got %v",
					tc.name, ManagementVRFInstanceName, err)
			}
		})
	}
}

// Cluster nodes compile through CompileConfigForNode*, the second compiler core,
// which carries its own call to the gate.
func TestReservedRoutingInstanceNameOnTheNodeCompilePaths_9622(t *testing.T) {
	cmds := append(append([]string{}, riBase9622...),
		"set groups node0 routing-instances mgmt instance-type virtual-router",
		"set groups node0 routing-instances blue instance-type virtual-router",
		`set apply-groups "${node}"`,
	)
	if _, err := CompileConfigForNode(setTree9622(t, cmds...), 0); err == nil || !strings.Contains(err.Error(), "reserved for") {
		t.Fatalf("#9622: CompileConfigForNode must reject the reserved instance on the strict path, got %v", err)
	}
	cfg, err := CompileConfigForNodeLenient(setTree9622(t, cmds...), 0)
	if err != nil {
		t.Fatalf("#9622: CompileConfigForNodeLenient must still boot: %v", err)
	}
	var names []string
	for _, ri := range cfg.RoutingInstances {
		names = append(names, ri.Name)
	}
	if len(names) != 1 || names[0] != "blue" {
		t.Errorf("#9622: node0's lenient compile must drop %q and keep blue, got %v", ManagementVRFInstanceName, names)
	}
	if n := countReservedWarnings9622(cfg.Warnings); n != 1 {
		t.Errorf("#9622: want exactly one warning reporting the reserved instance, got %d: %v", n, cfg.Warnings)
	}
}

// A reserved name takes no part in the #3855 table-id collision gate. The
// runtime quarantines it before its own collision pass, so it never claims a
// table; the AST gate must judge the same set. "mgmt" and "z1061437" fold to
// one stable table id.
func TestReservedNameTakesNoPartInTableIDCollision_9622(t *testing.T) {
	const sibling = "z1061437"
	if a, b := StableRoutingInstanceTableID(ManagementVRFInstanceName), StableRoutingInstanceTableID(sibling); a != b {
		t.Fatalf("fixture: %q and %q must fold to one table id, got %d and %d", ManagementVRFInstanceName, sibling, a, b)
	}
	cmds := append(append([]string{}, riBase9622...),
		"set routing-instances mgmt instance-type virtual-router",
		"set routing-instances "+sibling+" instance-type virtual-router",
	)
	_, err := CompileConfig(setTree9622(t, cmds...))
	if err == nil || !strings.Contains(err.Error(), "reserved for") || strings.Contains(err.Error(), "collision") {
		t.Fatalf("#9622: the strict path must reject the reserved name, not report a table-id collision against it: %v", err)
	}
	cfg, err := CompileConfigLenient(setTree9622(t, cmds...))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	var names []string
	for _, ri := range cfg.RoutingInstances {
		names = append(names, ri.Name)
	}
	if len(names) != 1 || names[0] != sibling {
		t.Errorf("#9622: the lenient compile must keep %q and drop the reserved instance, got %v", sibling, names)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3855") || strings.Contains(w, "collision") {
			t.Errorf("#9622: a warning reports a table-id collision the runtime never has: %q", w)
		}
	}
}

// The shared name scan now sees the brace-elided leaf instance, so the #3855
// table-id collision gate sees a packed instance as well. The colliding pair is
// found by search, not hardcoded, so the cell does not depend on one hash value.
// Both instances here are effective. An instance declared only in a group
// nothing applies is not counted (#9657).
func TestPackedLeafInstancesJoinTheTableIDCollisionGate_9622(t *testing.T) {
	byID := map[int]string{}
	var a, b string
	for i := 0; a == ""; i++ {
		if i > 1_000_000 {
			t.Fatal("fixture: no colliding instance-name pair found")
		}
		n := fmt.Sprintf("ri%d", i)
		id := StableRoutingInstanceTableID(n)
		if prev, ok := byID[id]; ok {
			a, b = prev, n
		}
		byID[id] = n
	}
	braced := "routing-instances {\n    " + a + " {\n        instance-type virtual-router;\n    }\n    " +
		b + " {\n        instance-type virtual-router;\n    }\n}\n"
	packed := "routing-instances {\n    " + a + " instance-type virtual-router;\n    " + b + " instance-type virtual-router;\n}\n"
	for _, tc := range []struct{ name, text string }{{"braced control", braced}, {"brace-elided", packed}} {
		if _, err := CompileConfig(parseText9622(t, tc.text)); err == nil || !strings.Contains(err.Error(), "table-id collision") {
			t.Errorf("#3855/#9622 %s: instances %q and %q fold to one kernel table and must be rejected on the strict "+
				"path, got %v", tc.name, a, b, err)
		}
	}
}
