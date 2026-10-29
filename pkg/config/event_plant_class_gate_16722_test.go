package config

import (
	"strings"
	"testing"
)

// #16722: the stamping gate must be a provable no-op detector — it may
// skip the two full lenient compiles only when neither tree can compile
// or raw-carry a change-configuration commands payload. These rows pin
// both directions: payload shapes (direct, nested, grouped, packed,
// inherited, policy-local apply-groups) must NOT skip, and configs with
// no commands payload (including keyword lookalikes outside
// event-options) MUST skip.

func gate16722Hier(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse %q: %v", src, errs)
	}
	return tree
}

func gate16722Flat(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand %q: %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", line, err)
		}
	}
	return tree
}

func TestTreeMayHaveEventCommands16722(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
		want bool
	}{
		{"nil tree", nil, false},
		{"empty tree", &ConfigTree{}, false},
		{"host-name only",
			gate16722Hier(t, `system { host-name fw; }`), false},
		{"policy without commands",
			gate16722Hier(t, `event-options { policy p { events ping_test_failed; } }`), false},
		{"policy with plant-class but no commands",
			gate16722Hier(t, `event-options { policy p { events e; plant-class alice; } }`), false},
		{"bare commands keyword",
			gate16722Hier(t, `event-options { policy p { events e; then { change-configuration { commands; } } } }`), false},
		{"direct commands block",
			gate16722Hier(t, `event-options { policy p { events e; then { change-configuration { commands "set system host-name x"; } } } }`), true},
		{"direct commands packed",
			gate16722Flat(t,
				"set event-options policy p events ping_test_failed",
				`set event-options policy p then change-configuration commands "set system host-name x"`), true},
		{"flat child-shape commands",
			func() *ConfigTree {
				tree := &ConfigTree{}
				if err := tree.SetPath([]string{"event-options", "policy", "p", "events", "ping_test_failed"}); err != nil {
					t.Fatal(err)
				}
				if err := tree.SetPath([]string{"event-options", "policy", "p", "then", "change-configuration", "commands", "set system host-name x"}); err != nil {
					t.Fatal(err)
				}
				return tree
			}(), true},
		{"nested one-key-container policy",
			gate16722Hier(t, `event-options { policy { p { events e; then { change-configuration { commands "set system host-name x"; } } } } }`), true},
		{"grouped commands hier",
			gate16722Hier(t, `groups { g { event-options { policy p { events e; then { change-configuration { commands "set system host-name x"; } } } } } } apply-groups g;`), true},
		{"grouped commands flat",
			gate16722Flat(t,
				"set groups g event-options policy p events ping_test_failed",
				`set groups g event-options policy p then change-configuration commands "set system host-name x"`,
				"set apply-groups g"), true},
		{"grouped policy without commands",
			gate16722Hier(t, `groups { g { event-options { policy p { events e; } } } } apply-groups g;`), false},
		{"policy-local apply-groups",
			gate16722Hier(t, `event-options { policy p { events e; apply-groups g; } }`), true},
		{"policy-local apply-groups-except",
			gate16722Hier(t, `event-options { policy p { events e; apply-groups-except g; } }`), true},
		{"unrelated then commands lookalike",
			gate16722Hier(t, `firewall { family inet { filter f { term t { then { change-configuration { commands "x"; } } } } } }`), false},
		{"unrelated description mentioning commands",
			gate16722Flat(t,
				"set system host-name fw",
				"set interfaces ge-0/0/0 description change-configuration commands"), false},
		{"inactive policy still counts (compiled prunes, raw fallback does not)",
			gate16722Hier(t, `event-options { inactive: policy p { events e; then { change-configuration { commands "set system host-name x"; } } } }`), true},
		{"compact event-options policy with commands",
			gate16722Hier(t, `event-options policy p { events e; then { change-configuration { commands "set system host-name x"; } } }`), true},
		{"compact event-options policy without commands",
			gate16722Hier(t, `event-options policy p { events e; }`), false},
		{"compact event-options policy with only plant-class",
			gate16722Hier(t, `event-options policy p { events e; plant-class alice; }`), false},
		{"compact event-options policy with packed commands",
			gate16722Hier(t, `event-options policy p then change-configuration commands "set system host-name x";`), true},
		{"event-options without a policy does not count",
			gate16722Hier(t, `event-options then change-configuration commands "set system host-name x";`), false},

		{"compact event-options policy inside a group",
			gate16722Hier(t, `groups { g { event-options policy p { events e; then { change-configuration { commands "set system host-name x"; } } } } } apply-groups g;`), true},
		{"compact event-options policy pack is first sibling",
			gate16722Hier(t, `system { host-name a; } event-options policy p { events e; then { change-configuration { commands "set system host-name x"; } } }`), true},
		{"compact event-options policy in group body",
			gate16722Hier(t, `groups { g { event-options policy p { events e; then { change-configuration { commands "set system host-name x"; } } } } } apply-groups g;`), true},
		{"packed policy identity must not mask unrelated policy commands",
			gate16722Hier(t, `event-options { policy q { events e; } } event-options policy p { events e; then { change-configuration { commands "set system host-name x"; } } }`), true},
		{"compact one-key policy container with commands",
			gate16722Hier(t, `event-options policy { p { events e; then { change-configuration { commands "set system host-name x"; } } } }`), true},
		{"compact one-key policy container in a group body",
			gate16722Hier(t, `groups { g { event-options policy { p { events e; then { change-configuration { commands "set system host-name x"; } } } } } } apply-groups g;`), true},
		{"elided policy-name spelling has no policy commands",
			gate16722Hier(t, `event-options policy { events e; then { change-configuration { commands "set system host-name x"; } } }`), false},


	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := treeMayHaveEventCommands9984(tc.tree); got != tc.want {
				t.Fatalf("treeMayHaveEventCommands9984 = %v, want %v", got, tc.want)
			}
		})
	}
}

// The gate is a pure skip: when it fires on both trees, stamping must
// leave the after tree byte-identical (no plant-class node invented, no
// commands disturbed). When either side carries commands, the existing
// stamping semantics apply unchanged.
func TestStampGateSkipsOnlyCommandless16722(t *testing.T) {
	// Commandless mutation: host-name edit on a config whose only event
	// policy has no commands. Stamping must be a no-op.
	before := gate16722Hier(t, `system { host-name a; } event-options { policy p { events e; plant-class alice; } }`)
	after := before.Clone()
	if err := after.SetPath([]string{"system", "host-name", "b"}); err != nil {
		t.Fatalf("SetPath host-name: %v", err)
	}
	want := after.FormatSet()
	StampChangedEventPlantClasses(before, after, "mallory")
	if got := after.FormatSet(); got != want {
		t.Fatalf("commandless stamp mutated the tree:\nbefore-stamp:\n%s\nafter-stamp:\n%s", want, got)
	}
	if strings.Contains(after.FormatSet(), "mallory") {
		t.Fatalf("commandless stamp planted mallory:\n%s", after.FormatSet())
	}

	// Commands present on the after side only (policy created by the
	// mutation): must stamp exactly as before the gate existed.
	before2 := gate16722Hier(t, `system { host-name a; }`)
	after2 := gate16722Hier(t, `system { host-name a; } event-options { policy p { events e; then { change-configuration { commands "set system host-name x"; } } } }`)
	StampChangedEventPlantClasses(before2, after2, "alice")
	if pol := compiledPlantClass9984(t, after2); pol.PlantClass != "alice" {
		t.Fatalf("new policy with commands stamped PlantClass=%q, want alice", pol.PlantClass)
	}

	// Commands present on the before side only (policy deleted by the
	// mutation): stamping the survivor-less after tree must not invent
	// a policy or marker.
	before3 := gate16722Hier(t, `event-options { policy p { events e; plant-class alice; then { change-configuration { commands "set system host-name x"; } } } }`)
	after3 := gate16722Hier(t, `system { host-name a; }`)
	StampChangedEventPlantClasses(before3, after3, "mallory")
	if strings.Contains(after3.FormatSet(), "event-options") {
		t.Fatalf("stamp after policy deletion invented event-options:\n%s", after3.FormatSet())
	}
}

// #17762: compact event-options/policy spelling carries its identity on the
// event-options node, so the raw gate must still run the stamper before
// normalization turns it into the ordinary hierarchical shape.
func TestCompactEventOptionsPolicyPlantClass17762(t *testing.T) {
	after := gate16722Hier(t, `event-options policy p { events e; then { change-configuration { commands "set system host-name x"; } } }`)
	if !treeMayHaveEventCommands9984(after) {
		t.Fatal("compact event-options policy with commands was skipped by the planting-class gate")
	}
	StampChangedEventPlantClasses(nil, after, "alice")
	if pol := compiledPlantClass9984(t, after); pol.PlantClass != "alice" {
		t.Fatalf("compact policy PlantClass=%q, want alice", pol.PlantClass)
	}
}

func TestMalformedCompactEventOptionsGateDoesNotPanic17762(t *testing.T) {
	malformed := &Node{Keys: []string{"event-options", "policy"}}
	then := &Node{Keys: []string{"then"}}
	changeConfig := &Node{Keys: []string{"change-configuration"}}
	commands := &Node{Keys: []string{"commands", "set system host-name x"}, IsLeaf: true}
	changeConfig.Children = []*Node{commands}
	then.Children = []*Node{changeConfig}
	malformed.Children = []*Node{then}
	tree := &ConfigTree{Children: []*Node{malformed}}
	if treeMayHaveEventCommands9984(tree) {
		t.Fatal("malformed compact policy identity must not be attributed")
	}
}

func TestCompactOneKeyPolicyPlantClassForgeryRestamped17762(t *testing.T) {
	before := gate16722Hier(t, `event-options policy { p { events e; plant-class alice; then { change-configuration { commands "set system host-name x"; } } } }`)
	after := gate16722Hier(t, `event-options policy { p { events e; plant-class super-user; then { change-configuration { commands "set system host-name x"; } } } }`)
	StampChangedEventPlantClasses(before, after, "alice")
	if pol := compiledPlantClass9984(t, after); pol.PlantClass != "alice" {
		t.Fatalf("forged one-key-container PlantClass=%q, want alice", pol.PlantClass)
	}
	if pol := compiledPlantClass9984(t, after); len(pol.ThenCommands) != 1 ||
		pol.ThenCommands[0] != "set system host-name x" {
		t.Fatalf("restamping disturbed one-key-container commands: %q", pol.ThenCommands)
	}
}

func TestCompactOneKeyPolicySuperuserQuarantined17762(t *testing.T) {
	sources := map[string]string{
		"top-level": `event-options policy { p { events e; plant-class super-user; then { change-configuration { commands "set system host-name x"; } } } }`,
		"group-body": `groups { g { event-options policy { p { events e; plant-class super-user; then { change-configuration { commands "set system host-name x"; } } } } } } apply-groups g;`,
	}
	for name, source := range sources {
		t.Run(name, func(t *testing.T) {
			tree := gate16722Hier(t, source)
			if pol := compiledPlantClass9984(t, tree); pol.PlantClass != EventPlantClassSuperuser ||
				len(pol.ThenCommands) != 1 {
				t.Fatalf("fixture PlantClass=%q commands=%q, want executable super-user policy",
					pol.PlantClass, pol.ThenCommands)
			}
			QuarantineUntrustedEventPlantClasses(tree)
			pol := compiledPlantClass9984(t, tree)
			if pol.PlantClass != "" {
				t.Fatalf("quarantined PlantClass=%q, want empty marker", pol.PlantClass)
			}
			if len(pol.ThenCommands) != 1 || pol.ThenCommands[0] != "set system host-name x" {
				t.Fatalf("quarantine disturbed commands: %q", pol.ThenCommands)
			}
		})
	}
}
