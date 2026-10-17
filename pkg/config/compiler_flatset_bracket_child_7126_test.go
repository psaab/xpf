package config

import (
	"strings"
	"testing"
)

// #7126 — a compiler that reads a leaf's own Keys[1:] AND its Children, exactly
// as CLAUDE.md and docs/config-schema.md prescribe, STILL drops every value past
// the first when the operator authors a bracket list through the flat-set path.
//
// The discriminator is mechanical: for a leaf setSchema declares
// `children: nil` and does NOT mark `multi: true`, SetPath files
// `set <path> <leaf> [ v1 v2 ]` as ONE child whose Keys are ["v1","v2"], so
// `child.Name()` (== Keys[0]) returns v1 and discards the rest. Reading
// Children is not the same as reading every KEY of each child. The
// hierarchical parser puts the list on the node's own tail instead, which is
// why these sites survive every brace-authored test.
//
// Two sites, and neither is a value the operator can see go missing:
//
//   - routing-options rib-groups <g> import-rib — the inter-VRF route-leak
//     membership list. A rib-group that should pull into two RIBs pulls into
//     one, so the second table's leak never happens, with no diagnostic, while
//     `show configuration` renders the full list back.
//   - event-options policy <p> events — the trigger set of an event policy. A
//     lost trigger means the automation never fires for part of what was
//     authored.
//
// Every test below runs ALL FIVE spellings the Junos grammar admits, because a
// fix that lands in one AST arm and not the other is exactly the failure this
// class is made of.

func ribImports(t *testing.T, cfg *Config, group string) []string {
	t.Helper()
	rg, ok := cfg.RoutingOptions.RibGroups[group]
	if !ok {
		t.Fatalf("rib-group %q not compiled (have %d groups)", group, len(cfg.RoutingOptions.RibGroups))
	}
	return rg.ImportRibs
}

func policyEvents(t *testing.T, cfg *Config, name string) []string {
	t.Helper()
	for _, ep := range cfg.EventOptions {
		if ep.Name == name {
			return ep.Events
		}
	}
	t.Fatalf("event policy %q not compiled (have %d policies)", name, len(cfg.EventOptions))
	return nil
}

func compileBraceStrict7126(t *testing.T, body string) *Config {
	t.Helper()
	p := NewParser(body)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", body, errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", body, err)
	}
	return cfg
}

// compileSetStrict7126 goes through ParseSetCommand + SetPath, the path `set`,
// `load set` and display-set replay take. NewParser must NOT be used for set
// syntax: it treats newlines as whitespace and merges every line into one node,
// which would hide exactly the shape this test exists for.
func compileSetStrict7126(t *testing.T, cmds ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func wantValues(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v (len %d), want %v", what, got, len(got), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}
}

// ribPreambleBrace / ribPreambleSet define the routing-instances whose ribs the
// import-rib lists below name. `import-rib` targets are cross-checked at commit
// (#2226), so a synthetic rib name would make every spelling fail for a reason
// that has nothing to do with #7126.
const ribPreambleBrace = `routing-instances { dmz-vr { instance-type virtual-router; } ` +
	`tunnel-vr { instance-type virtual-router; } } `

var ribPreambleSet = []string{
	"set routing-instances dmz-vr instance-type virtual-router",
	"set routing-instances tunnel-vr instance-type virtual-router",
}

func ribBrace(t *testing.T, body string) *Config {
	t.Helper()
	return compileBraceStrict7126(t, ribPreambleBrace+body)
}

func ribSet(t *testing.T, cmds ...string) *Config {
	t.Helper()
	return compileSetStrict7126(t, append(append([]string{}, ribPreambleSet...), cmds...)...)
}

// Site 1. The flat-set bracket (D) is the spelling that dropped; the other four
// are controls that must not regress while D is fixed.
func Test_7126_RibGroupImportRibEverySpelling(t *testing.T) {
	t.Run("A-hier-bracket", func(t *testing.T) {
		cfg := ribBrace(t, `routing-options { rib-groups { rg1 { import-rib [ dmz-vr.inet.0 inet.0 ]; } } }`)
		wantValues(t, "ImportRibs", ribImports(t, cfg, "rg1"), "dmz-vr.inet.0", "inet.0")
	})
	t.Run("B-hier-block", func(t *testing.T) {
		cfg := ribBrace(t, `routing-options { rib-groups { rg1 { import-rib { dmz-vr.inet.0; inet.0; } } } }`)
		wantValues(t, "ImportRibs", ribImports(t, cfg, "rg1"), "dmz-vr.inet.0", "inet.0")
	})
	t.Run("C-hier-repeat", func(t *testing.T) {
		// Repeated hierarchical statements land as SIBLING nodes. FindChild
		// returned the first and stopped, so this spelling dropped inet.0 even
		// though the flat-set repeated spelling below — the same configuration,
		// filed as CHILDREN of ONE node — accumulated correctly.
		cfg := ribBrace(t, `routing-options { rib-groups { rg1 { import-rib dmz-vr.inet.0; import-rib inet.0; } } }`)
		wantValues(t, "ImportRibs", ribImports(t, cfg, "rg1"), "dmz-vr.inet.0", "inet.0")
	})
	t.Run("D-set-bracket", func(t *testing.T) {
		cfg := ribSet(t, `set routing-options rib-groups rg1 import-rib [ dmz-vr.inet.0 inet.0 ]`)
		wantValues(t, "ImportRibs", ribImports(t, cfg, "rg1"), "dmz-vr.inet.0", "inet.0")
	})
	t.Run("E-set-repeat", func(t *testing.T) {
		cfg := ribSet(t,
			`set routing-options rib-groups rg1 import-rib dmz-vr.inet.0`,
			`set routing-options rib-groups rg1 import-rib inet.0`)
		wantValues(t, "ImportRibs", ribImports(t, cfg, "rg1"), "dmz-vr.inet.0", "inet.0")
	})
	t.Run("D-set-bracket-three-ribs", func(t *testing.T) {
		// Two values can be kept by an off-by-one that still truncates a
		// longer list; three cannot.
		cfg := ribSet(t, `set routing-options rib-groups rg1 import-rib [ dmz-vr.inet.0 tunnel-vr.inet.0 inet.0 ]`)
		wantValues(t, "ImportRibs", ribImports(t, cfg, "rg1"), "dmz-vr.inet.0", "tunnel-vr.inet.0", "inet.0")
	})
	t.Run("D-set-bracket-unbracketed-tail", func(t *testing.T) {
		// `set … import-rib a b` files the identical AST as the bracketed form
		// (the lexer strips the brackets), so it must compile the same list.
		cfg := ribSet(t, `set routing-options rib-groups rg1 import-rib dmz-vr.inet.0 inet.0`)
		wantValues(t, "ImportRibs", ribImports(t, cfg, "rg1"), "dmz-vr.inet.0", "inet.0")
	})
}

// The rib-group body is reached by TWO arms in compileRoutingOptions — a
// named-instance arm and a direct-child arm — which held byte-identical
// import-rib readers, and #7126 names the hazard that creates: a fix landing in
// only one arm leaves the defect in the other. They now share compileRibGroup,
// so this exercises that single body directly, over the five AST shapes, rather
// than trusting that whichever arm a given config happens to take was the one
// that got fixed.
//
// Measured at 22e17c2de: the named arm is INERT at HEAD. It selects with
// rgNode.FindChildren(""), which matches only a child whose first key is the
// empty string, and neither the brace parser nor SetPath produces one — the
// direct-child arm does all the work. The duplication was therefore latent
// rather than live, which is exactly why it survived: no test could have caught
// a divergence between the two.
func Test_7126_CompileRibGroupBodyEveryShape(t *testing.T) {
	cases := []struct {
		name string
		node *Node
		want []string
	}{
		{
			name: "hierarchical bracket / packed — tail on the node's own Keys",
			node: &Node{Keys: []string{"rg1"}, Children: []*Node{
				{Keys: []string{"import-rib", "inet.0", "inet.2"}},
			}},
			want: []string{"inet.0", "inet.2"},
		},
		{
			name: "hierarchical block / flat-set repeated — one child per rib",
			node: &Node{Keys: []string{"rg1"}, Children: []*Node{
				{Keys: []string{"import-rib"}, Children: []*Node{
					{Keys: []string{"inet.0"}}, {Keys: []string{"inet.2"}},
				}},
			}},
			want: []string{"inet.0", "inet.2"},
		},
		{
			// THE #7126 SHAPE.
			name: "flat-set bracket — every rib on ONE child's Keys",
			node: &Node{Keys: []string{"rg1"}, Children: []*Node{
				{Keys: []string{"import-rib"}, Children: []*Node{
					{Keys: []string{"inet.0", "inet.2"}},
				}},
			}},
			want: []string{"inet.0", "inet.2"},
		},
		{
			name: "repeated hierarchical statements — SIBLING import-rib nodes",
			node: &Node{Keys: []string{"rg1"}, Children: []*Node{
				{Keys: []string{"import-rib", "inet.0"}},
				{Keys: []string{"import-rib", "inet.2"}},
			}},
			want: []string{"inet.0", "inet.2"},
		},
		{
			name: "no import-rib at all",
			node: &Node{Keys: []string{"rg1"}},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rg := compileRibGroup("rg1", tc.node)
			if rg.Name != "rg1" {
				t.Fatalf("Name = %q, want rg1", rg.Name)
			}
			wantValues(t, "ImportRibs", rg.ImportRibs, tc.want...)
		})
	}
}

// A truncated import-rib list is not only a value drop, it is a GATE ESCAPE:
// the #2226 cross-reference check iterates ImportRibs, so a rib named in a slot
// the compiler never read could never be rejected. Measured at 22e17c2de,
// `import-rib [ inet.0 does-not-exist.inet.0 ]` committed CLEAN while the
// identical name in slot 0 was rejected. Asserted on THAT validator's own
// wording — a bare err != nil would pass if some other gate rejected the config
// for an unrelated reason.
func Test_7126_RibGroupImportRibTailReachesTheRefValidator(t *testing.T) {
	for _, tc := range []struct{ name, cmd string }{
		{"slot0", `set routing-options rib-groups rg1 import-rib [ does-not-exist.inet.0 inet.0 ]`},
		{"slot1", `set routing-options rib-groups rg1 import-rib [ inet.0 does-not-exist.inet.0 ]`},
		{"slot2", `set routing-options rib-groups rg1 import-rib [ inet.0 dmz-vr.inet.0 does-not-exist.inet.0 ]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, c := range append(append([]string{}, ribPreambleSet...), tc.cmd) {
				path, err := ParseSetCommand(c)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", c, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", c, err)
				}
			}
			_, cerr := CompileConfig(tree)
			if cerr == nil {
				t.Fatal("commit accepted an undefined import-rib target")
			}
			if !strings.Contains(cerr.Error(), "undefined rib") {
				t.Fatalf("rejected by the WRONG gate: %v", cerr)
			}

			// The widened read must not turn an already-persisted config into a
			// boot failure. #2226 already downgrades this rejection on the
			// tolerant load / peer-sync path (lenientRibGroupRefs); newly
			// VISIBLE tail entries have to land on that same downgrade, not
			// beside it.
			cfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("tolerant load must boot through an undefined import-rib: %v", lerr)
			}
			if !warningsContain(cfg.Warnings, "rib-group import-rib reference") {
				t.Fatalf("expected a downgraded import-rib-reference warning, got: %v", cfg.Warnings)
			}
		})
	}
}

// Site 2.
func Test_7126_EventPolicyEventsEverySpelling(t *testing.T) {
	t.Run("A-hier-bracket", func(t *testing.T) {
		cfg := compileBraceStrict7126(t, `event-options { policy p1 { events [ ping_test_failed ping_test_completed ]; } }`)
		wantValues(t, "Events", policyEvents(t, cfg, "p1"), "ping_test_failed", "ping_test_completed")
	})
	t.Run("B-hier-block", func(t *testing.T) {
		cfg := compileBraceStrict7126(t, `event-options { policy p1 { events { ping_test_failed; ping_test_completed; } } }`)
		wantValues(t, "Events", policyEvents(t, cfg, "p1"), "ping_test_failed", "ping_test_completed")
	})
	t.Run("C-hier-repeat", func(t *testing.T) {
		cfg := compileBraceStrict7126(t, `event-options { policy p1 { events ping_test_failed; events ping_test_completed; } }`)
		wantValues(t, "Events", policyEvents(t, cfg, "p1"), "ping_test_failed", "ping_test_completed")
	})
	t.Run("D-set-bracket", func(t *testing.T) {
		cfg := compileSetStrict7126(t, `set event-options policy p1 events [ ping_test_failed ping_test_completed ]`)
		wantValues(t, "Events", policyEvents(t, cfg, "p1"), "ping_test_failed", "ping_test_completed")
	})
	t.Run("E-set-repeat", func(t *testing.T) {
		cfg := compileSetStrict7126(t,
			`set event-options policy p1 events ping_test_failed`,
			`set event-options policy p1 events ping_test_completed`)
		wantValues(t, "Events", policyEvents(t, cfg, "p1"), "ping_test_failed", "ping_test_completed")
	})
	t.Run("D-set-bracket-three-events", func(t *testing.T) {
		cfg := compileSetStrict7126(t, `set event-options policy p1 events [ ping_test_failed ping_test_completed ping_probe_failed ]`)
		wantValues(t, "Events", policyEvents(t, cfg, "p1"), "ping_test_failed", "ping_test_completed", "ping_probe_failed")
	})
	t.Run("D-set-bracket-with-a-then-clause", func(t *testing.T) {
		// The whole point of the trigger set is the remediation it gates, so
		// pin the drop on a policy that actually has one.
		cfg := compileSetStrict7126(t,
			`set event-options policy p1 events [ ping_test_failed ping_test_completed ]`,
			`set event-options policy p1 then change-configuration commands "set system host-name recovered"`)
		wantValues(t, "Events", policyEvents(t, cfg, "p1"), "ping_test_failed", "ping_test_completed")
		ep := cfg.EventOptions[0]
		if len(ep.ThenCommands) != 1 || ep.ThenCommands[0] != "set system host-name recovered" {
			t.Fatalf("ThenCommands = %v, want the single authored command", ep.ThenCommands)
		}
	})
}

// The fabric leaf shares the reader after #7126 single-sourced it, so its own
// five spellings are re-asserted here. #6694's tests already cover it; this
// exists so a change to plainListValues that only the fabric leaf would notice
// still reds inside THIS change's test file rather than only next door.
func Test_7126_SharedReaderKeepsFabricMembersIntact(t *testing.T) {
	t.Run("hier-bracket", func(t *testing.T) {
		cfg := compileBraceStrict7126(t, `interfaces { fab0 { fabric-options { member-interfaces [ ge-0/0/0 ge-0/0/1 ]; } } }`)
		wantValues(t, "FabricMembers", cfg.Interfaces.Interfaces["fab0"].FabricMembers, "ge-0/0/0", "ge-0/0/1")
	})
	t.Run("set-bracket", func(t *testing.T) {
		cfg := compileSetStrict7126(t, `set interfaces fab0 fabric-options member-interfaces [ ge-0/0/0 ge-0/0/1 ]`)
		wantValues(t, "FabricMembers", cfg.Interfaces.Interfaces["fab0"].FabricMembers, "ge-0/0/0", "ge-0/0/1")
	})
}

// plainListValues is the shared body. Pin its contract directly, on hand-built
// nodes, so a caller-level green cannot hide a reader that happens to be right
// only for the shapes those callers exercise.
func Test_7126_PlainListValuesReadsEveryKeyOfEveryChild(t *testing.T) {
	cases := []struct {
		name string
		node *Node
		want []string
	}{
		{
			name: "tail only (hierarchical bracket / packed)",
			node: &Node{Keys: []string{"leaf", "a", "b"}},
			want: []string{"a", "b"},
		},
		{
			name: "one child per value (hierarchical block / flat-set repeated)",
			node: &Node{Keys: []string{"leaf"}, Children: []*Node{
				{Keys: []string{"a"}}, {Keys: []string{"b"}},
			}},
			want: []string{"a", "b"},
		},
		{
			// THE #7126 SHAPE. One child, every value on its Keys.
			name: "one child holding every value (flat-set bracket)",
			node: &Node{Keys: []string{"leaf"}, Children: []*Node{
				{Keys: []string{"a", "b", "c"}},
			}},
			want: []string{"a", "b", "c"},
		},
		{
			name: "tail AND children (mixed authoring merged by the AST)",
			node: &Node{Keys: []string{"leaf", "a"}, Children: []*Node{
				{Keys: []string{"b", "c"}},
			}},
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty tokens are not values",
			node: &Node{Keys: []string{"leaf", "", "a"}, Children: []*Node{
				{Keys: []string{"", "b"}},
			}},
			want: []string{"a", "b"},
		},
		{
			name: "no value at all",
			node: &Node{Keys: []string{"leaf"}},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := plainListValues(tc.node)
			if len(got) != len(tc.want) {
				t.Fatalf("plainListValues = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("plainListValues = %v, want %v", got, tc.want)
				}
			}
		})
	}
	if plainListValues(nil) != nil {
		t.Fatalf("plainListValues(nil) must be nil")
	}
}
