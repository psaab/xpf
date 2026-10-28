package config

import (
	"os"
	"strings"
	"testing"
)

// #17196: the compound/split `family` walk had one shared extractor in
// firewall and three hand copies elsewhere. The sampling copy indexed
// Keys[0] with no guard (panic on an empty-Keys child, the malformed
// persisted/synced AST #4827/#7522 fixed in the other copies), and all
// three copies kept the Keys[1] preference #9883 removed from firewall,
// so `family { bogus inet { … } }` silently discarded the leading junk
// token and installed the trailing family.
//
// The fix moves the extractor to family_members.go as familyMembers and
// routes compileInterfaces, compileForwardingOptionsWithOpts (family
// inet6 mode) and compileSampling through it. Each caller reports an
// unknown member (empty Af, undeclared token, undeclared residue) with
// the #9017-style diagnostic: strict rejects, lenient warns and installs
// nothing.

// emptyKeysTree17196 builds a hand tree for one top whose `family` node
// has a single child with NO keys (the malformed persisted shape).
// top is "sampling", "forwarding" or "interfaces".
func emptyKeysTree17196(top string) *ConfigTree {
	afNode := &Node{Keys: nil, Children: []*Node{{Keys: []string{"output"}}}}
	familyNode := &Node{Keys: []string{"family"}, Children: []*Node{afNode}}
	switch top {
	case "sampling":
		instNode := &Node{Keys: []string{"instance", "i1"}, Children: []*Node{familyNode}}
		sampNode := &Node{Keys: []string{"sampling"}, Children: []*Node{instNode}}
		return &ConfigTree{Children: []*Node{{Keys: []string{"forwarding-options"}, Children: []*Node{sampNode}}}}
	case "forwarding":
		return &ConfigTree{Children: []*Node{{Keys: []string{"forwarding-options"}, Children: []*Node{familyNode}}}}
	default: // interfaces
		unitNode := &Node{Keys: []string{"unit", "0"}, Children: []*Node{familyNode}}
		ifNode := &Node{Keys: []string{"ge-0/0/0"}, Children: []*Node{unitNode}}
		return &ConfigTree{Children: []*Node{{Keys: []string{"interfaces"}, Children: []*Node{ifNode}}}}
	}
}

func compileNoPanic17196(t *testing.T, tree *ConfigTree, lenient bool) (cfg *Config, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("compile PANICKED on a malformed persisted AST: %v — a corrupted "+
				"config store must fail the load, never take the daemon down (#17196)", r)
		}
	}()
	if lenient {
		return CompileConfigLenient(tree)
	}
	return CompileConfig(tree)
}

func hasUnknownFamilyWarning17196(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "is not a known address family") {
			return true
		}
	}
	return false
}

// TestFamilyMembersEmptyKeysNoPanic17196 is the defect proper: an
// empty-Keys child under all three tops must return an error (strict)
// or a warning (lenient) and never panic, in strict and lenient.
func TestFamilyMembersEmptyKeysNoPanic17196(t *testing.T) {
	for _, top := range []string{"sampling", "forwarding", "interfaces"} {
		t.Run(top+"/strict", func(t *testing.T) {
			cfg, err := compileNoPanic17196(t, emptyKeysTree17196(top), false)
			if err == nil {
				t.Fatalf("strict compile accepted an empty-Keys family child under %s, want rejection (cfg=%v)", top, cfg != nil)
			}
			if !strings.Contains(err.Error(), "is not a known address family") {
				t.Fatalf("strict error must carry the #9017-style unknown-family message, got: %v", err)
			}
		})
		t.Run(top+"/lenient", func(t *testing.T) {
			cfg, err := compileNoPanic17196(t, emptyKeysTree17196(top), true)
			if err != nil {
				t.Fatalf("lenient compile must not brick on a malformed family child (#1960): %v", err)
			}
			if !hasUnknownFamilyWarning17196(cfg) {
				t.Fatalf("lenient compile must warn with the unknown-family message, warnings=%v", cfg.Warnings)
			}
			// Nothing installed for the unknown member.
			if cfg.ForwardingOptions.FamilyInet6Mode != "" {
				t.Errorf("lenient installed FamilyInet6Mode=%q for an empty-Keys member", cfg.ForwardingOptions.FamilyInet6Mode)
			}
			if cfg.ForwardingOptions.Sampling != nil {
				if inst := cfg.ForwardingOptions.Sampling.Instances["i1"]; inst != nil && (inst.FamilyInet != nil || inst.FamilyInet6 != nil) {
					t.Errorf("lenient installed a sampling family for an empty-Keys member: %+v", inst)
				}
			}
			if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc != nil {
				if unit := ifc.Units[0]; unit != nil && (unit.FamilyInet || unit.FamilyInet6) {
					t.Errorf("lenient installed an interface family for an empty-Keys member: %+v", unit)
				}
			}
		})
	}
}

// TestFamilyMembersBogusSmuggleRejected17196 pins the Keys[1] smuggle:
// `{bogus inet6 {mode}}` under forwarding-options and `{bogus inet {…}}`
// under sampling (and interfaces) are rejected strictly with the
// #9017-style message and install nothing; lenient warns and installs
// nothing.
func TestFamilyMembersBogusSmuggleRejected17196(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		install func(*Config) bool // true if the trailing family was installed
	}{
		{
			name: "forwarding-options bogus inet6",
			text: "forwarding-options { family { bogus inet6 { mode packet-based; } } }",
			install: func(c *Config) bool {
				return c.ForwardingOptions.FamilyInet6Mode == "packet-based"
			},
		},
		{
			name: "sampling bogus inet",
			text: "forwarding-options { sampling { instance i1 { family { bogus inet { output { flow-server 10.0.0.1 { port 2055; } } } } } } }",
			install: func(c *Config) bool {
				if c.ForwardingOptions.Sampling == nil {
					return false
				}
				inst := c.ForwardingOptions.Sampling.Instances["i1"]
				return inst != nil && inst.FamilyInet != nil
			},
		},
		{
			name: "interfaces bogus inet",
			text: "interfaces { ge-0/0/0 { unit 0 { family { bogus inet { address 10.0.0.1/24; } } } } }",
			install: func(c *Config) bool {
				ifc := c.Interfaces.Interfaces["ge-0/0/0"]
				if ifc == nil {
					return false
				}
				unit := ifc.Units[0]
				return unit != nil && unit.FamilyInet
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/strict", func(t *testing.T) {
			tree, perrs := NewParser(tc.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			cfg, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict compile accepted %q, want rejection; installed=%v", tc.text, cfg != nil && tc.install(cfg))
			}
			if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "is not a known address family") {
				t.Fatalf("strict error must name the bogus token with the #9017-style message, got: %v", err)
			}
		})
		t.Run(tc.name+"/lenient", func(t *testing.T) {
			tree, perrs := NewParser(tc.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile must not brick (#1960): %v", err)
			}
			if tc.install(cfg) {
				t.Errorf("lenient installed the trailing family behind a bogus leading token: %q", tc.text)
			}
			if !hasUnknownFamilyWarning17196(cfg) {
				t.Errorf("lenient must warn with the unknown-family message, warnings=%v", cfg.Warnings)
			}
		})
	}
}

// TestFamilyMembersInterfaceResidueFixture17196 pins the D58-04
// direction: the interface install token is the child NAME, never
// Keys[1], so `family { inet mtu 1500 { address … } }` (structured
// member with residue) no longer installs inet behind the residue, and
// the well-formed spellings still compile.
func TestFamilyMembersInterfaceResidueFixture17196(t *testing.T) {
	// Residue fixture: strict rejects, lenient warns and installs nothing.
	tree, perrs := NewParser("interfaces { ge-0/0/0 { unit 0 { family { inet mtu 1500 { address 10.0.0.1/24; } } } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted `inet mtu 1500 { … }` residue member, want rejection")
	} else if !strings.Contains(err.Error(), "is not a known address family") {
		t.Fatalf("strict error must carry the unknown-family message, got: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc != nil {
		if unit := ifc.Units[0]; unit != nil && (unit.FamilyInet || len(unit.Addresses) > 0) {
			t.Errorf("lenient installed inet behind residue: unit=%+v", unit)
		}
	}
	if !hasUnknownFamilyWarning17196(cfg) {
		t.Errorf("lenient must warn, warnings=%v", cfg.Warnings)
	}

	// Controls: the well-formed spellings still compile their families.
	for _, text := range []string{
		"interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; mtu 1500; } } } }",
		"interfaces { ge-0/0/0 { unit 0 { family { inet { address 10.0.0.1/24; } } } } }",
		"forwarding-options { family inet6 { mode packet-based; } }",
		"forwarding-options { family { inet6 { mode packet-based; } } }",
		"forwarding-options { sampling { instance i1 { family inet { output { flow-server 10.0.0.1 { port 2055; } } } } } }",
	} {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("control %q must parse: %v", text, perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("control %q strict rejected: %v", text, err)
		}
		switch {
		case strings.Contains(text, "sampling"):
			inst := cfg.ForwardingOptions.Sampling.Instances["i1"]
			if inst == nil || inst.FamilyInet == nil {
				t.Errorf("control %q: sampling FamilyInet not installed", text)
			}
		case strings.Contains(text, "forwarding-options"):
			if cfg.ForwardingOptions.FamilyInet6Mode != "packet-based" {
				t.Errorf("control %q: FamilyInet6Mode=%q, want packet-based", text, cfg.ForwardingOptions.FamilyInet6Mode)
			}
		default:
			ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
			if ifc == nil || ifc.Units[0] == nil || !ifc.Units[0].FamilyInet || len(ifc.Units[0].Addresses) == 0 {
				t.Errorf("control %q: interface inet family/address not installed: %+v", text, ifc)
			}
		}
	}
}

// TestFamilyMembersSingleExtractorCensus17196 is the structural guard:
// no hand copy of the compound/split walk may remain outside the shared
// extractor. The acceptance census is
// `rg -n 'afNodes = append\(afNodes' pkg/config --glob '!*_test.go'`
// returning 0; this test pins the same invariant hermetically.
func TestFamilyMembersSingleExtractorCensus17196(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", name, err)
		}
		if strings.Contains(string(b), "afNodes = append(afNodes") {
			t.Errorf("%s still hand-copies the family walk (afNodes append); use familyMembers from family_members.go (#17196)", name)
		}
	}
	// The shared extractor itself must exist and be the firewall path.
	b, err := os.ReadFile("family_members.go")
	if err != nil {
		t.Fatalf("family_members.go missing: %v", err)
	}
	if !strings.Contains(string(b), "func familyMembers(famNode *Node) []familyMember") {
		t.Error("family_members.go does not define familyMembers(famNode *Node) []familyMember")
	}
}
