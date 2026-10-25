package config

import (
	"strings"
	"testing"
)

// #16679: BGP `multihop` was an xpf-only scalar `multihop <ttl>` leaf.
// Junos spells it as a presence container — `multihop;`,
// `multihop { ttl N; }`, `multihop no-nexthop-change;` (bgp, group and
// neighbor hierarchy) — and every Junos spelling was rejected at
// commit ("missing value" / "not an integer").
//
// Acceptance: the Junos rows commit and render `ebgp-multihop <ttl>`
// (via BGPNeighbor.MultihopTTL), and `no-nexthop-change` is refused
// BY NAME until it is rendered (FRR `ebgp-multihop` rewrites the
// received next hop; Junos' flag asks to retain it, and FRR has no
// per-neighbor equivalent). `multihop <N>` stays as an alias.
//
// Fix: `multihop` is modelled as a typed leaf with `ttl` /
// `no-nexthop-change` modifiers (schema_bgp_multihop_16679.go); the
// bare form resolves to the Junos default TTL 64; group and neighbor
// spelling at group level is inherited by neighbors as before.

func multihopTree16679(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	return tree
}

func multihopHier16679(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return tree
}

func multihopTTL16679(t *testing.T, tree *ConfigTree) int {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("compiled BGP = %+v, want exactly one neighbor", cfg.Protocols.BGP)
	}
	return cfg.Protocols.BGP.Neighbors[0].MultihopTTL
}

// --- Accepted spellings: hierarchical ---

var multihopHierRows16679 = []struct {
	name string
	src  string
	want int
}{
	{"group scalar control", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop 2; neighbor 10.0.0.1; } } }`, 2},
	{"group bare", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop; neighbor 10.0.0.1; } } }`, 64},
	{"group ttl blocked", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 2; } neighbor 10.0.0.1; } } }`, 2},
	{"group ttl packed", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop ttl 2; neighbor 10.0.0.1; } } }`, 2},
	{"group ttl 1 boundary", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 1; } neighbor 10.0.0.1; } } }`, 1},
	{"group ttl 255 boundary", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 255; } neighbor 10.0.0.1; } } }`, 255},
	{"neighbor bare", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { multihop; } } } }`, 64},
	{"neighbor ttl blocked", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { multihop { ttl 5; } } } } }`, 5},
	{"neighbor ttl packed braced", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { multihop ttl 7; passive; } } } }`, 7},
	{"neighbor packed run", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 multihop ttl 7 passive; } } }`, 7},
	{"neighbor overrides group", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop 3; neighbor 10.0.0.1 { multihop { ttl 9; } } } } }`, 9},
	{"neighbor bare overrides group ttl", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 3; } neighbor 10.0.0.1 { multihop; } } } }`, 64},
}

func TestBGPMultihopHierarchicalSpellings16679(t *testing.T) {
	for _, row := range multihopHierRows16679 {
		t.Run(row.name, func(t *testing.T) {
			tree := multihopHier16679(t, row.src)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate must commit %s: %v", row.name, err)
			}
			if got := multihopTTL16679(t, tree); got != row.want {
				t.Errorf("%s: MultihopTTL = %d, want %d", row.name, got, row.want)
			}
			// Accepted spellings must not draw the generic #10707
			// "may be silently ignored" advisory for the TTL token.
			cfg, err := CompileConfig(multihopHier16679(t, row.src))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "multihop") && strings.Contains(w, "#10707") {
					t.Errorf("%s: spurious #10707 advisory on a compiled statement: %q", row.name, w)
				}
			}
		})
	}
}

// --- Accepted spellings: flat-set ---

var multihopFlatRows16679 = []struct {
	name  string
	lines []string
	want  int
}{
	{"group scalar control", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G multihop 2",
		"set protocols bgp group G neighbor 10.0.0.1"}, 2},
	{"group bare", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G multihop",
		"set protocols bgp group G neighbor 10.0.0.1"}, 64},
	{"group ttl", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G multihop ttl 2",
		"set protocols bgp group G neighbor 10.0.0.1"}, 2},
	{"neighbor scalar control", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1 multihop 3"}, 3},
	{"neighbor bare", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1 multihop"}, 64},
	{"neighbor ttl", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1 multihop ttl 3"}, 3},
	{"group bare then ttl refines", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G multihop",
		"set protocols bgp group G multihop ttl 4",
		"set protocols bgp group G neighbor 10.0.0.1"}, 4},
}

func TestBGPMultihopFlatSetSpellings16679(t *testing.T) {
	for _, row := range multihopFlatRows16679 {
		t.Run(row.name, func(t *testing.T) {
			tree := multihopTree16679(t, row.lines...)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate must commit %s: %v", row.name, err)
			}
			if got := multihopTTL16679(t, tree); got != row.want {
				t.Errorf("%s: MultihopTTL = %d, want %d", row.name, got, row.want)
			}
			cfg, err := CompileConfig(multihopTree16679(t, row.lines...))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "multihop") && strings.Contains(w, "#10707") {
					t.Errorf("%s: spurious #10707 advisory: %q", row.name, w)
				}
			}
		})
	}
}

// Fully fused flat line `neighbor 10.0.0.1 multihop ttl 3 passive`:
// the TTL compiles and the statement commits; `passive` fused onto
// the ttl child is a generic flat-run limitation (handing the whole
// fused child to the neighbor statement split would require cutting
// INSIDE a statement) — recorded as residual #16679, not asserted
// here beyond the TTL.
func TestBGPMultihopFlatFusedNeighbourLine16679(t *testing.T) {
	tree := multihopTree16679(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1 multihop ttl 3 passive",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("fused line must commit: %v", err)
	}
	if got := multihopTTL16679(t, tree); got != 3 {
		t.Errorf("fused line MultihopTTL = %d, want 3", got)
	}
}

// Routing instance: the shared BGP schema node carries the same
// spellings (schemaRoutingInstanceProtocols shares by pointer).
func TestBGPMultihopRoutingInstance16679(t *testing.T) {
	tree := multihopTree16679(t,
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp group G peer-as 65011",
		"set routing-instances VR1 protocols bgp group G multihop ttl 9",
		"set routing-instances VR1 protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("RI SchemaValidate: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("RI compile: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].BGP == nil || len(cfg.RoutingInstances[0].BGP.Neighbors) != 1 {
		t.Fatalf("RI BGP not compiled: %+v", cfg.RoutingInstances)
	}
	if got := cfg.RoutingInstances[0].BGP.Neighbors[0].MultihopTTL; got != 9 {
		t.Errorf("RI MultihopTTL = %d, want 9", got)
	}

	hier := multihopHier16679(t, `routing-instances { VR1 { instance-type virtual-router; protocols { bgp { local-as 65010; group G { peer-as 65011; multihop; neighbor 10.0.0.1; } } } } }`)
	if err := SchemaValidate(hier); err != nil {
		t.Fatalf("RI hier bare SchemaValidate: %v", err)
	}
	cfg2, err := CompileConfig(hier)
	if err != nil {
		t.Fatalf("RI hier compile: %v", err)
	}
	if got := cfg2.RoutingInstances[0].BGP.Neighbors[0].MultihopTTL; got != 64 {
		t.Errorf("RI hier bare MultihopTTL = %d, want 64 (Junos default)", got)
	}
}

// --- Refused by name: no-nexthop-change ---

var multihopRefusedHier16679 = []struct {
	name string
	src  string
}{
	{"group packed", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop no-nexthop-change; neighbor 10.0.0.1; } } }`},
	{"group blocked", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { no-nexthop-change; } neighbor 10.0.0.1; } } }`},
	{"group blocked with ttl", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 2; no-nexthop-change; } neighbor 10.0.0.1; } } }`},
	{"group scalar plus flag", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop 2 no-nexthop-change; neighbor 10.0.0.1; } } }`},
	{"neighbor packed", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { multihop no-nexthop-change; } } } }`},
	{"neighbor blocked with ttl", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { multihop { ttl 5; no-nexthop-change; } } } } }`},
	{"ri group packed", `routing-instances { VR1 { instance-type virtual-router; protocols { bgp { local-as 65010; group G { peer-as 65011; multihop no-nexthop-change; neighbor 10.0.0.1; } } } } }`},
}

var multihopRefusedFlat16679 = []struct {
	name  string
	lines []string
}{
	{"group flat", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G multihop no-nexthop-change",
		"set protocols bgp group G neighbor 10.0.0.1"}},
	{"neighbor flat", []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1 multihop no-nexthop-change"}},
	{"ri group flat", []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp group G peer-as 65011",
		"set routing-instances VR1 protocols bgp group G multihop no-nexthop-change",
		"set routing-instances VR1 protocols bgp group G neighbor 10.0.0.1"}},
}

func TestBGPMultihopNoNexthopChangeRefused16679(t *testing.T) {
	assertRefused := func(t *testing.T, tree *ConfigTree) {
		t.Helper()
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatal("SchemaValidate accepted no-nexthop-change; want refusal by name")
		}
		if !strings.Contains(err.Error(), "no-nexthop-change") {
			t.Errorf("refusal must name no-nexthop-change: %v", err)
		}
		if !strings.Contains(err.Error(), "#16679") {
			t.Errorf("refusal must carry #16679: %v", err)
		}
	}
	for _, row := range multihopRefusedHier16679 {
		t.Run("hier/"+row.name, func(t *testing.T) {
			assertRefused(t, multihopHier16679(t, row.src))
		})
	}
	for _, row := range multihopRefusedFlat16679 {
		t.Run("flat/"+row.name, func(t *testing.T) {
			assertRefused(t, multihopTree16679(t, row.lines...))
		})
	}
}

// Tolerant path: lenient compile must boot and carry a SPECIFIC
// warning naming the refused statement; strict compile (no
// SchemaValidate) must surface it too. The refused statement is not
// partially honoured: no TTL is rendered for it.
func TestBGPMultihopNoNexthopChangeTolerantWarning16679(t *testing.T) {
	for _, row := range multihopRefusedFlat16679 {
		t.Run(row.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(multihopTree16679(t, row.lines...))
			if err != nil {
				t.Fatalf("lenient must boot: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "no-nexthop-change") && strings.Contains(w, "#16679") {
					found = true
				}
			}
			if !found {
				t.Errorf("tolerant warnings must name no-nexthop-change (#16679), got %v", cfg.Warnings)
			}
			if cfg.Protocols.BGP != nil {
				for _, n := range cfg.Protocols.BGP.Neighbors {
					if n.MultihopTTL != 0 {
						t.Errorf("refused statement must not render a TTL, got %d", n.MultihopTTL)
					}
				}
			}
			if len(cfg.RoutingInstances) > 0 && cfg.RoutingInstances[0].BGP != nil {
				for _, n := range cfg.RoutingInstances[0].BGP.Neighbors {
					if n.MultihopTTL != 0 {
						t.Errorf("RI refused statement must not render a TTL, got %d", n.MultihopTTL)
					}
				}
			}
		})
	}
	// Strict compile without SchemaValidate still names the drop.
	cfg, err := CompileConfig(multihopTree16679(t, multihopRefusedFlat16679[0].lines...))
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "no-nexthop-change") && strings.Contains(w, "#16679") {
			found = true
		}
	}
	if !found {
		t.Errorf("strict compile warnings must name no-nexthop-change (#16679), got %v", cfg.Warnings)
	}
}

// --- Still refused: malformed TTLs ---

var multihopBadRows16679 = []struct {
	name string
	src  string
}{
	{"ttl 0 blocked", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 0; } neighbor 10.0.0.1; } } }`},
	{"ttl 256 blocked", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 256; } neighbor 10.0.0.1; } } }`},
	{"ttl 256 packed", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop ttl 256; neighbor 10.0.0.1; } } }`},
	{"scalar 256", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop 256; neighbor 10.0.0.1; } } }`},
	{"scalar 0", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop 0; neighbor 10.0.0.1; } } }`},
	{"ttl word", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl abc; } neighbor 10.0.0.1; } } }`},
	{"ttl missing value blocked", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl; } neighbor 10.0.0.1; } } }`},
	{"unknown word", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop banana; neighbor 10.0.0.1; } } }`},
}

func TestBGPMultihopBadTTLRefused16679(t *testing.T) {
	for _, row := range multihopBadRows16679 {
		t.Run(row.name, func(t *testing.T) {
			tree := multihopHier16679(t, row.src)
			if err := SchemaValidate(tree); err == nil {
				t.Errorf("%s must be refused at commit", row.name)
			}
		})
	}
	// Flat-set equivalents of the range gate.
	for _, lines := range [][]string{
		{"set protocols bgp local-as 65001", "set protocols bgp group G peer-as 65002", "set protocols bgp group G multihop ttl 256", "set protocols bgp group G neighbor 10.0.0.1"},
		{"set protocols bgp local-as 65001", "set protocols bgp group G peer-as 65002", "set protocols bgp group G neighbor 10.0.0.1 multihop ttl 0"},
	} {
		if err := SchemaValidate(multihopTree16679(t, lines...)); err == nil {
			t.Errorf("flat %v must be refused at commit", lines)
		}
	}
}

// Controls: a config with no multihop stays directly connected
// (MultihopTTL 0, no rendered line — pinned in pkg/frr), and a policy
// NAMED "multihop" still compiles as a policy, not as the statement
// (#15137 fused-cut guard must not treat the bare name as a statement).
func TestBGPMultihopControls16679(t *testing.T) {
	tree := multihopTree16679(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("no-multihop control must commit: %v", err)
	}
	if got := multihopTTL16679(t, tree); got != 0 {
		t.Errorf("no-multihop control MultihopTTL = %d, want 0", got)
	}

	policyTree := multihopHier16679(t, `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { export multihop; } } } } policy-options { policy-statement multihop { then accept; } }`)
	cfg, err := CompileConfig(policyTree)
	if err != nil {
		t.Fatalf("policy-named-multihop compile: %v", err)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if len(n.Export) != 1 || n.Export[0] != "multihop" {
		t.Errorf("policy named multihop: Export = %v, want [multihop]", n.Export)
	}
	if n.MultihopTTL != 0 {
		t.Errorf("policy named multihop must not set MultihopTTL, got %d", n.MultihopTTL)
	}
}
