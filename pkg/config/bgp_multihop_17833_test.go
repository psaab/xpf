package config

import (
	"strings"
	"testing"
)

// #17833 (retro-review of #17542): three gaps in the BGP multihop
// modelling that all fail OPEN — the statement silently disappears or
// is partially applied instead of being modelled or refused:
//
//  1. BGP-LEVEL multihop — the third Junos hierarchy level named by
//     the #16679 contract — was unmodelled: it committed on the
//     open-world bgp subtree with only the generic #10707 advisory
//     and rendered nothing (MultihopTTL 0, FRR direct default).
//  2. Group normalisation (bgpMultihopChildTTL16679) replaced the
//     authored `multihop { ttl 2; no-nexthop-change; }` node with a
//     synthesised `multihop ttl 2` BEFORE the extractor's refusal
//     check, so the tolerant/direct compile applied the TTL of a
//     statement its own warning said was dropped. Fused spellings
//     (`multihop { ttl 2 no-nexthop-change; }`, flat `multihop ttl 2
//     no-nexthop-change`) escaped the refusal scan entirely.
//  3. Unknown children in the multihop block (`multihop { banana; }`)
//     and the missing-value packed form (`multihop ttl;`) strict-
//     committed silently and compiled the TTL-64 default.
//
// Acceptance: bgp-level multihop commits, inherits (neighbor >
// group > bgp) and renders; every refused/malformed spelling keeps
// the prior/inherited TTL on tolerant paths and is refused by name
// at strict commit.

// bgpLevelTTL17833 compiles a hierarchical config strictly and
// returns the sole neighbor's MultihopTTL.
func bgpLevelTTL17833(t *testing.T, src string) int {
	t.Helper()
	tree := multihopHier16679(t, src)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("compiled BGP = %+v, want exactly one neighbor", cfg.Protocols.BGP)
	}
	return cfg.Protocols.BGP.Neighbors[0].MultihopTTL
}

func TestBGPMultihopBGPLevelModelled17833(t *testing.T) {
	rows := []struct {
		name string
		src  string
		want int
	}{
		{"bare default", `protocols { bgp { local-as 65001; multihop; group G { peer-as 65002; neighbor 10.0.0.1; } } }`, 64},
		{"ttl blocked", `protocols { bgp { local-as 65001; multihop { ttl 4; } group G { peer-as 65002; neighbor 10.0.0.1; } } }`, 4},
		{"scalar alias", `protocols { bgp { local-as 65001; multihop 4; group G { peer-as 65002; neighbor 10.0.0.1; } } }`, 4},
		{"group overrides bgp", `protocols { bgp { local-as 65001; multihop { ttl 4; } group G { peer-as 65002; multihop { ttl 9; } neighbor 10.0.0.1; } } }`, 9},
		{"group bare overrides bgp ttl", `protocols { bgp { local-as 65001; multihop { ttl 4; } group G { peer-as 65002; multihop; neighbor 10.0.0.1; } } }`, 64},
		{"neighbor overrides bgp", `protocols { bgp { local-as 65001; multihop { ttl 4; } group G { peer-as 65002; neighbor 10.0.0.1 { multihop { ttl 7; } } } } }`, 7},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tree := multihopHier16679(t, row.src)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("bgp-level multihop must commit (%s): %v", row.name, err)
			}
			if got := bgpLevelTTL17833(t, row.src); got != row.want {
				t.Errorf("%s: MultihopTTL = %d, want %d", row.name, got, row.want)
			}
			// The modelled statement must not draw the generic
			// #10707 "may be silently ignored" advisory.
			cfg, err := CompileConfig(multihopHier16679(t, row.src))
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

	flat := multihopTree16679(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp multihop",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(flat); err != nil {
		t.Fatalf("flat bgp-level bare must commit: %v", err)
	}
	if got := multihopTTL16679(t, flat); got != 64 {
		t.Errorf("flat bgp-level bare: MultihopTTL = %d, want 64", got)
	}
	flatTTL := multihopTree16679(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp multihop ttl 4",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(flatTTL); err != nil {
		t.Fatalf("flat bgp-level ttl must commit: %v", err)
	}
	if got := multihopTTL16679(t, flatTTL); got != 4 {
		t.Errorf("flat bgp-level ttl: MultihopTTL = %d, want 4", got)
	}

	ri := multihopTree16679(t,
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp multihop",
		"set routing-instances VR1 protocols bgp group G peer-as 65011",
		"set routing-instances VR1 protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(ri); err != nil {
		t.Fatalf("RI bgp-level bare must commit: %v", err)
	}
	cfg, err := CompileConfig(ri)
	if err != nil {
		t.Fatalf("RI compile: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].BGP == nil || len(cfg.RoutingInstances[0].BGP.Neighbors) != 1 {
		t.Fatalf("RI BGP not compiled: %+v", cfg.RoutingInstances)
	}
	if got := cfg.RoutingInstances[0].BGP.Neighbors[0].MultihopTTL; got != 64 {
		t.Errorf("RI bgp-level bare MultihopTTL = %d, want 64", got)
	}
}

// The refused spelling is refused by name at bgp level too, and the
// tolerant path warns without applying any TTL.
func TestBGPMultihopBGPLevelRefused17833(t *testing.T) {
	hier := multihopHier16679(t, `protocols { bgp { local-as 65001; multihop no-nexthop-change; group G { peer-as 65002; neighbor 10.0.0.1; } } }`)
	if err := SchemaValidate(hier); err == nil {
		t.Fatal("bgp-level no-nexthop-change must be refused at commit")
	} else if !strings.Contains(err.Error(), "no-nexthop-change") || !strings.Contains(err.Error(), "#16679") {
		t.Errorf("refusal must name no-nexthop-change (#16679): %v", err)
	}

	flat := multihopTree16679(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp multihop no-nexthop-change",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(flat); err == nil {
		t.Fatal("flat bgp-level no-nexthop-change must be refused at commit")
	}
	cfg, err := CompileConfigLenient(flat)
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
	for _, n := range cfg.Protocols.BGP.Neighbors {
		if n.MultihopTTL != 0 {
			t.Errorf("refused bgp-level statement must not render a TTL, got %d", n.MultihopTTL)
		}
	}
}

// #17833 core: the refused sibling must survive group normalisation
// — through the REAL hierarchical group compile path, not the
// extractor called on a hand-built node. Before the fix the direct
// and lenient compiles rendered TTL 2 while warning that the
// statement was dropped.
func TestBGPMultihopRefusedSiblingNotPartiallyApplied17833(t *testing.T) {
	src := `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 2; no-nexthop-change; } neighbor 10.0.0.1; } } }`
	if err := SchemaValidate(multihopHier16679(t, src)); err == nil {
		t.Fatal("blocked ttl+flag must be refused at commit")
	}
	for _, mode := range []string{"strict-direct", "lenient"} {
		var cfg *Config
		var err error
		if mode == "strict-direct" {
			cfg, err = CompileConfig(multihopHier16679(t, src))
		} else {
			cfg, err = CompileConfigLenient(multihopHier16679(t, src))
		}
		if err != nil {
			t.Fatalf("%s compile: %v", mode, err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "no-nexthop-change") && strings.Contains(w, "#16679") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: warnings must name no-nexthop-change (#16679), got %v", mode, cfg.Warnings)
		}
		for _, n := range cfg.Protocols.BGP.Neighbors {
			if n.MultihopTTL != 0 {
				t.Errorf("%s: refused statement must not render a TTL, got %d", mode, n.MultihopTTL)
			}
		}
	}

	// A refused GROUP statement falls back to the bgp-level default
	// (the refused statement itself applies nothing).
	seed := `protocols { bgp { local-as 65001; multihop { ttl 5; } group G { peer-as 65002; multihop { ttl 2; no-nexthop-change; } neighbor 10.0.0.1; } } }`
	cfg, err := CompileConfigLenient(multihopHier16679(t, seed))
	if err != nil {
		t.Fatalf("lenient seed compile: %v", err)
	}
	if got := cfg.Protocols.BGP.Neighbors[0].MultihopTTL; got != 5 {
		t.Errorf("refused group statement must inherit the bgp-level TTL 5, got %d", got)
	}

	// Fused spellings that escaped the first-position-only scans.
	fusedRows := []struct {
		name string
		src  string
	}{
		{"blocked ttl with fused flag", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 2 no-nexthop-change; } neighbor 10.0.0.1; } } }`},
		{"flat fused ttl+flag", "set protocols bgp local-as 65001\nset protocols bgp group G peer-as 65002\nset protocols bgp group G multihop ttl 2 no-nexthop-change\nset protocols bgp group G neighbor 10.0.0.1"},
	}
	for _, row := range fusedRows {
		t.Run(row.name, func(t *testing.T) {
			var tree *ConfigTree
			if strings.Contains(row.src, "\n") {
				tree = multihopTree16679(t, strings.Split(row.src, "\n")...)
			} else {
				tree = multihopHier16679(t, row.src)
			}
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("%s must be refused at commit", row.name)
			} else if !strings.Contains(err.Error(), "no-nexthop-change") {
				t.Errorf("%s: refusal must name no-nexthop-change: %v", row.name, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("%s lenient: %v", row.name, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "no-nexthop-change") && strings.Contains(w, "#16679") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: lenient warnings must name no-nexthop-change, got %v", row.name, cfg.Warnings)
			}
			for _, n := range cfg.Protocols.BGP.Neighbors {
				if n.MultihopTTL != 0 {
					t.Errorf("%s: refused fused statement must not render a TTL, got %d", row.name, n.MultihopTTL)
				}
			}
		})
	}

	// Controls: a VALID sibling statement still applies.
	separate := multihopTree16679(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G multihop ttl 2",
		"set protocols bgp group G multihop no-nexthop-change",
		"set protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(separate); err == nil {
		t.Fatal("separate refused statement must still be refused at commit")
	}
	cfg2, err := CompileConfigLenient(separate)
	if err != nil {
		t.Fatalf("separate lenient: %v", err)
	}
	if got := cfg2.Protocols.BGP.Neighbors[0].MultihopTTL; got != 2 {
		t.Errorf("valid sibling statement must still apply TTL 2 (refused one dropped), got %d", got)
	}

	// Neighbor-level refusal keeps the inherited group TTL (control).
	nb := `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop 3; neighbor 10.0.0.1 { multihop { ttl 5; no-nexthop-change; } } } } }`
	cfg3, err := CompileConfigLenient(multihopHier16679(t, nb))
	if err != nil {
		t.Fatalf("neighbor control lenient: %v", err)
	}
	if got := cfg3.Protocols.BGP.Neighbors[0].MultihopTTL; got != 3 {
		t.Errorf("refused neighbor statement must keep the group TTL 3, got %d", got)
	}
}

// `multihop { banana; }` used to strict-commit silently and compile
// the TTL-64 default.
func TestBGPMultihopUnknownChildRefused17833(t *testing.T) {
	rows := []struct {
		name string
		src  string
	}{
		{"group", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { banana; } neighbor 10.0.0.1; } } }`},
		{"group beside ttl", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 2; banana; } neighbor 10.0.0.1; } } }`},
		{"neighbor", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { multihop { banana; } } } } }`},
		{"bgp level", `protocols { bgp { local-as 65001; multihop { banana; } group G { peer-as 65002; neighbor 10.0.0.1; } } }`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tree := multihopHier16679(t, row.src)
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("%s: unknown multihop child must be refused at commit", row.name)
			} else if !strings.Contains(err.Error(), "banana") {
				t.Errorf("%s: refusal must name the unknown statement: %v", row.name, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("%s lenient: %v", row.name, err)
			}
			for _, n := range cfg.Protocols.BGP.Neighbors {
				if n.MultihopTTL != 0 {
					t.Errorf("%s: unknown child must not default the TTL to 64, got %d", row.name, n.MultihopTTL)
				}
			}
		})
	}

	// Control: the modelled blocked statement still commits.
	if err := SchemaValidate(multihopHier16679(t, `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 2; } neighbor 10.0.0.1; } } }`)); err != nil {
		t.Fatalf("blocked ttl control must commit: %v", err)
	}
}

// `multihop ttl;` (no value) used to commit as the bare presence
// form and compile the TTL-64 default.
func TestBGPMultihopMissingValueRefused17833(t *testing.T) {
	hierRows := []struct {
		name string
		src  string
	}{
		{"group packed", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop ttl; neighbor 10.0.0.1; } } }`},
		{"neighbor packed", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { multihop ttl; } } } }`},
		{"bgp level packed", `protocols { bgp { local-as 65001; multihop ttl; group G { peer-as 65002; neighbor 10.0.0.1; } } }`},
		{"group blocked control", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl; } neighbor 10.0.0.1; } } }`},
	}
	for _, row := range hierRows {
		t.Run(row.name, func(t *testing.T) {
			tree := multihopHier16679(t, row.src)
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("%s: missing TTL value must be refused at commit", row.name)
			} else if !strings.Contains(err.Error(), "missing value") {
				t.Errorf("%s: refusal must say missing value: %v", row.name, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("%s lenient: %v", row.name, err)
			}
			for _, n := range cfg.Protocols.BGP.Neighbors {
				if n.MultihopTTL != 0 {
					t.Errorf("%s: missing value must not default the TTL to 64, got %d", row.name, n.MultihopTTL)
				}
			}
		})
	}

	flat := multihopTree16679(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group G peer-as 65002",
		"set protocols bgp group G multihop ttl",
		"set protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(flat); err == nil {
		t.Fatal("flat missing TTL value must be refused at commit")
	}
	cfg, err := CompileConfigLenient(flat)
	if err != nil {
		t.Fatalf("flat lenient: %v", err)
	}
	if got := cfg.Protocols.BGP.Neighbors[0].MultihopTTL; got != 0 {
		t.Errorf("flat missing value must not default the TTL to 64, got %d", got)
	}

	// Controls: the valued spellings still commit.
	for _, tree := range []*ConfigTree{
		multihopHier16679(t, `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop ttl 2; neighbor 10.0.0.1; } } }`),
		multihopTree16679(t,
			"set protocols bgp local-as 65001",
			"set protocols bgp group G peer-as 65002",
			"set protocols bgp group G multihop ttl 2",
			"set protocols bgp group G neighbor 10.0.0.1"),
	} {
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("valued control must commit: %v", err)
		}
		if got := multihopTTL16679(t, tree); got != 2 {
			t.Errorf("valued control MultihopTTL = %d, want 2", got)
		}
	}
}
