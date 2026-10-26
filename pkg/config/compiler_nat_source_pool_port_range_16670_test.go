// #16670: regression from #15675 — the `port <N>` wildcard on the
// source-NAT pool `port` node split the flat `port range <lo> to <hi>`
// into `port range` + `port 1024 to 2048`, so SchemaValidate rejected
// `to` under the closed-world subtree and a pool port range could not
// be committed via `set` (pkg/configstore's
// TestCompileTreeStrict_StandaloneCleanSNAT_5876 was red at base).
//
// The root cause was in SetPath's multi-leaf absorber: at a parent
// with a wildcard, every trailing token of a multi leaf was forced to
// be a sibling instance (#9685), so `range`'s values were re-homed.
// Only the pool range leaf opts into retaining its operands ahead of
// that wildcard. Declared sibling keywords and other wildcard parents
// retain their existing behavior.
//
// Flat-set fixtures MUST use ParseSetCommand/SetPath (snatPoolTree);
// hierarchical fixtures MUST use NewParser.
package config

import (
	"strings"
	"testing"
)

// Flat Junos and legacy range spellings must validate and compile to
// the same PortLow/PortHigh as the hierarchical spelling.
func TestSourceNATPoolPortRangeFlatSetValidates16670(t *testing.T) {
	const txt = "security {\n zones { security-zone trust; security-zone untrust; }\n nat {\n  source {\n   pool p1 {\n    address { 203.0.113.5/32; }\n    port { range 1024 to 2048; }\n   }\n   rule-set RS {\n    from zone trust;\n    to zone untrust;\n    rule R1 { match { source-address 10.0.0.0/24; } then { source-nat { pool p1; } } }\n   }\n  }\n }\n}\n"
	treeH, perrs := NewParser(txt).Parse()
	if len(perrs) != 0 {
		t.Fatalf("hierarchical parse: %v", perrs)
	}
	if err := SchemaValidate(treeH); err != nil {
		t.Fatalf("hierarchical SchemaValidate: %v", err)
	}
	cfgH, err := CompileConfig(treeH)
	if err != nil {
		t.Fatalf("hierarchical CompileConfig: %v", err)
	}
	want := cfgH.Security.NAT.SourcePools["p1"]
	if want == nil {
		t.Fatalf("hierarchical pool p1 missing")
	}
	if want.PortLow != 1024 || want.PortHigh != 2048 {
		t.Fatalf("hierarchical PortLow/PortHigh = %d/%d, want 1024/2048", want.PortLow, want.PortHigh)
	}

	for _, cmd := range []string{
		"set security nat source pool p1 port range 1024 to 2048",
		"set security nat source pool p1 port range low 1024 high 2048",
	} {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32", cmd)
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("SchemaValidate(%q): %v (want pass — flat range must not split at the port wildcard)", cmd, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", cmd, err)
		}
		pool := cfg.Security.NAT.SourcePools["p1"]
		if pool == nil {
			t.Fatalf("pool p1 missing for %q", cmd)
		}
		if pool.PortLow != want.PortLow || pool.PortHigh != want.PortHigh {
			t.Fatalf("%q => %d-%d, want hierarchical %d-%d", cmd, pool.PortLow, pool.PortHigh, want.PortLow, want.PortHigh)
		}
	}
}

// `port <N>` single-port spelling must survive the fix.
func TestSourceNATPoolPortSingleStillValidates16670(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port 3000")
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate(port 3000): %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(port 3000): %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool.PortLow != 3000 || pool.PortHigh != 3000 {
		t.Fatalf("port 3000 => %d-%d, want 3000-3000", pool.PortLow, pool.PortHigh)
	}
}

// A flat range on one `set` line followed by a modifier on its own
// line, and a bare empty range, keep their prior semantics.
func TestSourceNATPoolPortRangeControls16670(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range 1024 to 2048",
		"set security nat source pool p1 port random-allocation")
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate(range+random): %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(range+random): %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool.PortLow != 1024 || pool.PortHigh != 2048 || !pool.PortRandomAllocation {
		t.Fatalf("range+random => %d-%d rand=%v, want 1024-2048 rand=true", pool.PortLow, pool.PortHigh, pool.PortRandomAllocation)
	}

	// Empty range still fails closed (not widened to the default).
	empty := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range")
	if _, err := CompileConfig(empty); err == nil {
		t.Fatalf("CompileConfig accepted empty `port range` (want fail-closed)")
	}

	// Unknown keyword after port still fails closed, never widened.
	bogus := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port bogus-allocation")
	if _, err := CompileConfig(bogus); err == nil {
		t.Fatalf("CompileConfig accepted `port bogus-allocation` (want fail-closed)")
	}
	if err := SchemaValidate(bogus); err != nil && !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("SchemaValidate returned an unrelated error: %v", err)
	}
}

// Pin the AST before any compiler normalization can repair it. Turning off
// the opt-in is a control for the default wildcard sibling behavior.
func TestPoolRangeAbsorptionIsOptIn16670(t *testing.T) {
	rangeSchema := schemaSecurity.children["nat"].children["source"].children["pool"].children["port"].children["range"]
	original := rangeSchema.absorbBeforeWildcard
	defer func() { rangeSchema.absorbBeforeWildcard = original }()
	if !original {
		t.Fatal("source-pool range must opt into operand absorption")
	}
	for _, absorb := range []bool{true, false} {
		rangeSchema.absorbBeforeWildcard = absorb
		tree := &ConfigTree{}
		path, err := ParseSetCommand("set security nat source pool P port range 1024 to 2048 random-allocation")
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
		port := tree.FindChild("security").FindChild("nat").FindChild("source").FindChild("pool").FindChild("port")
		r := port.FindChild("range")
		if absorb {
			if len(port.Children) != 2 || strings.Join(r.Keys, " ") != "range 1024 to 2048" || !r.IsLeaf || len(r.Children) != 0 {
				t.Fatalf("range operands escaped their leaf: %+v", port)
			}
			if sibling := port.Children[1]; sibling.Name() != "random-allocation" || !sibling.IsLeaf {
				t.Fatalf("declared sibling was absorbed: %+v", sibling)
			}
		} else if len(r.Keys) != 1 || port.FindChild("1024") == nil {
			t.Fatalf("default wildcard sibling behavior changed: %+v", port)
		}
	}
}
