// #15675 (V6-02): `security nat source pool <name> port` bundle:
//   - empty/hierarchical `port range` silently defaulted to 1024-65535;
//   - `port no-translation` + `port deterministic` compiled without
//     exclusivity (dataplane silently suppressed deterministic);
//   - `port no-translation` pools were charged 64,512 port slots/IP by
//     the aggregate budget walk;
//   - `port <N>` and `port random-allocation` were rejected by
//     SchemaValidate (closed-world) while the compiler accepted /
//     mis-rejected them.
//
// Flat-set fixtures MUST use ParseSetCommand/SetPath (snatPoolTree);
// hierarchical fixtures MUST use NewParser.
package config

import (
	"strings"
	"testing"
)

// Empty flat `port range;` must fail closed, not widen to 1024-65535.
func TestSourceNATPoolEmptyRangeFailsClosed_15675(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range")
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted empty `port range` (want strict reject, not silent 1024-65535 default)")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Fatalf("lenient compile produced no warning for empty range")
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 missing")
	}
	if pool.PortRangeInvalidSpec == "" {
		t.Fatalf("PortRangeInvalidSpec empty, want non-empty sentinel (%q)", pool.PortRangeInvalidSpec)
	}
	if _, _, ok := SourceNATPoolPortRange(pool); ok {
		t.Fatalf("SourceNATPoolPortRange ok=true for empty range, want false (pool must be marked unusable)")
	}
	if reason := SourceNATPoolUnusableReason(pool); reason != "invalid_port_range" {
		t.Fatalf("SourceNATPoolUnusableReason = %q, want invalid_port_range", reason)
	}
	// The lenient contract keeps the unstamped default in the raw
	// fields (#5457); unusability is carried by PortRangeInvalidSpec /
	// SourceNATPoolPortRange above, not by zeroing the raw range.
	if pool.PortLow != 1024 || pool.PortHigh != 65535 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want unstamped default 1024/65535 on lenient path", pool.PortLow, pool.PortHigh)
	}
}

// Hierarchical `port { range { 5000 to 6000; } }` must compile as authored.
func TestSourceNATPoolHierarchicalRangeBlock_15675(t *testing.T) {
	const txt = "security {\n zones { security-zone trust; security-zone untrust; }\n nat {\n  source {\n   pool p1 {\n    address { 203.0.113.5/32; }\n    port { range { 5000 to 6000; } }\n   }\n   rule-set RS {\n    from zone trust;\n    to zone untrust;\n    rule R1 { match { source-address 10.0.0.0/24; } then { source-nat { pool p1; } } }\n   }\n  }\n }\n}\n"
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected hierarchical range block: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 missing")
	}
	if pool.PortLow != 5000 || pool.PortHigh != 6000 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want 5000/6000 (hierarchical range { } silently dropped to default on revert)", pool.PortLow, pool.PortHigh)
	}
}

// Hierarchical empty `port { range; }` must fail closed.
func TestSourceNATPoolHierarchicalEmptyRange_15675(t *testing.T) {
	const txt = "security {\n zones { security-zone trust; security-zone untrust; }\n nat {\n  source {\n   pool p1 {\n    address { 203.0.113.5/32; }\n    port { range; }\n   }\n  }\n }\n}\n"
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted hierarchical empty range")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool.PortRangeInvalidSpec == "" {
		t.Fatalf("PortRangeInvalidSpec empty for hierarchical empty range")
	}
}

// `port no-translation` + `port deterministic` must reject at strict
// compile (not silently suppress deterministic) and warn leniently.
func TestSourceNATPoolNoTranslationDeterministicExclusive_15675(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port no-translation",
		"set security nat source pool p1 port deterministic block-size 512",
		"set security nat source pool p1 port deterministic host address 10.0.0.0/16")
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted no-translation + deterministic (want mutual-exclusivity reject)")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want mutually exclusive", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "mutually exclusive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient warnings %v lack mutually-exclusive warning", cfg.Warnings)
	}
}

// Control: deterministic alone still compiles; no-translation alone still compiles.
func TestSourceNATPoolExclusiveControls_15675(t *testing.T) {
	det := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port deterministic block-size 512",
		"set security nat source pool p1 port deterministic host address 10.0.0.0/26")
	if _, err := CompileConfig(det); err != nil {
		t.Fatalf("deterministic alone rejected: %v", err)
	}
	nt := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port no-translation")
	if _, err := CompileConfig(nt); err != nil {
		t.Fatalf("no-translation alone rejected: %v", err)
	}
}

// `port no-translation` pools charge 0 port slots, not 64,512/IP.
func TestSourceNATPoolNoTranslationZeroPortCharge_15675(t *testing.T) {
	// Unit: resolver reports no port capacity.
	pool := &NATPool{Name: "p1", Addresses: []string{"203.0.113.5/32"}, PortNoTranslation: true}
	lo, hi, ok := SourceNATPoolPortRange(pool)
	if !ok || lo != 0 || hi != 0 {
		t.Fatalf("SourceNATPoolPortRange(no-translation) = %d-%d ok=%v, want 0-0 true", lo, hi, ok)
	}
	// Aggregate: referenced no-translation pool charges portCap 0.
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port no-translation")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	charges := sourceNATAggregateReferencedCharges(cfg)
	if len(charges) != 1 {
		t.Fatalf("charges = %+v, want 1", charges)
	}
	if charges[0].portCap != 0 {
		t.Fatalf("portCap = %d, want 0 for no-translation pool (64,512/IP over-charge on revert)", charges[0].portCap)
	}
	if charges[0].addrs != 1 {
		t.Fatalf("addrs = %d, want 1 (address budget still charged)", charges[0].addrs)
	}
	// Control: a normal pool still charges its range.
	tree2 := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range 5000 to 6000")
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig control: %v", err)
	}
	c2 := sourceNATAggregateReferencedCharges(cfg2)
	if len(c2) != 1 || c2[0].portCap != 1001 {
		t.Fatalf("control charges = %+v, want portCap 1001", c2)
	}
}

// `port <N>` and `port random-allocation` pass SchemaValidate and compile.
func TestSourceNATPoolPortNumericAndRandomSchema_15675(t *testing.T) {
	for _, cmd := range []string{
		"set security nat source pool p1 port 5000",
		"set security nat source pool p1 port random-allocation",
		"set security nat source pool p1 port no-random-allocation",
	} {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32", cmd)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate(%q): %v (want pass)", cmd, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", cmd, err)
		}
		pool := cfg.Security.NAT.SourcePools["p1"]
		switch {
		case strings.HasSuffix(cmd, "port 5000"):
			if pool.PortLow != 5000 || pool.PortHigh != 5000 {
				t.Fatalf("port 5000 => %d-%d, want 5000-5000", pool.PortLow, pool.PortHigh)
			}
		case strings.HasSuffix(cmd, "random-allocation") && !strings.Contains(cmd, "no-random"):
			if !pool.PortRandomAllocation {
				t.Fatalf("random-allocation not recorded")
			}
		case strings.Contains(cmd, "no-random-allocation"):
			if pool.PortRandomAllocation {
				t.Fatalf("no-random-allocation left PortRandomAllocation true")
			}
			if !pool.PortNoRandomAllocationAuthored {
				t.Fatalf("no-random-allocation authored marker not set")
			}
			// Accepted-only advisory must surface.
			found := false
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, "no-random-allocation") {
					found = true
				}
			}
			if !found {
				t.Fatalf("ValidateConfig lacks no-random-allocation advisory: %v", ValidateConfig(cfg))
			}
		}
	}
	// Control: an unknown port keyword is admitted by the schema
	// wildcard (it occupies the numeric slot) but fails CLOSED at
	// strict compile as an invalid port spec — never silently
	// widened to the default range.
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port bogus-allocation")
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted unknown port keyword bogus-allocation (want fail-closed invalid range)")
	}
}
