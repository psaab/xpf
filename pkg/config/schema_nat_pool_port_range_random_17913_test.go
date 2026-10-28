package config

import (
	"strings"
	"testing"
)

// #17913: combined source-NAT pool `port range <lo> to <hi> random-allocation`
// on ONE flat set line (and the legacy `low <lo> high <hi>` + either
// allocation modifier) is supported: SetPath absorbs the declared
// `random-allocation` / `no-random-allocation` as siblings behind the range
// leaf (see TestPoolRangeAbsorptionIsOptIn16670), then the compiler stamps
// both the range and modifier, as store-level coverage shows. SchemaValidate
// must not feed the trailing modifier to parseSourcePoolPortRange as a
// range endpoint.
//
// RED on master: SchemaValidate rejects the combined line with
// `port range "1024 to 2048 random-allocation" is invalid`.
func TestSourceNATPoolPortRangeRandomCombined17913(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cmd        string
		wantRand   bool
		wantNoRand bool
		wantLo     int
		wantHi     int
	}{
		{"junos-random", "set security nat source pool p1 port range 1024 to 2048 random-allocation", true, false, 1024, 2048},
		{"junos-no-random", "set security nat source pool p1 port range 1024 to 2048 no-random-allocation", false, true, 1024, 2048},
		{"legacy-random", "set security nat source pool p1 port range low 1024 high 2048 random-allocation", true, false, 1024, 2048},
		{"legacy-no-random", "set security nat source pool p1 port range low 1024 high 2048 no-random-allocation", false, true, 1024, 2048},
		{"single-random", "set security nat source pool p1 port range 1024 random-allocation", true, false, 1024, 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := snatPoolTree(t,
				"set security nat source pool p1 address 203.0.113.5/32", tc.cmd)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate(%q): %v (want combined range+modifier accepted, #17913)", tc.cmd, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig(%q): %v", tc.cmd, err)
			}
			pool := cfg.Security.NAT.SourcePools["p1"]
			if pool == nil {
				t.Fatalf("pool p1 missing for %q", tc.cmd)
			}
			if pool.PortLow != tc.wantLo || pool.PortHigh != tc.wantHi {
				t.Fatalf("%q => %d-%d, want %d-%d", tc.cmd, pool.PortLow, pool.PortHigh, tc.wantLo, tc.wantHi)
			}
			if pool.PortRandomAllocation != tc.wantRand {
				t.Fatalf("%q => PortRandomAllocation=%v, want %v", tc.cmd, pool.PortRandomAllocation, tc.wantRand)
			}
			if pool.PortNoRandomAllocationAuthored != tc.wantNoRand {
				t.Fatalf("%q => PortNoRandomAllocationAuthored=%v, want %v", tc.cmd, pool.PortNoRandomAllocationAuthored, tc.wantNoRand)
			}
			if pool.PortRangeInvalidSpec != "" {
				t.Fatalf("%q => PortRangeInvalidSpec=%q, want empty", tc.cmd, pool.PortRangeInvalidSpec)
			}
		})
	}

	// Hierarchical combined spelling: `port { range 1024 to 2048; random-allocation; }`.
	treeH, perrs := NewParser("security {\n nat {\n  source {\n   pool p1 {\n    address 203.0.113.5/32;\n    port { range 1024 to 2048; random-allocation; }\n   }\n  }\n }\n}\n").Parse()
	if len(perrs) != 0 {
		t.Fatalf("hierarchical parse: %v", perrs)
	}
	if err := SchemaValidate(treeH); err != nil {
		t.Fatalf("hierarchical SchemaValidate(range+random): %v", err)
	}
}

// The allocation modifier must not become a laundering token: bounds,
// ordering, malformed tails, unknown or repeated suffixes all still reject at
// SchemaValidate. Range-value errors retain the #16717 range diagnostic;
// malformed sibling shapes may be rejected by the closed-world child walk.
func TestSourceNATPoolPortRangeRandomControls17913(t *testing.T) {
	for _, tc := range []struct {
		name           string
		cmd            string
		wantRangeError bool
	}{
		{"zero-low", "set security nat source pool p1 port range 0 to 2048 random-allocation", true},
		{"over-high", "set security nat source pool p1 port range 1024 to 65536 random-allocation", true},
		{"decreasing", "set security nat source pool p1 port range 2048 to 1024 random-allocation", true},
		{"bogus-suffix", "set security nat source pool p1 port range 1024 to 2048 bogus-allocation", false},
		{"double-random", "set security nat source pool p1 port range 1024 to 2048 random-allocation random-allocation", false},
		{"random-first", "set security nat source pool p1 port range random-allocation 1024 to 2048", false},
		{"trailing-junk", "set security nat source pool p1 port range 1024 to 2048 random-allocation junk", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := snatPoolTree(t,
				"set security nat source pool p1 address 203.0.113.5/32", tc.cmd)
			err := SchemaValidate(tree)
			if err == nil {
				t.Fatalf("SchemaValidate accepted %q; want rejection (#17913)", tc.cmd)
			}
			if tc.wantRangeError && !strings.Contains(err.Error(), "is invalid; source-pool ports") {
				t.Fatalf("SchemaValidate(%q) error = %v, want the source-pool range message", tc.cmd, err)
			}
		})
	}
	// Direct tail-validator pins: the modifier is stripped exactly once
	// and only in trailing position.
	if err := validateSourcePoolPortRangeTail16717([]string{"1024", "to", "2048", "random-allocation"}, nil); err != nil {
		t.Fatalf("validateSourcePoolPortRangeTail16717 combined: %v", err)
	}
	if err := validateSourcePoolPortRangeTail16717([]string{"1024", "to", "2048", "random-allocation", "extra"}, nil); err == nil {
		t.Fatal("validateSourcePoolPortRangeTail16717 accepted trailing junk after modifier")
	}
}
