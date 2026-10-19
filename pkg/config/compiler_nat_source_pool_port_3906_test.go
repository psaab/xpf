// #3906: a source-NAT pool's `port range <low> to <high>` and `port
// no-translation` were SILENTLY IGNORED. The port parser required the
// non-Junos `range low <lo> high <hi>` keyword shape, so the Junos `port range
// <low> to <high>` never applied and the pool defaulted to 1024-65535 PAT;
// `no-translation` was dropped and the pool PAT-translated the port anyway; and
// a reversed / out-of-range range committed green then dropped the rule at
// runtime.
//
// The fix parses `port range <low> to <high>` (both the Junos `<low> to <high>`
// and the legacy `low <lo> high <hi>` shapes), applies `no-translation`, and
// adds validateSourceNATPoolStrict to reject a reversed or out-of-range range at
// commit. RED-on-revert:
//   - revert the parse: `port range 5000 to 6000` leaves PortLow/PortHigh at the
//     1024/65535 default (the range is dropped).
//   - revert no-translation parse: PortNoTranslation stays false.
//   - revert the strict validator (or its registration): a reversed range
//     compiles clean.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath, never NewParser.
package config

import "testing"

func snatPoolTree(t *testing.T, poolCmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	cmds := append([]string{}, poolCmds...)
	cmds = append([]string{"set security zones security-zone trust", "set security zones security-zone untrust"}, cmds...)
	cmds = append(cmds,
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool p1",
	)
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestSourceNATPoolPortRangeApplied_3906 is the core apply test. RED-on-revert:
// without the `<low> to <high>` parse the pool falls back to the 1024-65535
// default.
func TestSourceNATPoolPortRangeApplied_3906(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range 5000 to 6000")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 missing")
	}
	if pool.PortLow != 5000 || pool.PortHigh != 6000 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want 5000/6000 (range silently ignored -> 1024/65535 default on revert)",
			pool.PortLow, pool.PortHigh)
	}
	if pool.PortNoTranslation {
		t.Fatalf("PortNoTranslation = true, want false (only a range was configured)")
	}
}

// Legacy explicit-keyword shape (`range low <lo> high <hi>`) must still compile
// so an on-disk config authored against the pre-#3906 grammar keeps working.
func TestSourceNATPoolPortRangeLegacyShape_3906(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range low 5000 high 6000")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool.PortLow != 5000 || pool.PortHigh != 6000 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want 5000/6000 (legacy shape)", pool.PortLow, pool.PortHigh)
	}
}

// TestSourceNATPoolNoTranslation_3906: `port no-translation` sets the preserve
// flag. RED-on-revert: PortNoTranslation stays false.
func TestSourceNATPoolNoTranslation_3906(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port no-translation")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if !pool.PortNoTranslation {
		t.Fatalf("PortNoTranslation = false, want true (no-translation silently ignored on revert)")
	}
}

// TestSourceNATPoolPortRangeRejectedAtCommit_3906: reversed / out-of-range
// ranges hard-reject at commit and downgrade to a warning on the lenient path.
// RED-on-revert (validator removed): these compile clean.
func TestSourceNATPoolPortRangeRejectedAtCommit_3906(t *testing.T) {
	cases := []struct {
		name string
		pool []string
	}{
		{"reversed", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 port range 6000 to 5000"}},
		{"over-range-high", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 port range 5000 to 70000"}},
		{"reversed-legacy-shape", []string{
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 port range low 6000 high 5000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := snatPoolTree(t, tc.pool...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted invalid SNAT pool range %q (want reject)", tc.name)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected %q (want warn-and-compile): %v", tc.name, err)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatalf("CompileConfigLenient produced no warning for %q", tc.name)
			}
		})
	}
}

// Over-reject control: a valid range, an edge 1-65535 range, no-translation, and
// a pool with NO port config must all commit clean and keep the correct
// PortLow/PortHigh (default 1024/65535 when unconfigured).
func TestSourceNATPoolPortValidStillCompiles_3906(t *testing.T) {
	t.Run("valid-range", func(t *testing.T) {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32",
			"set security nat source pool p1 port range 1 to 65535")
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected valid edge range: %v", err)
		}
	})
	t.Run("no-port-config-defaults", func(t *testing.T) {
		tree := snatPoolTree(t,
			"set security nat source pool p1 address 203.0.113.5/32")
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected default pool: %v", err)
		}
		pool := cfg.Security.NAT.SourcePools["p1"]
		if pool.PortLow != 1024 || pool.PortHigh != 65535 {
			t.Fatalf("default PortLow/PortHigh = %d/%d, want 1024/65535", pool.PortLow, pool.PortHigh)
		}
		if pool.PortNoTranslation {
			t.Fatalf("PortNoTranslation = true, want false (no port config)")
		}
	})
}
