package config

import (
	"testing"
)

// #15010: Junos `prefix-limit { maximum N; }` without `teardown` is
// log-only. The old renderer emitted a bare FRR `maximum-prefix N`, which
// tears the session down on overflow (bgpd bgp_maximum_prefix_overflow
// sends CEASE/max-prefix and, with no pmax_restart, stays suppressed until
// `clear bgp neighbor`). These cells pin the typed teardown model.

func bgpPrefixLimitTeardownTree15010(t *testing.T, family, extra string) *ConfigTree {
	t.Helper()
	lines := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family " + family + " unicast prefix-limit maximum 1000",
	}
	if extra != "" {
		lines = append(lines, "set protocols bgp group external family "+family+" unicast prefix-limit "+extra)
	}
	lines = append(lines, "set protocols bgp group external neighbor 10.0.0.2")
	return flatTreeFromSets(t, lines...)
}

func TestBGPPrefixLimitTeardownCompiles15010(t *testing.T) {
	// Default (no teardown): log-only.
	cfg, err := CompileConfig(bgpPrefixLimitTeardownTree15010(t, "inet", ""))
	if err != nil {
		t.Fatalf("compile default: %v", err)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if n.PrefixLimitInet != 1000 || n.PrefixLimitTeardownInet {
		t.Fatalf("default = %+v, want maximum 1000 log-only", n)
	}
	// Teardown bare.
	cfg, err = CompileConfig(bgpPrefixLimitTeardownTree15010(t, "inet", "teardown"))
	if err != nil {
		t.Fatalf("compile teardown bare: %v", err)
	}
	n = cfg.Protocols.BGP.Neighbors[0]
	if !n.PrefixLimitTeardownInet || n.PrefixLimitTeardownPctInet != 0 || n.PrefixLimitIdleTimeoutInet != 0 {
		t.Fatalf("teardown bare = %+v, want teardown pct=0 idle=0", n)
	}
	// Teardown with pct + idle-timeout minutes.
	cfg, err = CompileConfig(bgpPrefixLimitTeardownTree15010(t, "inet", "teardown 75 idle-timeout 30"))
	if err != nil {
		t.Fatalf("compile teardown 75/30: %v", err)
	}
	n = cfg.Protocols.BGP.Neighbors[0]
	if !n.PrefixLimitTeardownInet || n.PrefixLimitTeardownPctInet != 75 || n.PrefixLimitIdleTimeoutInet != 30 {
		t.Fatalf("teardown 75/30 = %+v, want pct 75 idle 30", n)
	}
	// Teardown with idle-timeout forever (encoded 0 with Forever flag, distinct from short-reestablish 0).
	cfg, err = CompileConfig(bgpPrefixLimitTeardownTree15010(t, "inet", "teardown idle-timeout forever"))
	if err != nil {
		t.Fatalf("compile teardown forever: %v", err)
	}
	n = cfg.Protocols.BGP.Neighbors[0]
	if !n.PrefixLimitTeardownInet || !n.PrefixLimitIdleForeverInet {
		t.Fatalf("teardown forever = %+v, want Forever true", n)
	}
	// inet6 mirror.
	cfg, err = CompileConfig(bgpPrefixLimitTeardownTree15010(t, "inet6", "teardown 50 idle-timeout 10"))
	if err != nil {
		t.Fatalf("compile inet6 teardown: %v", err)
	}
	n = cfg.Protocols.BGP.Neighbors[0]
	if n.PrefixLimitInet6 != 1000 || !n.PrefixLimitTeardownInet6 || n.PrefixLimitTeardownPctInet6 != 50 || n.PrefixLimitIdleTimeoutInet6 != 10 {
		t.Fatalf("inet6 teardown = %+v", n)
	}
}

func TestBGPPrefixLimitTeardownSchemaRejects15010(t *testing.T) {
	bad := []string{"teardown 0", "teardown 101", "teardown banana", "teardown 75 idle-timeout 0", "teardown 75 idle-timeout 2401", "teardown 75 idle-timeout banana", "teardown idle-timeout", "drop-excess", "hide-excess"}
	for _, extra := range bad {
		t.Run(extra, func(t *testing.T) {
			tree := bgpPrefixLimitTeardownTree15010(t, "inet", extra)
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("SchemaValidate accepted %q, want rejection", extra)
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted %q, want rejection", extra)
			}
		})
	}
	// drop-excess / hide-excess are not modelled; they must not commit silently.
	for _, kw := range []string{"drop-excess 50", "hide-excess 50"} {
		tree := bgpPrefixLimitTeardownTree15010(t, "inet", kw)
		if err := SchemaValidate(tree, nil); err == nil {
			// If schema admits unknown, compiler must reject/warn — checked below via compile.
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("%q committed silently with no model", kw)
			}
		}
	}
}

func TestBGPPrefixLimitTeardownHierarchical15010(t *testing.T) {
	src := `protocols { bgp { local-as 65001; group external { peer-as 65002; neighbor 10.0.0.2; family { inet { unicast { prefix-limit { maximum 1000; teardown 75 { idle-timeout 30; } } } } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("hierarchical schema: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hierarchical compile: %v", err)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if !n.PrefixLimitTeardownInet || n.PrefixLimitTeardownPctInet != 75 || n.PrefixLimitIdleTimeoutInet != 30 {
		t.Fatalf("hierarchical teardown = %+v, want 75/30", n)
	}
	// Neighbor override replaces group action wholesale.
	tree2 := flatTreeFromSets(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet unicast prefix-limit maximum 1000",
		"set protocols bgp group external family inet unicast prefix-limit teardown 90 idle-timeout 5",
		"set protocols bgp group external neighbor 10.0.0.2",
		"set protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit maximum 2000",
	)
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("override compile: %v", err)
	}
	n2 := cfg2.Protocols.BGP.Neighbors[0]
	// Neighbor supplied maximum-only prefix-limit: Junos most-specific
	// level replaces the action, so teardown is cleared (log-only).
	if n2.PrefixLimitInet != 2000 || n2.PrefixLimitTeardownInet {
		t.Fatalf("neighbor maximum-only override = %+v, want 2000 log-only", n2)
	}
	// Neighbor teardown override.
	tree3 := flatTreeFromSets(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet unicast prefix-limit maximum 1000",
		"set protocols bgp group external neighbor 10.0.0.2",
		"set protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit maximum 2000",
		"set protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit teardown idle-timeout forever",
	)
	cfg3, err := CompileConfig(tree3)
	if err != nil {
		t.Fatalf("neighbor teardown compile: %v", err)
	}
	n3 := cfg3.Protocols.BGP.Neighbors[0]
	if n3.PrefixLimitInet != 2000 || !n3.PrefixLimitTeardownInet || !n3.PrefixLimitIdleForeverInet {
		t.Fatalf("neighbor teardown forever = %+v", n3)
	}
}

func TestBGPPrefixLimitTeardownTolerantPreserves15010(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet unicast prefix-limit maximum 4000",
		"set protocols bgp group external family inet unicast prefix-limit teardown 80 idle-timeout 20",
		"set protocols bgp group external neighbor 10.0.0.2",
		"set protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit teardown banana",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted teardown banana")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if n.PrefixLimitInet != 4000 || !n.PrefixLimitTeardownInet || n.PrefixLimitTeardownPctInet != 80 || n.PrefixLimitIdleTimeoutInet != 20 {
		t.Fatalf("tolerant preserved = %+v, want group 4000 teardown 80/20", n)
	}
}
