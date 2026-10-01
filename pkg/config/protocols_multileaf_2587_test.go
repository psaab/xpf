package config

import "testing"

// #2587: a set of routing-protocol compilers read a `multi: true` export /
// import / members leaf via only child.Keys[1] (no Keys[1:] slice, no
// child.Children iteration). A bracketed list `[ a b c ]` collapses onto a
// single leaf's Keys in BOTH AST shapes (#2419), so those readers silently
// kept only the FIRST value — `protocols ospf export [ connected static ]`
// redistributed only `connected`; `community c1 members [ 65000:1 65000:2 ]`
// truncated.
//
// The fix routes each reader through the shared firewallMatchValues SSOT
// (Keys[1:] + each child leaf). The schema leaves were already marked
// multi:true (schema_routing.go), so only the compiler readers changed.
//
// These are fail-on-revert guards: each asserts ALL N values survive on BOTH
// the flat-set bracket-list shape (via ParseSetCommand + SetPath, the
// CLAUDE.md-mandated harness for flat-set) and the hierarchical block shape.
// Reverting any reader to the single-Keys[1] form drops the trailing values
// and fails the len/element assertions. The dual-AST differential harness
// alone misses this class because both shapes collapse identically (#2585) —
// dedicated assertions are required.

// --- OSPF export ---

func TestOSPFExportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols ospf export [ connected static bgp ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.OSPF == nil {
		t.Fatalf("OSPF config nil")
	}
	got := cfg.Protocols.OSPF.Export
	want := []string{"connected", "static", "bgp"}
	if !equalStrs(got, want) {
		t.Errorf("OSPF.Export = %v, want %v (trailing policies dropped without firewallMatchValues)", got, want)
	}
}

func TestOSPFExportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    ospf {
        export [ connected static bgp ];
    }
}`
	cfg := mustCompile(t, src)
	if cfg.Protocols.OSPF == nil {
		t.Fatalf("OSPF config nil")
	}
	got := cfg.Protocols.OSPF.Export
	want := []string{"connected", "static", "bgp"}
	if !equalStrs(got, want) {
		t.Errorf("OSPF.Export = %v, want %v", got, want)
	}
}

// --- BGP export + import ---

func TestBGPExportImportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp export [ connected static ospf ]",
		"set protocols bgp import [ imp1 imp2 ]",
		"set policy-options policy-statement imp1 term t then accept",
		"set policy-options policy-statement imp2 term t then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.BGP == nil {
		t.Fatalf("BGP config nil")
	}
	if got, want := cfg.Protocols.BGP.Export, []string{"connected", "static", "ospf"}; !equalStrs(got, want) {
		t.Errorf("BGP.Export = %v, want %v", got, want)
	}
	if got, want := cfg.Protocols.BGP.Import, []string{"imp1", "imp2"}; !equalStrs(got, want) {
		t.Errorf("BGP.Import = %v, want %v", got, want)
	}
}

func TestBGPExportImportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    bgp {
        local-as 65001;
        export [ connected static ospf ];
        import [ imp1 imp2 ];
    }
}
policy-options {
    policy-statement imp1 { term t { then accept; } }
    policy-statement imp2 { term t { then accept; } }
}`
	cfg := mustCompile(t, src)
	if cfg.Protocols.BGP == nil {
		t.Fatalf("BGP config nil")
	}
	if got, want := cfg.Protocols.BGP.Export, []string{"connected", "static", "ospf"}; !equalStrs(got, want) {
		t.Errorf("BGP.Export = %v, want %v", got, want)
	}
	if got, want := cfg.Protocols.BGP.Import, []string{"imp1", "imp2"}; !equalStrs(got, want) {
		t.Errorf("BGP.Import = %v, want %v", got, want)
	}
}

// --- BGP group export + import (#2702) ---
//
// The top-level `protocols bgp export/import` readers were routed through
// firewallMatchValues by #2587/#2690, but the per-GROUP and per-NEIGHBOR
// export/import readers still used the nodeVal-first pattern. nodeVal returns
// Keys[1] (non-empty for a bracket-list), so the `if v != ""` branch appended
// ONLY the first policy and the `else ... Keys[1:]` fallback never ran — every
// policy past the first was silently dropped (#2702, the #2690-review claim
// that group/neighbor were "already correct" was wrong).
//
// Group-level export/import are inherited into each neighbor's Export/Import
// slice (group default first), so these assert the FULL bracket list survives
// on the inheriting neighbor. Reverting the readers to nodeVal-first drops the
// trailing policies and fails the element assertions.

func bgpNeighbor(t *testing.T, cfg *Config, addr string) *BGPNeighbor {
	t.Helper()
	if cfg.Protocols.BGP == nil {
		t.Fatalf("BGP config nil")
	}
	for _, n := range cfg.Protocols.BGP.Neighbors {
		if n.Address == addr {
			return n
		}
	}
	t.Fatalf("neighbor %s not compiled (have %d neighbors)", addr, len(cfg.Protocols.BGP.Neighbors))
	return nil
}

func TestBGPGroupExportImportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 export [ OUT-A OUT-B ]",
		"set protocols bgp group g1 import [ IN-A IN-B ]",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set policy-options policy-statement OUT-A term t then accept",
		"set policy-options policy-statement OUT-B term t then accept",
		"set policy-options policy-statement IN-A term t then accept",
		"set policy-options policy-statement IN-B term t then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	n := bgpNeighbor(t, cfg, "10.0.0.1")
	if got, want := n.Export, []string{"OUT-A", "OUT-B"}; !equalStrs(got, want) {
		t.Errorf("group-inherited neighbor.Export = %v, want %v (trailing group export dropped without firewallMatchValues)", got, want)
	}
	if got, want := n.Import, []string{"IN-A", "IN-B"}; !equalStrs(got, want) {
		t.Errorf("group-inherited neighbor.Import = %v, want %v", got, want)
	}
}

func TestBGPGroupExportImportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    bgp {
        local-as 65001;
        group g1 {
            export [ OUT-A OUT-B ];
            import [ IN-A IN-B ];
            neighbor 10.0.0.1 { peer-as 65001; }
        }
    }
}
policy-options {
    policy-statement OUT-A { term t { then accept; } }
    policy-statement OUT-B { term t { then accept; } }
    policy-statement IN-A { term t { then accept; } }
    policy-statement IN-B { term t { then accept; } }
}`
	cfg := mustCompile(t, src)
	n := bgpNeighbor(t, cfg, "10.0.0.1")
	if got, want := n.Export, []string{"OUT-A", "OUT-B"}; !equalStrs(got, want) {
		t.Errorf("group-inherited neighbor.Export = %v, want %v", got, want)
	}
	if got, want := n.Import, []string{"IN-A", "IN-B"}; !equalStrs(got, want) {
		t.Errorf("group-inherited neighbor.Import = %v, want %v", got, want)
	}
}

// --- BGP neighbor export + import (#2702) ---
//
// Per-neighbor export/import are appended AFTER the inherited group policies
// (last-wins; #2490). With no group-level export here the neighbor slice holds
// exactly the per-neighbor bracket list, so the assertion targets the
// neighbor reader in isolation.

func TestBGPNeighborExportImportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 export [ N-OUT-A N-OUT-B ]",
		"set protocols bgp group g1 neighbor 10.0.0.1 import [ N-IN-A N-IN-B ]",
		"set policy-options policy-statement N-OUT-A term t then accept",
		"set policy-options policy-statement N-OUT-B term t then accept",
		"set policy-options policy-statement N-IN-A term t then accept",
		"set policy-options policy-statement N-IN-B term t then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	n := bgpNeighbor(t, cfg, "10.0.0.1")
	if got, want := n.Export, []string{"N-OUT-A", "N-OUT-B"}; !equalStrs(got, want) {
		t.Errorf("neighbor.Export = %v, want %v (trailing neighbor export dropped without firewallMatchValues)", got, want)
	}
	if got, want := n.Import, []string{"N-IN-A", "N-IN-B"}; !equalStrs(got, want) {
		t.Errorf("neighbor.Import = %v, want %v", got, want)
	}
}

func TestBGPNeighborExportImportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    bgp {
        local-as 65001;
        group g1 {
            neighbor 10.0.0.1 {
                peer-as 65001;
                export [ N-OUT-A N-OUT-B ];
                import [ N-IN-A N-IN-B ];
            }
        }
    }
}
policy-options {
    policy-statement N-OUT-A { term t { then accept; } }
    policy-statement N-OUT-B { term t { then accept; } }
    policy-statement N-IN-A { term t { then accept; } }
    policy-statement N-IN-B { term t { then accept; } }
}`
	cfg := mustCompile(t, src)
	n := bgpNeighbor(t, cfg, "10.0.0.1")
	if got, want := n.Export, []string{"N-OUT-A", "N-OUT-B"}; !equalStrs(got, want) {
		t.Errorf("neighbor.Export = %v, want %v", got, want)
	}
	if got, want := n.Import, []string{"N-IN-A", "N-IN-B"}; !equalStrs(got, want) {
		t.Errorf("neighbor.Import = %v, want %v", got, want)
	}
}

// --- OSPFv3 export ---

func TestOSPFv3ExportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols ospf3 export [ connected static ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.OSPFv3 == nil {
		t.Fatalf("OSPFv3 config nil")
	}
	got := cfg.Protocols.OSPFv3.Export
	want := []string{"connected", "static"}
	if !equalStrs(got, want) {
		t.Errorf("OSPFv3.Export = %v, want %v", got, want)
	}
}

func TestOSPFv3ExportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    ospf3 {
        export [ connected static ];
    }
}`
	cfg := mustCompile(t, src)
	if cfg.Protocols.OSPFv3 == nil {
		t.Fatalf("OSPFv3 config nil")
	}
	got := cfg.Protocols.OSPFv3.Export
	want := []string{"connected", "static"}
	if !equalStrs(got, want) {
		t.Errorf("OSPFv3.Export = %v, want %v", got, want)
	}
}

// --- IS-IS export ---

func TestISISExportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols isis export [ connected static bgp ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.ISIS == nil {
		t.Fatalf("ISIS config nil")
	}
	got := cfg.Protocols.ISIS.Export
	want := []string{"connected", "static", "bgp"}
	if !equalStrs(got, want) {
		t.Errorf("ISIS.Export = %v, want %v", got, want)
	}
}

func TestISISExportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    isis {
        export [ connected static bgp ];
    }
}`
	cfg := mustCompile(t, src)
	if cfg.Protocols.ISIS == nil {
		t.Fatalf("ISIS config nil")
	}
	got := cfg.Protocols.ISIS.Export
	want := []string{"connected", "static", "bgp"}
	if !equalStrs(got, want) {
		t.Errorf("ISIS.Export = %v, want %v", got, want)
	}
}

// --- policy-options community members ---

func TestCommunityMembersMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set policy-options community c1 members [ 65000:1 65000:2 65000:3 ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	cd := cfg.PolicyOptions.Communities["c1"]
	if cd == nil {
		t.Fatalf("community c1 not compiled")
	}
	got := cd.Members
	want := []string{"65000:1", "65000:2", "65000:3"}
	if !equalStrs(got, want) {
		t.Errorf("community c1 Members = %v, want %v (trailing members dropped without firewallMatchValues)", got, want)
	}
}

func TestCommunityMembersMultiValueHierarchical(t *testing.T) {
	src := `policy-options {
    community c1 {
        members [ 65000:1 65000:2 65000:3 ];
    }
}`
	cfg := mustCompile(t, src)
	cd := cfg.PolicyOptions.Communities["c1"]
	if cd == nil {
		t.Fatalf("community c1 not compiled")
	}
	got := cd.Members
	want := []string{"65000:1", "65000:2", "65000:3"}
	if !equalStrs(got, want) {
		t.Errorf("community c1 Members = %v, want %v", got, want)
	}
}

// mustCompile parses a hierarchical config source and compiles it, failing the
// test on any parse or compile error.
func mustCompile(t *testing.T, src string) *Config {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}
