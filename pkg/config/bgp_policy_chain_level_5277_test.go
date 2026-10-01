package config

import "testing"

// #5277: a BGP policy chain `import`/`export [ A B C ]` is an ORDERED chain
// (each policy evaluated in turn, first terminal action wins). The FRR renderer
// composes the whole chain, but that is only correct if the compiler hands it a
// COHERENT same-LEVEL list. Junos most-specific-LEVEL-wins means a neighbor's
// own import/export REPLACES the inherited group import/export (it does NOT
// merge). These tests pin the compiler side of that contract.

// TestBGPNeighborImportReplacesGroup: a group-level import plus a neighbor-level
// import must yield ONLY the neighbor's own list (group dropped) — most-specific
// LEVEL wins. Pre-#5277 the compiler APPENDED [GROUP, NEIGH...] and the renderer
// picked the last, conflating "override" with "chain".
func TestBGPNeighborImportReplacesGroup(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols bgp group g1 import GROUP-IMPORT",
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 import [ NEIGH-A NEIGH-B ]",
		"set policy-options policy-statement GROUP-IMPORT term t then accept",
		"set policy-options policy-statement NEIGH-A term t then reject",
		"set policy-options policy-statement NEIGH-B term t then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	n := bgpNeighbor(t, cfg, "10.0.0.1")
	if got, want := n.Import, []string{"NEIGH-A", "NEIGH-B"}; !equalStrs(got, want) {
		t.Errorf("neighbor.Import = %v, want %v (neighbor's own import must REPLACE the inherited group import, #5277)", got, want)
	}
}

// TestBGPNeighborExportReplacesGroup is the export symmetric of the import test.
func TestBGPNeighborExportReplacesGroup(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 export GROUP-EXPORT",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 export [ N-A N-B ]",
		"set policy-options policy-statement GROUP-EXPORT term t then accept",
		"set policy-options policy-statement N-A term t then reject",
		"set policy-options policy-statement N-B term t then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	n := bgpNeighbor(t, cfg, "10.0.0.1")
	if got, want := n.Export, []string{"N-A", "N-B"}; !equalStrs(got, want) {
		t.Errorf("neighbor.Export = %v, want %v (neighbor's own export must REPLACE the inherited group export, #5277)", got, want)
	}
}

// TestBGPNeighborInheritsGroupWhenNoOwnPolicy: a neighbor WITHOUT its own
// import/export still inherits the group's ordered chain intact (the replace
// only triggers when the neighbor sets its own). Guards against the #5277
// replace clobbering the common inherit-only path (#5270 order-independence).
func TestBGPNeighborInheritsGroupWhenNoOwnPolicy(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group g1 import [ G-IN-A G-IN-B ]",
		"set protocols bgp group g1 export [ G-OUT-A G-OUT-B ]",
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set policy-options policy-statement G-IN-A term t then accept",
		"set policy-options policy-statement G-IN-B term t then accept",
		"set policy-options policy-statement G-OUT-A term t then accept",
		"set policy-options policy-statement G-OUT-B term t then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	n := bgpNeighbor(t, cfg, "10.0.0.1")
	if got, want := n.Import, []string{"G-IN-A", "G-IN-B"}; !equalStrs(got, want) {
		t.Errorf("neighbor.Import = %v, want %v (no own import → inherit the full group chain)", got, want)
	}
	if got, want := n.Export, []string{"G-OUT-A", "G-OUT-B"}; !equalStrs(got, want) {
		t.Errorf("neighbor.Export = %v, want %v (no own export → inherit the full group chain)", got, want)
	}
}
