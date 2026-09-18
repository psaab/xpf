package config

import (
	"slices"
	"testing"
)

// #10055 — packed group tail beside a bracketed inline run.
//
// #9855 promotes an inline leaf peer and merges a packed group tail into it,
// but only when the peer's own tail expands under the schema walk. A bracketed
// run does not expand: packedBodyChildren consumes `virtual-address A` and
// chokes on the leftover `B`, so the helper bails to override and the group
// tail is dropped on valid input. Fixture is the issue's measured case.
func TestPackedBracketedPeerTailMerge10055(t *testing.T) {
	text := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 priority 200; } } } } } } } apply-groups G; ` +
		`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 virtual-address [ 10.0.61.1/24 10.0.61.3/24 ]; } } } } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var vg *VRRPGroup
	for _, g := range cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].VRRPGroups {
		vg = g
	}
	if vg == nil {
		t.Fatal("vrrp-group 1 did not compile")
	}
	if vg.Priority != 200 {
		t.Fatalf("priority = %d, want 200 (group tail must merge beside the bracketed run)", vg.Priority)
	}
	if !slices.Equal(vg.VirtualAddresses, []string{"10.0.61.1/24", "10.0.61.3/24"}) {
		t.Fatalf("virtual-addresses = %v, want both inline VIPs", vg.VirtualAddresses)
	}
}

// Inline-wins control: the promotion merges one level down, so an inline
// value still beats the group's. The bracketed peer expands, the group tail
// merges beside it, and the inline priority wins.
func TestPackedBracketedPeerInlineWins10055(t *testing.T) {
	text := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 priority 200; } } } } } } } apply-groups G; ` +
		`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 virtual-address [ 10.0.61.1/24 10.0.61.3/24 ] priority 100; } } } } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var vg *VRRPGroup
	for _, g := range cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].VRRPGroups {
		vg = g
	}
	if vg == nil {
		t.Fatal("vrrp-group 1 did not compile")
	}
	if vg.Priority != 100 {
		t.Fatalf("priority = %d, want 100 (inline value still wins after promotion)", vg.Priority)
	}
	if !slices.Equal(vg.VirtualAddresses, []string{"10.0.61.1/24", "10.0.61.3/24"}) {
		t.Fatalf("virtual-addresses = %v, want both inline VIPs", vg.VirtualAddresses)
	}
}

// Multi-statement tail with the same leftover shape: the bracketed run is the
// FIRST statement and a sibling follows. One consumption rule fixes both.
func TestPackedBracketedRunThenSibling10055(t *testing.T) {
	text := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 preempt; } } } } } } } apply-groups G; ` +
		`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 virtual-address [ 10.0.61.1/24 10.0.61.3/24 ] priority 100; } } } } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var vg *VRRPGroup
	for _, g := range cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].VRRPGroups {
		vg = g
	}
	if vg == nil {
		t.Fatal("vrrp-group 1 did not compile")
	}
	if !vg.Preempt {
		t.Fatalf("preempt = false, want true (group tail must merge beside the expanded run)")
	}
	if !slices.Equal(vg.VirtualAddresses, []string{"10.0.61.1/24", "10.0.61.3/24"}) {
		t.Fatalf("virtual-addresses = %v, want both inline VIPs", vg.VirtualAddresses)
	}
}

// Genuinely-unexpandable control: a bare multi-value leftover (no brackets,
// so no run to consume as one statement) still bails to override — base
// parity, tail verbatim, inline VIPs compile.
func TestPackedBareLeftoverStillBails10055(t *testing.T) {
	text := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 priority 200; } } } } } } } apply-groups G; ` +
		`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 virtual-address 10.0.61.1/24 10.0.61.3/24; } } } } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var vg *VRRPGroup
	for _, g := range cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].VRRPGroups {
		vg = g
	}
	if vg == nil {
		t.Fatal("vrrp-group 1 did not compile")
	}
	if vg.Priority != 100 {
		t.Fatalf("priority = %d, want 100 (bare leftover still bails to override)", vg.Priority)
	}
	if !slices.Equal(vg.VirtualAddresses, []string{"10.0.61.1/24", "10.0.61.3/24"}) {
		t.Fatalf("virtual-addresses = %v, want both inline VIPs", vg.VirtualAddresses)
	}
}
