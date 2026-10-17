package config

import (
	"strings"
	"testing"
)

// #14573: two units of the SAME reth carrying the same vlan-id both resolve
// onto the one member device (`reth1 unit 100 vlan-id 100` and `reth1 unit
// 200 vlan-id 100` -> ge-0-0-1.100). Pass 3 of
// validateInterfaceNameCollisionStrict skipped a reth ENTIRELY (#7795), so
// strict commit accepted it even though daemon_reth.go calls a duplicate
// vlan-id "an invalid config the compiler does not reject for uniqueness".
// The two units are distinct L3 identities on one ifindex: the forwarding
// builder's last-wins / contested-zone handling silently drops or mis-zones
// one of them.
//
// The fix runs the sibling subOwner check across units of the same reth,
// skipping only the reth-vs-authored-dotted-member alias (#6722 case C).

func rethDupVlanLines14573() []string {
	return []string{
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.100.1/24",
		"set interfaces reth1 unit 200 vlan-id 100 family inet address 10.0.200.1/24",
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
	}
}

// FAIL-ON-REVERT: restoring the whole-reth skip in pass 3 (or dropping the
// intra-reth subOwner check) makes strict CompileConfig accept this again.
func TestRethDuplicateVlanIDStrictReject14573(t *testing.T) {
	err := compileSet7795(t, rethDupVlanLines14573()...)
	if err == nil {
		t.Fatal("strict CompileConfig accepted two units of reth1 with the same " +
			"vlan-id 100; both resolve to ge-0-0-1.100, so one unit's zone/filter " +
			"silently wins on the shared ifindex (#14573)")
	}
	for _, want := range []string{"reth1.100", "reth1.200", "ge-0-0-1.100"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("duplicate-vlan error %q does not name %q", err, want)
		}
	}
}

// The derivation covers the unit-number arm too: a no-vlan unit resolves by
// unit number, so `unit 100` (no vlan-id) and `unit 200 vlan-id 100` of the
// same reth also share one device. FAIL-ON-REVERT: a gate re-deriving only
// base + "." + vlan-id accepts this.
func TestRethUnitNumberVsVlanIDStrictReject14573(t *testing.T) {
	err := compileSet7795(t,
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 100 family inet address 10.0.100.1/24",
		"set interfaces reth1 unit 200 vlan-id 100 family inet address 10.0.200.1/24",
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
	)
	if err == nil {
		t.Fatal("strict CompileConfig accepted reth1 unit 100 (unit-number device) " +
			"beside reth1 unit 200 vlan-id 100; both resolve to ge-0-0-1.100 (#14573)")
	}
	if !strings.Contains(err.Error(), "reth1.100") || !strings.Contains(err.Error(), "reth1.200") {
		t.Errorf("error must name reth1.100 and reth1.200; got: %v", err)
	}
}

// CONTROL (#6722 case C): a single reth VLAN unit plus the authored dotted
// member aliasing it must still compile — that aliasing is legal and built.
// Also the acceptance control from the issue: `reth1 unit 100 vlan-id 100`
// alone compiles.
func TestRethSingleVlanUnitAndDottedAliasStillCompile14573(t *testing.T) {
	if err := compileSet7795(t,
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.61.1/24",
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/1.100 gigether-options redundant-parent reth1",
	); err != nil {
		t.Fatalf("reth1 unit 100 vlan-id 100 plus the authored ge-0/0/1.100 alias "+
			"(#6722 case C) must still compile; rejecting it un-ships #6722: %v", err)
	}
}

// CONTROL: distinct vlan-ids on units of the same reth are the ordinary HA
// trunk shape and must compile. Without this the reject cells above would be
// satisfied by rejecting every multi-unit reth.
func TestRethDistinctVlanIDsStillCompile14573(t *testing.T) {
	if err := compileSet7795(t,
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.100.1/24",
		"set interfaces reth1 unit 200 vlan-id 200 family inet address 10.0.200.1/24",
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
	); err != nil {
		t.Fatalf("two reth units with distinct vlan-ids must compile: %v", err)
	}
}

// CONTROL: the same vlan-id on units of DIFFERENT reths (different members)
// is two devices, not one, and must compile. Pins the owner-scoping of the
// intra-reth check: an unscoped device registry would reject this.
func TestSameVlanIDOnDifferentRethsStillCompiles14573(t *testing.T) {
	if err := compileSet7795(t,
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100 family inet address 10.0.100.1/24",
		"set interfaces reth2 redundant-ether-options redundancy-group 1",
		"set interfaces reth2 vlan-tagging",
		"set interfaces reth2 unit 100 vlan-id 100 family inet address 10.1.100.1/24",
		"set chassis cluster reth-count 3",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth2",
	); err != nil {
		t.Fatalf("vlan-id 100 on units of two different reths resolves to two "+
			"member devices and must compile: %v", err)
	}
}

// Lenient split: the same duplicate-vlan reth config must LOAD with a warning
// on the tolerant path (#1960 no-brick), exactly like its #5832/#7795
// siblings. FAIL-ON-REVERT: hard-rejecting here bricks a grandfathered
// config on restart / peer-sync.
func TestRethDuplicateVlanIDLenientWarns14573(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range rethDupVlanLines14573() {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must NOT reject a grandfathered reth duplicate "+
			"vlan-id (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "reth1.100") || !hasWarningSubstr(cfg.Warnings, "reth1.200") {
		t.Fatalf("tolerant load must warn naming reth1.100 and reth1.200, warnings=%v", cfg.Warnings)
	}
}
