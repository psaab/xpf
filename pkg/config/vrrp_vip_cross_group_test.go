package config

import (
	"strings"
	"testing"
)

// #14407: two distinct VRRP elections claiming one VIP on the same
// interface+family can elect different masters under divergent per-node
// track state, so both nodes install/advertise the same address.
//
// FAIL-ON-REVERT: drop the validateVRRPVIPCrossGroupStrict dispatch in
// compiler_uniformgates_cluster_zone.go (or the VRID-distinct check inside
// it) and the strict-reject tests below go green on the BAD config.

// TestVRRPCrossGroupSameVIPFailsCommit is the decisive fixture from the
// issue: one interface unit, two groups, same VIP, tracking DIFFERENT
// uplinks.
func TestVRRPCrossGroupSameVIPFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 priority 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 track-interface ge-0/0/1 priority-cost 150",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 2 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 2 priority 200",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 2 track-interface ge-0/0/2 priority-cost 150",
	})
	cfg, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject same VIP claimed by two groups; got cfg=%+v", cfg)
	}
	if !strings.Contains(err.Error(), "10.0.0.100") {
		t.Errorf("error %q does not name the VIP", err.Error())
	}
	if !strings.Contains(err.Error(), "vrrp-group 1") || !strings.Contains(err.Error(), "vrrp-group 2") {
		t.Errorf("error %q does not name both groups", err.Error())
	}
}

// TestVRRPCrossGroupSameVIPAliasSpellingFailsCommit pins canonicalization:
// a bare spelling and a CIDR spelling of the same host must collide.
func TestVRRPCrossGroupSameVIPAliasSpellingFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 2 virtual-address 10.0.0.100/24",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject alias spellings of the same VIP across groups")
	}
}

// TestVRRPCrossGroupDifferentInterfacesCommits is the control: the same VIP
// on two different units/interfaces is a different L2 domain and stays legal.
func TestVRRPCrossGroupDifferentInterfacesCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("same VIP on different interfaces must commit: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected compiled config")
	}
	// Different unit of the same interface is also a different kernel device.
	tree2 := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 1 family inet address 10.0.1.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 1 family inet address 10.0.0.3/24 vrrp-group 1 virtual-address 10.0.0.100/24",
	})
	if _, err := CompileConfig(tree2); err != nil {
		t.Fatalf("same VIP on different units must commit: %v", err)
	}
}

// TestVRRPCrossGroupDifferentVIPsCommits is the control: two groups carrying
// DIFFERENT VIPs on one unit still commit.
func TestVRRPCrossGroupDifferentVIPsCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 2 virtual-address 10.0.0.101/24",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("different VIPs on one unit must commit: %v", err)
	}
}

// TestVRRPCrossGroupLenientWarns pins the #1960 downgrade: lenient compile
// succeeds but warns naming the overlap.
func TestVRRPCrossGroupLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 2 virtual-address 10.0.0.100/24",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject cross-group overlap (no-brick): %v", err)
	}
	if !warningsContain(cfg.Warnings, "10.0.0.100") {
		t.Fatalf("lenient compile should warn naming the VIP; warnings=%v", cfg.Warnings)
	}
}

// TestVRRPCrossGroupExplicitVsRethFailsCommit covers the secondary arm: an
// explicit group whose VIP equals a RETH unit address competes with the
// RETH-derived instance (VRID 100+RG) when RETH VRRP synthesis is active.
func TestVRRPCrossGroupExplicitVsRethFailsCommit(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-14407",
		"set chassis cluster reth-count 1",
		"set chassis cluster no-private-rg-election",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.0.100/24 vrrp-group 1 virtual-address 10.0.0.100/24",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("expected explicit-vs-RETH same-VIP overlap to be rejected")
	} else if !strings.Contains(err.Error(), "10.0.0.100") {
		t.Errorf("error %q does not name the VIP", err.Error())
	}
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if l == "set chassis cluster no-private-rg-election" {
			continue
		}
		kept = append(kept, l)
	}
	if _, err := CompileConfig(buildTree(t, kept)); err != nil {
		t.Fatalf("private-rg-election disables RETH synthesis; must commit: %v", err)
	}
}
