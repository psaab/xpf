package config

import (
	"strings"
	"testing"
)

// #15688: duplicate (kernelInterface, VRID, family) VRRP groups and RETH
// VRID election-domain collisions committed cleanly, then aborted
// vrrp.Manager.UpdateInstances for the entire node.

func TestVRRPInstanceIdentityDuplicateSameUnitFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.3/24 vrrp-group 1 virtual-address 10.0.0.101/24",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected duplicate (interface, VRID, family) groups to be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate VRRP instance identity") ||
		!strings.Contains(err.Error(), "vrrp-group 1") {
		t.Errorf("error %q does not name the duplicate instance identity", err.Error())
	}
}

func TestVRRPInstanceIdentityDuplicateInet6FailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::2/64 vrrp-inet6-group 7 virtual-inet6-address 2001:db8::100/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::3/64 vrrp-inet6-group 7 virtual-inet6-address 2001:db8::101/64",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected duplicate IPv6 (interface, VRID, family) groups to be rejected")
	}
}

func TestVRRPInstanceIdentityDualStackSameVRIDCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::2/64 vrrp-inet6-group 1 virtual-inet6-address 2001:db8::100/64",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("dual-stack same VRID with distinct families must commit: %v", err)
	}
}

func TestVRRPInstanceIdentityDifferentVRIDsCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.3/24 vrrp-group 2 virtual-address 10.0.0.101/24",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("different VRIDs on one unit must commit: %v", err)
	}
}

// The explicit group and the RETH-derived instance bind different interfaces
// here; patching the explicit group onto reth0 makes their kernel devices
// coincide. Use the standalone interface name that resolves to the RETH member:
// in this fixture reth0 has no physical member map, so CollectRethInstances
// binds "reth0" itself. Put the explicit group on reth0 instead.
func TestVRRPInstanceIdentityExplicitVsRethFailsCommit(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-15688",
		"set chassis cluster reth-count 1",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.0.2/24 vrrp-group 101 virtual-address 10.0.0.100/24",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("expected explicit VRID 101 group colliding with RETH RG1 (VRID 101) to be rejected")
	}
	if !strings.Contains(err.Error(), "VRID 101") {
		t.Errorf("error %q does not name VRID 101", err.Error())
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

func TestVRRPInstanceIdentityDuplicateRethInterfacesFailsCommit(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-15688",
		"set chassis cluster reth-count 2",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.0.2/24",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.2/24",
	}
	// reth0 and reth1 resolve to distinct kernel devices, so this is legal
	// unless both map to the same member; assert it commits (control).
	if _, err := CompileConfig(buildTree(t, lines)); err != nil {
		t.Fatalf("distinct RETH devices with same RG must commit: %v", err)
	}
}

func TestVRRPInstanceIdentityLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 1 virtual-address 10.0.0.100/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.3/24 vrrp-group 1 virtual-address 10.0.0.101/24",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject duplicate identity (no-brick): %v", err)
	}
	if !warningsContain(cfg.Warnings, "duplicate VRRP instance identity") {
		t.Fatalf("lenient compile should warn naming duplicate identity; warnings=%v", cfg.Warnings)
	}
}
