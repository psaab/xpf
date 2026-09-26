package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// TestShowChassisClusterStatus_VRRPLogicalZoneInterface is the #4908
// (C175-HC-116) and #10844 RED-on-revert guard. A security zone binds a
// LOGICAL interface ("ge-0-0-0.0"), but cfg.Interfaces.Interfaces is keyed by
// the BASE name ("ge-0-0-0"), so the old direct lookup silently dropped the
// VRRP row. The fixture also reports its configured VRRP group as non-master:
// both facts must be visible, and the row must be labelled `configured:`.
func TestShowChassisClusterStatus_VRRPLogicalZoneInterface(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-10844",
		"set chassis cluster reth-count 2",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 7 node 0 priority 200",
		"set chassis cluster redundancy-group 7 node 1 priority 100",
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.61.1/24 vrrp-group 7 virtual-address 10.0.61.254/24",
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.61.1/24 vrrp-group 7 priority 200",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 7",
		"set interfaces reth0 unit 0 family inet address 10.0.62.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.62.1/24 vrrp-group 7 virtual-address 10.0.62.254/24",
		"set interfaces reth0 unit 0 family inet address 10.0.62.1/24 vrrp-group 7 priority 200",
		"set security zones security-zone trust interfaces ge-0-0-0.0",
		"set security zones security-zone trust interfaces reth0.0",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("fixture did not compile chassis cluster")
	}
	reth := cfg.Interfaces.Interfaces["reth0"]
	if reth == nil || reth.RedundancyGroup != 7 {
		t.Fatalf("fixture reth0 redundancy group = %v, want 7", reth)
	}
	manager := cluster.NewManager(cfg.Chassis.Cluster.NodeID, cfg.Chassis.Cluster.ClusterID)
	manager.UpdateConfig(cfg.Chassis.Cluster)
	manager.SetRGForwardingFunc(func(rgID int) (cluster.RGForwarding, bool) {
		return cluster.RGForwarding{}, rgID == 7
	})
	c := &CLI{store: store, cluster: manager}
	out := captureStdout(t, func() {
		if err := c.showChassisClusterStatus(); err != nil {
			t.Fatalf("showChassisClusterStatus: %v", err)
		}
	})

	for _, want := range []string{
		"Redundancy group: 7",
		"vrrp-master=none",
		"VRRP on ge-0-0-0.0: configured: group 7, priority 200, VIP 10.0.61.254/24",
		"VRRP on reth0.0: configured: group 7, priority 200, VIP 10.0.62.254/24",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("configured non-master VRRP detail missing %q:\n%s", want, out)
		}
	}
}

// TestValidatePolicyZoneFilter is the #4908 (C175-HC-126) RED-on-revert guard
// for the local CLI: a from-zone/to-zone selector missing its zone value must
// be rejected rather than silently dropped (which returned a broader/one-sided
// inventory). Removing the validation call makes the malformed cases pass with
// nil errors.
func TestValidatePolicyZoneFilter(t *testing.T) {
	good := [][]string{
		{},
		{"from-zone", "trust"},
		{"from-zone", "trust", "to-zone", "untrust"},
		{"global"},
		{"detail", "from-zone", "trust", "to-zone", "untrust"},
	}
	for _, args := range good {
		if err := validatePolicyZoneFilter(args); err != nil {
			t.Errorf("validatePolicyZoneFilter(%v) = %v, want nil", args, err)
		}
	}
	bad := [][]string{
		{"from-zone"},
		{"to-zone"},
		{"from-zone", "trust", "to-zone"},
		{"from-zone", "to-zone", "untrust"},
	}
	for _, args := range bad {
		if err := validatePolicyZoneFilter(args); err == nil {
			t.Errorf("validatePolicyZoneFilter(%v) = nil, want an error (malformed selector)", args)
		}
	}
}
