package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #10844: ShowText must identify config-derived per-group details, not render
// them as live state. This fixture puts VRRP group 7 on reth0, which is
// explicitly attached to redundancy-group 7. The live aggregate says
// vrrp-master=none, so the configured VIP row must remain clearly qualified.
func TestShowTextClusterStatusLabelsConfiguredNonMasterVRRP10844(t *testing.T) {
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
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 7",
		"set interfaces reth0 unit 0 family inet address 10.0.62.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.62.1/24 vrrp-group 7 virtual-address 10.0.62.254/24",
		"set interfaces reth0 unit 0 family inet address 10.0.62.1/24 vrrp-group 7 priority 200",
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
	s := &Server{store: store, cluster: manager}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "chassis-cluster-status"})
	if err != nil {
		t.Fatalf("ShowText(chassis-cluster-status): %v", err)
	}
	for _, want := range []string{
		"Redundancy group: 7",
		"vrrp-master=none",
		"VRRP on reth0.0: configured: group 7, priority 200, VIP 10.0.62.254/24",
	} {
		if !strings.Contains(resp.GetOutput(), want) {
			t.Fatalf("configured non-master VRRP detail missing %q:\n%s", want, resp.GetOutput())
		}
	}
}
