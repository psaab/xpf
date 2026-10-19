package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #15239 (A56-01): the orchestrator rejoin travels over SystemAction. Before
// the fix, grpcCluster.ResetFailover issued cluster-failover-reset:<rg> per
// configured RG, and each per-RG Manager.ResetFailover cleared the
// node-global kernel-upgrade hold inline — so the FIRST RG's reset released
// an unverified candidate on every RG. The rejoin is now the single
// `cluster-rejoin` action (Manager.ResetAllFailover): every RG reset AND
// the hold cleared, synchronously, in one node-local verb. A per-RG
// cluster-failover-reset:<rg> must leave the hold in place.
//
// Revert either half and this goes RED: drop the cluster-rejoin case and
// the action is InvalidArgument; restore the per-RG hold clear and the
// reset cell's hold assertion fails.

func rejoinManager15239(t *testing.T) *cluster.Manager {
	t.Helper()
	m := cluster.NewManager(0, 1)
	m.SetKernelUpgradeHold(cluster.KernelUpgradeHoldCandidate)
	cfg := &config.ClusterConfig{
		RethCount: 2,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
			{ID: 1, NodePriorities: map[int]int{0: 200}},
		},
	}
	m.UpdateConfig(cfg)
	if m.IsLocalPrimary(0) || m.IsLocalPrimary(1) {
		t.Fatal("precondition: held candidate must be secondary on every RG")
	}
	return m
}

func TestSystemActionClusterRejoinClearsHold15239(t *testing.T) {
	m := rejoinManager15239(t)
	s := &Server{cluster: m}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-rejoin"})
	if err != nil {
		t.Fatalf("SystemAction(cluster-rejoin): %v", err)
	}
	if resp.GetMessage() == "" {
		t.Error("cluster-rejoin must return a message")
	}
	if m.KernelUpgradeHeld() {
		t.Fatal("cluster-rejoin (ResetAllFailover) must clear the kernel-upgrade hold synchronously")
	}
	if !m.IsLocalPrimary(0) || !m.IsLocalPrimary(1) {
		t.Fatal("after cluster-rejoin the isolated node must reclaim primary on every RG")
	}
}

func TestSystemActionSingleRGResetPreservesHold15239(t *testing.T) {
	m := rejoinManager15239(t)
	s := &Server{cluster: m}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover-reset:1"}); err != nil {
		t.Fatalf("SystemAction(cluster-failover-reset:1): %v", err)
	}
	if !m.KernelUpgradeHeld() {
		t.Fatal("single-RG cluster-failover-reset:1 cleared the node-global kernel-upgrade hold (A56-01)")
	}
	if m.IsLocalPrimary(0) || m.IsLocalPrimary(1) {
		t.Fatal("held candidate claimed primary after a single-RG reset")
	}
	// The rejoin verb is local-only: it must never be fabric-safe (a peer
	// must not be able to release this node's hold over the fabric link).
	if isFabricSafeSystemAction(&pb.SystemActionRequest{Action: "cluster-rejoin"}) {
		t.Fatal("cluster-rejoin must be denied on the fabric listener (local-only)")
	}
}

func TestSystemActionClusterRejoinNoCluster15239(t *testing.T) {
	s := &Server{}
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-rejoin"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("cluster-rejoin with no cluster: code = %v (%v), want FailedPrecondition", status.Code(err), err)
	}
}
