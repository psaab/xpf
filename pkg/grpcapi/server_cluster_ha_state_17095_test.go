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

// TestGetClusterHAState17095 pins the typed RPC: presence is carried
// (peer HA absent when no peer, present when alive), RG states map to
// the wire enum, and a cluster-less server refuses FailedPrecondition
// rather than fabricating an empty state (#17095).
func TestGetClusterHAState17095(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ClusterID: 1, NodeID: 0,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	})
	s := &Server{cluster: m}
	resp, err := s.GetClusterHAState(context.Background(), &pb.GetClusterHAStateRequest{})
	if err != nil {
		t.Fatalf("GetClusterHAState: %v", err)
	}
	if resp.GetPeerAlive() {
		t.Error("fresh manager: peer alive")
	}
	if resp.LocalHaProtocol == nil {
		t.Error("local HA protocol must always be present")
	}
	if resp.PeerHaProtocol != nil {
		t.Error("no peer: peer HA protocol must be absent, not zero (#17095 presence)")
	}
	if resp.GetSessionSyncWirePresent() {
		t.Error("no peer: peer wire field must be absent")
	}
	if len(resp.GetRedundancyGroups()) != 1 || resp.GetRedundancyGroups()[0].GetPeerState() != pb.RGNodeState_RG_NODE_STATE_UNKNOWN {
		t.Errorf("RG peer state = %v, want UNKNOWN with no peer", resp.GetRedundancyGroups())
	}

	bare := &Server{}
	if _, err := bare.GetClusterHAState(context.Background(), &pb.GetClusterHAStateRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("cluster-less server: err=%v, want FailedPrecondition", err)
	}
}
