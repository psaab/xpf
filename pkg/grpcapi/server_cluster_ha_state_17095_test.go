package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
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

// TestGetClusterHAStateInterceptorAdmission17095 proves the new RPC is
// priced and admitted through the REAL authorization path, not merely
// present as a handler (#18118 B1). The direct handler call above is
// test-only-green for authz: without the methodPermissions entry the
// census fails and a non-super caller would be charged PermAll at
// runtime. This cell drives principalUnaryInterceptor with a read-only
// principal: it must be admitted (PermView, the `show chassis cluster`
// equivalent), must reach the handler, and the table must price the
// method at exactly PermView. A stranger (no login class) must still
// be denied, so the cell cannot pass under a blanket-admit gate.
func TestGetClusterHAStateInterceptorAdmission17095(t *testing.T) {
	if perm, ok := methodPermissions["GetClusterHAState"]; !ok || perm != config.PermView {
		t.Fatalf("methodPermissions[GetClusterHAState] = %v, %v; want PermView, true (#18118 B1)", perm, ok)
	}
	if perm, mapped := methodPermission(pb.BpfrxService_GetClusterHAState_FullMethodName, &pb.GetClusterHAStateRequest{}); !mapped || perm != config.PermView {
		t.Fatalf("methodPermission(GetClusterHAState) = %v, %v; want PermView, true", perm, mapped)
	}
	usePasswdFixture5278(t)
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ClusterID: 1, NodeID: 0,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	})
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278), Cluster: m})
	req := &pb.GetClusterHAStateRequest{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_GetClusterHAState_FullMethodName}
	called := false
	handler := func(ctx context.Context, request any) (any, error) {
		called = true
		return s.GetClusterHAState(ctx, request.(*pb.GetClusterHAStateRequest))
	}
	resp, err := s.principalUnaryInterceptor(ctxWithPeerUID(authzUIDReadOnly), req, info, handler)
	if err != nil {
		t.Fatalf("read-only interceptor GetClusterHAState: %v, want admitted at PermView", err)
	}
	if !called {
		t.Fatal("interceptor admitted but never reached the GetClusterHAState handler")
	}
	if _, ok := resp.(*pb.GetClusterHAStateResponse); !ok {
		t.Fatalf("interceptor response type %T, want *pb.GetClusterHAStateResponse", resp)
	}
	// Negative control: a uid that is not a login user must be denied
	// at the same gate, so admission above is a class verdict, not a
	// blanket pass.
	called = false
	if _, err := s.principalUnaryInterceptor(ctxWithPeerUID(authzUIDStranger), req, info, handler); status.Code(err) != codes.PermissionDenied {
		t.Errorf("stranger interceptor GetClusterHAState: err=%v, want PermissionDenied", err)
	}
	if called {
		t.Error("stranger reached the GetClusterHAState handler past the interceptor")
	}
}
