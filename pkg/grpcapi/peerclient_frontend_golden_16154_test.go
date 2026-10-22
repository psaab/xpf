package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #16154 fold (Opus): byte-golden output must be pinned from the gRPC
// FRONTEND, not only via peerclient.Reconcile unit calls. These cells
// drive the real grpcapi path: SystemAction -> executeClusterFailover
// -> proxyClusterFailover -> proxyPeerSystemAction(WithPersistentNat-
// Generation) (which applies context.WithTimeout(ctx,
// proxyPeerTimeout(req)) on this surface's ctx) -> peerSystemActionFn
// returning DeadlineExceeded -> failoverProxyTimeoutOutcome ->
// peerclient.Reconcile -> SystemActionResponse.Message. The response
// message is byte-compared, including the peer-down cells (peer dead
// in the heartbeat view: PeerAlive()==false) that the pre-fold 15081
// grpcapi suite did not cover.

const (
	goldenGRPCIRGCommitted16154   = "Manual failover completed for redundancy group 1 (transfer committed on node 1; proxy response timed out after the peer committed)"
	goldenGRPCIRGNotMoved16154    = "Cluster failover outcome unknown for redundancy group 1: forwarded request to node 1 timed out; redundancy group 1 is not primary on node 1 — verify ownership before retrying"
	goldenGRPCIRGPeerDown16154    = "Cluster failover outcome unknown for redundancy group 1: forwarded request to node 1 timed out and the peer is unreachable; verify redundancy group 1 ownership before retrying"
	goldenGRPCIDataCommitted16154 = "Manual failover completed for data redundancy groups [1 2] (transfer committed on node 1; proxy response timed out after the peer committed)"
	goldenGRPCIDataPartial16154   = "Data failover outcome unknown: forwarded request to node 1 timed out; data redundancy groups now primary on node 1: [1] — verify ownership before retrying"
	goldenGRPCIDataNone16154      = "Data failover outcome unknown: forwarded request to node 1 timed out; data redundancy groups now primary on node 1: [] — verify ownership before retrying"
	goldenGRPCIDataPeerDown16154  = "Data failover outcome unknown: forwarded request to node 1 timed out and the peer is unreachable; verify redundancy group ownership before retrying"
)

func grpcFrontendGolden16154(t *testing.T, setPeer func(mgr *cluster.Manager), err error) *Server {
	t.Helper()
	s := failoverProxyServer15081(t)
	if setPeer != nil {
		setPeer(s.cluster)
	}
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, err
	}
	return s
}

func TestGRPCFrontendGolden16154(t *testing.T) {
	deadline := status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	cases := []struct {
		name    string
		action  string
		setPeer func(mgr *cluster.Manager)
		err     error
		want    string
	}{
		{
			name:   "rg committed after timeout",
			action: "cluster-failover:1:node1",
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
			},
			err:  deadline,
			want: goldenGRPCIRGCommitted16154,
		},
		{
			name:   "rg committed raw context deadline",
			action: "cluster-failover:1:node1",
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
			},
			err:  context.DeadlineExceeded,
			want: goldenGRPCIRGCommitted16154,
		},
		{
			name:   "rg peer reachable not moved",
			action: "cluster-failover:1:node1",
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
			},
			err:  deadline,
			want: goldenGRPCIRGNotMoved16154,
		},
		{
			name:    "rg peer down",
			action:  "cluster-failover:1:node1",
			setPeer: nil, // no peer states: PeerAlive()==false
			err:     deadline,
			want:    goldenGRPCIRGPeerDown16154,
		},
		{
			name:   "data committed after timeout",
			action: "cluster-failover-data:node1",
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
				mgr.SetPeerGroupStateForTesting(2, cluster.StatePrimary)
			},
			err:  deadline,
			want: goldenGRPCIDataCommitted16154,
		},
		{
			name:   "data partially completed",
			action: "cluster-failover-data:node1",
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
				mgr.SetPeerGroupStateForTesting(2, cluster.StateSecondary)
			},
			err:  deadline,
			want: goldenGRPCIDataPartial16154,
		},
		{
			name:   "data peer reachable none moved",
			action: "cluster-failover-data:node1",
			setPeer: func(mgr *cluster.Manager) {
				mgr.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
				mgr.SetPeerGroupStateForTesting(2, cluster.StateSecondary)
			},
			err:  deadline,
			want: goldenGRPCIDataNone16154,
		},
		{
			name:    "data peer down",
			action:  "cluster-failover-data:node1",
			setPeer: nil,
			err:     deadline,
			want:    goldenGRPCIDataPeerDown16154,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := grpcFrontendGolden16154(t, tc.setPeer, tc.err)
			resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: tc.action})
			if err != nil {
				t.Fatalf("SystemAction() error = %v, want reconciled (byte-golden) response", err)
			}
			if resp == nil {
				t.Fatal("SystemAction() response = nil, want byte-golden message")
			}
			if resp.Message != tc.want {
				t.Fatalf("gRPC response byte-drift:\n got: %q\nwant: %q", resp.Message, tc.want)
			}
		})
	}
}
