package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #18585: `request chassis cluster failover redundancy-group N node <peer>`
// is refused before any fabric RPC when the heartbeat-measured peer clock is
// past the guaranteed-break bound, with the number and both remedies. Below
// the bound it is proxied exactly as before.
func TestCrossNodeFailoverFailsFastOnPeerClockSkew18585(t *testing.T) {
	mgr := cluster.NewManager(0, 22)
	calls := 0
	s := &Server{
		cluster: mgr,
		peerSystemActionFn: func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
			calls++
			return &pb.SystemActionResponse{Message: "Manual failover completed for redundancy group 2 (transfer committed)"}, nil
		},
	}
	for _, action := range []string{"cluster-failover:2:node1", "cluster-failover-data:node1"} {
		mgr.NotePeerWallClockForTesting(-72 * time.Second)
		_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: action})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "run this command on node1") {
			t.Fatalf("%s with the peer 72 s behind: err = %v, want FailedPrecondition naming the remedy", action, err)
		}
		if calls != 0 {
			t.Fatalf("%s: the fabric RPC must not be attempted; calls=%d", action, calls)
		}
		mgr.NotePeerWallClockForTesting(-1 * time.Second)
		if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: action}); err != nil {
			t.Fatalf("%s with clocks 1 s apart: %v", action, err)
		}
		if calls != 1 {
			t.Fatalf("%s: below the bound the request must be proxied once; calls=%d", action, calls)
		}
		calls = 0
	}
}

// #18585 review seat AE: the refusal's recommended workaround — run the move
// on the target node, a local pull — must NOT be refused on the same skew.
func TestLocalTargetFailoverProceedsOnPeerClockSkew18585(t *testing.T) {
	mgr := cluster.NewManager(0, 22)
	mgr.NotePeerWallClockForTesting(-72 * time.Second)
	s := &Server{
		cluster: mgr,
		peerSystemActionFn: func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
			t.Fatalf("a local-target move must not proxy to the peer")
			return nil, nil
		},
	}
	for _, action := range []string{"cluster-failover:2:node0", "cluster-failover-data:node0"} {
		_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: action})
		if err != nil && strings.Contains(err.Error(), "cross-node request not sent") {
			t.Fatalf("%s: the local pull was refused on the peer's clock: %v", action, err)
		}
	}
}
