package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #18559: `request chassis cluster failover redundancy-group N` run on the
// OWNER of a data RG used to be Manager.ManualFailover: the owner demoted at
// once and the peer promoted on its next heartbeat, so everything the owner
// fabric-redirected in between died on the peer's HA-inactive gate (H1's
// planned moves, 71-336 ms on loss). It now runs the node-targeted,
// make-before-break transfer to the peer. The remote CLI (`cli -c`) reaches
// this handler, so these cells drive SystemAction itself.

const untargetedTransferOK18559 = "Manual failover completed for redundancy group 1 (transfer committed)"

// untargetedServer18559 builds node0 with RG0/RG1 configured. owner says
// whether node0 is primary for RG1; peerAlive whether node1 is up (and then
// primary for RG1 iff node0 is not).
func untargetedServer18559(t *testing.T, owner, peerAlive bool, peer func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error)) (*Server, *cluster.Manager) {
	t.Helper()
	mgr := cluster.NewManager(0, 22)
	mgr.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 0, NodePriorities: map[int]int{0: 100, 1: 90}},
		{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
	}})
	// UpdateConfig's single-node election makes the RGs primary; set both
	// roles explicitly.
	local := cluster.StateSecondary
	if owner {
		local = cluster.StatePrimary
	}
	mgr.SetGroupStateForTesting(0, local)
	mgr.SetGroupStateForTesting(1, local)
	if peerAlive {
		peerState := cluster.StatePrimary
		if owner {
			peerState = cluster.StateSecondary
		}
		mgr.SetPeerGroupStateForTesting(1, peerState)
	}
	return &Server{cluster: mgr, peerSystemActionFn: peer}, mgr
}

func failoverCount18559(mgr *cluster.Manager, rgID int) int {
	for _, rg := range mgr.GroupStates() {
		if rg.GroupID == rgID {
			return rg.FailoverCount
		}
	}
	return -1
}

// The owner of a data RG with a live peer forwards the targeted transfer to
// the peer and does NOT resign locally. RED before #18559: the handler called
// ManualFailover and never asked the peer.
func TestUntargetedFailoverOnOwnerRunsPeerTransfer18559(t *testing.T) {
	var forwarded []string
	s, mgr := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		forwarded = append(forwarded, req.Action)
		return &pb.SystemActionResponse{Message: untargetedTransferOK18559}, nil
	})
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if err != nil {
		t.Fatalf("untargeted failover on the owner: %v", err)
	}
	if len(forwarded) != 1 || forwarded[0] != "cluster-failover:1:node1" {
		t.Fatalf("forwarded to the peer = %q, want exactly [cluster-failover:1:node1] (the make-before-break transfer)", forwarded)
	}
	if resp.GetMessage() != untargetedTransferOK18559 {
		t.Fatalf("message = %q, want the peer's transfer result %q", resp.GetMessage(), untargetedTransferOK18559)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned locally (ManualFailover) instead of leaving the demotion to the transfer's fence")
	}
}

// notReady18559 is the refusal RequestPeerFailover returns on a peer that is
// not takeover-ready, as the peer's gRPC handler wraps it.
var notReady18559 = status.Error(codes.FailedPrecondition,
	"local redundancy group 1 not ready for explicit failover ready=false ready_since=<zero> reasons=[session sync not primed]")

// A peer that is not takeover-ready refuses before it sends anything. The
// owner must NOT resign into it: demoting to a peer that will not promote
// strands the RG (#18731 class). The refusal reaches the operator with the
// peer's readiness reasons. RED before #18559: the handler resigned and
// reported "triggered".
func TestUntargetedFailoverPeerNotReadyRefusesWithoutDemoting18559(t *testing.T) {
	calls := 0
	s, mgr := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		calls++
		return nil, notReady18559
	})
	before := failoverCount18559(mgr, 1)
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want the peer's FailedPrecondition refusal", err)
	}
	for _, want := range []string{"not ready for explicit failover", "reasons=[session sync not primed]", "node 1", "no local resign"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}
	if calls != 1 {
		t.Fatalf("transfer attempts = %d, want 1", calls)
	}
	if !mgr.IsLocalPrimary(1) || failoverCount18559(mgr, 1) != before {
		t.Fatal("the owner demoted although the peer refused the transfer")
	}
}

// A request that provably never reached the peer (dialPeer found no fabric
// address) falls back to the pre-#18559 local resign: nothing happened
// anywhere, and the peer claims the RG on its next heartbeat.
func TestUntargetedFailoverDialFailureFallsBackToLocalResign18559(t *testing.T) {
	s, mgr := untargetedServer18559(t, true, true, nil) // no seam: the real dialPeer runs and finds no fabric address
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if err != nil {
		t.Fatalf("a transfer that never reached the peer must fall back to the local resign: %v", err)
	}
	if resp.GetMessage() != "Manual failover triggered for redundancy group 1" {
		t.Fatalf("message = %q, want the local-resign text", resp.GetMessage())
	}
	if mgr.IsLocalPrimary(1) {
		t.Fatal("local resign did not run after the dial failure")
	}
}

// An RPC error after the dial may have been delivered, so it is reported and
// nothing resigns on top of it.
func TestUntargetedFailoverRPCErrorAfterDialDoesNotResign18559(t *testing.T) {
	s, mgr := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.Unavailable, "connection reset by peer")
	})
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want the RPC's Unavailable", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned on top of a request that may have reached the peer")
	}
}

// A transfer whose outcome is unknown (the proxy deadline reconciled with the
// RG not yet on the peer) may still commit, so the owner must not resign on
// top of it. RED before #18559: the handler resigned and reported success.
func TestUntargetedFailoverUnknownOutcomeDoesNotResign18559(t *testing.T) {
	s, mgr := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	})
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.Unknown {
		t.Fatalf("err = %v, want codes.Unknown (outcome unknown, verify before retrying)", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned on top of a transfer whose outcome is unknown")
	}
}

// A transfer that got as far as this node's applied-ACK has demoted it; its
// abort or the #5079 lease restores it. The failure is reported and nothing
// resigns on top of it. RED before #18559 (no transfer, plain resign).
func TestUntargetedFailoverAfterOwnerAckDoesNotResign18559(t *testing.T) {
	var mgr *cluster.Manager
	s, m := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		// The peer's request reached this node's OnRemoteFailover, which
		// demoted it inside the #5640 fence, and then the commit failed.
		mgr.SetGroupStateForTesting(1, cluster.StateSecondaryHold)
		return nil, status.Error(codes.FailedPrecondition, "failover commit for redundancy group 1 failed")
	})
	mgr = m
	before := failoverCount18559(mgr, 1)
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want the transfer's FailedPrecondition", err)
	}
	if got := failoverCount18559(mgr, 1); got != before {
		t.Fatalf("FailoverCount %d -> %d: a local resign ran on top of a transfer that had already demoted this node", before, got)
	}
}

// The untargeted form keeps its local-resign meaning where there is nothing
// to make before the break: RG0, a node that does not own the RG, a dead peer,
// and a request the peer forwarded to us (never re-proxied).
func TestUntargetedFailoverStaysLocalResignOutsideOwnerDataRG18559(t *testing.T) {
	noProxy := func(t *testing.T) func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
			t.Errorf("unexpected peer transfer %q", req.Action)
			return nil, status.Error(codes.Internal, "unexpected")
		}
	}
	t.Run("RG0 on the owner", func(t *testing.T) {
		s, mgr := untargetedServer18559(t, true, true, noProxy(t))
		if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:0"}); err != nil {
			t.Fatalf("RG0 untargeted failover: %v", err)
		}
		if mgr.IsLocalPrimary(0) {
			t.Fatal("RG0 must keep the local resign")
		}
	})
	t.Run("non-owner", func(t *testing.T) {
		s, _ := untargetedServer18559(t, false, true, noProxy(t))
		if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"}); err != nil {
			t.Fatalf("untargeted failover on the non-owner: %v", err)
		}
	})
	t.Run("peer dead", func(t *testing.T) {
		s, mgr := untargetedServer18559(t, true, false, noProxy(t))
		if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"}); err != nil {
			t.Fatalf("untargeted failover with no peer: %v", err)
		}
		if mgr.IsLocalPrimary(1) {
			t.Fatal("with no peer the local resign must still run")
		}
	})
	t.Run("forwarded by the peer", func(t *testing.T) {
		s, _ := untargetedServer18559(t, true, true, noProxy(t))
		ctx := withPeerMarkers(context.Background(), peerMarkers{forwarded: true})
		_, _ = s.SystemAction(ctx, &pb.SystemActionRequest{Action: "cluster-failover:1"})
	})
}

// #18585 + #18559: with the peer's clock past the fabric-token bound the
// transfer is refused before any fabric RPC, so nothing was sent and the
// owner falls back to the local resign instead of failing the command.
func TestUntargetedFailoverClockRefusalFallsBackToLocalResign18559(t *testing.T) {
	calls := 0
	s, mgr := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		calls++
		return &pb.SystemActionResponse{Message: untargetedTransferOK18559}, nil
	})
	mgr.NotePeerWallClockForTesting(-72 * time.Second)
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"}); err != nil {
		t.Fatalf("clock-refused transfer must fall back to the local resign: %v", err)
	}
	if calls != 0 {
		t.Fatalf("a clock-refused transfer must not reach the fabric; calls=%d", calls)
	}
	if mgr.IsLocalPrimary(1) {
		t.Fatal("local resign did not run after the clock refusal")
	}
}
