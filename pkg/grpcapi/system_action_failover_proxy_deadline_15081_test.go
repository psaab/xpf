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

// #15081 (A43-02): proxyPeerSystemAction applied a flat 5s deadline to
// forwarded node-targeted cluster failovers. The peer's
// RequestPeerFailover sequence (failover ACK, commit-ready settle,
// commit ACK — each bounded at 20s/3s, and the barrier ACK alone can be
// delayed 30+s by bulk session sync) always risks exceeding 5s, so the
// operator received a bare DeadlineExceeded while the peer completed
// the ownership move.
//
// These tests drive the exact mechanism: SystemAction with a
// node-targeted failover action, proxied via peerSystemActionFn.
// RED-on-revert: restoring the 5s deadline fails the deadline-capture
// tests (captured ctx deadline ~5s, not the cluster budget); removing
// the timeout reconciliation fails the committed/unknown tests (bare
// codes.DeadlineExceeded surfaces).

func failoverProxyServer15081(t *testing.T) *Server {
	t.Helper()
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})
	s.cluster.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
			{ID: 2, NodePriorities: map[int]int{0: 100, 1: 90}},
		},
	})
	return s
}

// The forwarded failover must carry the cluster-budget deadline, not 5s.
func TestProxyFailoverDeadlineSizedFromClusterBudget15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	var captured time.Duration
	var hasDeadline bool
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		dl, ok := ctx.Deadline()
		hasDeadline = ok
		if ok {
			captured = time.Until(dl)
		}
		return &pb.SystemActionResponse{Message: "proxied"}, nil
	}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v", err)
	}
	if resp.Message != "proxied" {
		t.Fatalf("response = %q, want proxied", resp.Message)
	}
	if !hasDeadline {
		t.Fatal("forwarded failover carried no context deadline")
	}
	// Cluster budget: 2*20s ACK + 2*3s settle = 46s. Allow scheduling slack.
	if captured < 40*time.Second || captured > 50*time.Second {
		t.Fatalf("forwarded failover deadline = %v, want ~46s cluster budget (was 5s pre-fix)", captured)
	}
}

// Same sizing for the data-failover form.
func TestProxyDataFailoverDeadlineSizedFromClusterBudget15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	var captured time.Duration
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		if dl, ok := ctx.Deadline(); ok {
			captured = time.Until(dl)
		}
		return &pb.SystemActionResponse{Message: "proxied-data"}, nil
	}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover-data:node1"}); err != nil {
		t.Fatalf("SystemAction() error = %v", err)
	}
	if captured < 40*time.Second || captured > 50*time.Second {
		t.Fatalf("forwarded data failover deadline = %v, want ~46s cluster budget", captured)
	}
}

// Control: a non-failover forwarded action keeps the 5s budget.
func TestProxyNonFailoverKeepsShortDeadline15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	var captured time.Duration
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		if dl, ok := ctx.Deadline(); ok {
			captured = time.Until(dl)
		}
		return &pb.SystemActionResponse{Message: "nat cleared"}, nil
	}
	// clear-persistent-nat early-returns without a dataplane table, so it
	// never proxies; size via the helper directly plus a proxy-level
	// control below. The helper assertion is the control: only targeted
	// failovers get the long budget.
	if got := proxyPeerTimeout(&pb.SystemActionRequest{Action: "clear-persistent-nat"}); got != 5*time.Second {
		t.Fatalf("proxyPeerTimeout(clear-persistent-nat) = %v, want 5s", got)
	}
	if got := proxyPeerTimeout(&pb.SystemActionRequest{Action: "cluster-failover:1"}); got != 5*time.Second {
		t.Fatalf("proxyPeerTimeout(untargeted failover) = %v, want 5s (never proxied)", got)
	}
	if got := proxyPeerTimeout(&pb.SystemActionRequest{Action: "cluster-failover:1:node1"}); got < 40*time.Second {
		t.Fatalf("proxyPeerTimeout(targeted failover) = %v, want cluster budget", got)
	}
	_ = captured
}

// Peer committed but proxy leg timed out: report success, never a bare
// DeadlineExceeded.
func TestProxyFailoverTimeoutAfterPeerCommitReportsSuccess15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	s.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v, want reconciled success (bare DeadlineExceeded pre-fix)", err)
	}
	if !strings.Contains(resp.Message, "transfer committed") || !strings.Contains(resp.Message, "proxy response timed out") {
		t.Fatalf("response = %q, want committed-after-timeout success", resp.Message)
	}
}

// A raw context.DeadlineExceeded (transport ctx expiry) reconciles the
// same way as a gRPC DeadlineExceeded status.
func TestProxyFailoverContextDeadlineAfterPeerCommit15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	s.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, context.DeadlineExceeded
	}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v, want reconciled success", err)
	}
	if !strings.Contains(resp.Message, "transfer committed") {
		t.Fatalf("response = %q, want committed success", resp.Message)
	}
}

// Peer reachable but did not commit: outcome unknown, still not a bare
// DeadlineExceeded, and the message tells the operator to verify
// ownership before retrying.
func TestProxyFailoverTimeoutNotCommittedReportsUnknown15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	s.cluster.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v, want outcome-unknown response", err)
	}
	if !strings.Contains(resp.Message, "outcome unknown") || !strings.Contains(resp.Message, "verify") {
		t.Fatalf("response = %q, want outcome-unknown with verify guidance", resp.Message)
	}
	if strings.Contains(resp.Message, "transfer committed") && !strings.Contains(resp.Message, "timed out") {
		t.Fatalf("response = %q must not claim a committed transfer", resp.Message)
	}
}

// Data failover: peer primary for every data RG after a proxy timeout
// reports committed; a partial set reports unknown with the peer's set.
func TestProxyDataFailoverTimeoutReconciliation15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	s.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	s.cluster.SetPeerGroupStateForTesting(2, cluster.StatePrimary)
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover-data:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v, want reconciled success", err)
	}
	if !strings.Contains(resp.Message, "transfer committed") {
		t.Fatalf("response = %q, want committed success", resp.Message)
	}

	// Partial: only RG1 moved.
	s2 := failoverProxyServer15081(t)
	s2.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	s2.cluster.SetPeerGroupStateForTesting(2, cluster.StateSecondary)
	s2.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	}
	resp, err = s2.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover-data:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v, want outcome-unknown response", err)
	}
	if !strings.Contains(resp.Message, "outcome unknown") || !strings.Contains(resp.Message, "[1]") {
		t.Fatalf("response = %q, want outcome-unknown naming peer-primary [1]", resp.Message)
	}
}

// Control: a non-deadline proxy error relays verbatim (no reconciliation).
func TestProxyFailoverNonDeadlineErrorRelaysVerbatim15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	s.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.FailedPrecondition, "not ready for takeover")
	}
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not ready for takeover") {
		t.Fatalf("error = %v, want verbatim FailedPrecondition relay", err)
	}
}

// Control: a peer that answers within the budget returns its response
// untouched.
func TestProxyFailoverSuccessWithinBudgetUntouched15081(t *testing.T) {
	s := failoverProxyServer15081(t)
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return &pb.SystemActionResponse{Message: "Manual failover completed for redundancy group 1 (transfer committed)"}, nil
	}
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v", err)
	}
	if resp.Message != "Manual failover completed for redundancy group 1 (transfer committed)" {
		t.Fatalf("response = %q, want peer response untouched", resp.Message)
	}
}
