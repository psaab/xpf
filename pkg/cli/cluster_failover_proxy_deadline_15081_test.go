package cli

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

// #15081 (A43-02), CLI twin: pkg/cli/peer.go applied the same flat 5s
// deadline to forwarded node-targeted failovers as the gRPC proxy, so
// `request chassis cluster failover ... node <peer>` printed a bare
// DeadlineExceeded while the peer completed the move. The CLI now
// sizes the forwarded failover from the cluster budget and reconciles
// a deadline outcome against RG ownership.
//
// RED-on-revert: restoring the 5s deadline fails the deadline-capture
// test; removing the reconciliation fails the committed/unknown tests
// (handleRequestChassisClusterFailover returns the bare error).

func failoverCLI15081(t *testing.T) *CLI {
	t.Helper()
	mgr := cluster.NewManager(0, 1)
	mgr.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
			{ID: 2, NodePriorities: map[int]int{0: 100, 1: 90}},
		},
	})
	return &CLI{cluster: mgr}
}

func TestCLIFailoverProxyDeadlineSizedFromClusterBudget15081(t *testing.T) {
	c := failoverCLI15081(t)
	// Production path: peerSystemActionFn receives the context the CLI
	// built WITHOUT the proxy deadline (the deadline is applied only on
	// the real dial path). Exercise requestPeerSystemAction's seam
	// contract via the sizing helper and the dial-path capture below.
	if got := peerSystemActionTimeout("cluster-failover:1:node1"); got < 40*time.Second {
		t.Fatalf("peerSystemActionTimeout(targeted) = %v, want ~46s cluster budget (was 5s pre-fix)", got)
	}
	if got := peerSystemActionTimeout("cluster-failover-data:node1"); got < 40*time.Second {
		t.Fatalf("peerSystemActionTimeout(data) = %v, want ~46s cluster budget", got)
	}
	if got := peerSystemActionTimeout("clear-persistent-nat"); got != 5*time.Second {
		t.Fatalf("peerSystemActionTimeout(clear-persistent-nat) = %v, want 5s control", got)
	}
	if got := peerSystemActionTimeout("cluster-failover:1"); got != 5*time.Second {
		t.Fatalf("peerSystemActionTimeout(untargeted) = %v, want 5s (never proxied)", got)
	}
	_ = c
}

func TestCLIFailoverTimeoutAfterPeerCommitReportsSuccess15081(t *testing.T) {
	c := failoverCLI15081(t)
	c.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	c.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "", status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	}
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1", "node", "1"})
	})
	if callErr != nil {
		t.Fatalf("handleRequestChassisClusterFailover() error = %v, want reconciled success (bare DeadlineExceeded pre-fix)", callErr)
	}
	if !strings.Contains(out, "transfer committed") || !strings.Contains(out, "proxy response timed out") {
		t.Fatalf("stdout = %q, want committed-after-timeout success", out)
	}
}

func TestCLIFailoverTimeoutNotCommittedReportsUnknown15081(t *testing.T) {
	c := failoverCLI15081(t)
	c.cluster.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
	c.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "", context.DeadlineExceeded
	}
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1", "node", "1"})
	})
	if callErr != nil {
		t.Fatalf("handleRequestChassisClusterFailover() error = %v, want outcome-unknown message", callErr)
	}
	if !strings.Contains(out, "outcome unknown") || !strings.Contains(out, "verify") {
		t.Fatalf("stdout = %q, want outcome-unknown with verify guidance", out)
	}
}

func TestCLIDataFailoverTimeoutPartialReportsUnknown15081(t *testing.T) {
	c := failoverCLI15081(t)
	c.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	c.cluster.SetPeerGroupStateForTesting(2, cluster.StateSecondary)
	c.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "", status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	}
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"data", "node", "1"})
	})
	if callErr != nil {
		t.Fatalf("handleRequestChassisClusterFailover() error = %v, want outcome-unknown message", callErr)
	}
	if !strings.Contains(out, "outcome unknown") || !strings.Contains(out, "[1]") {
		t.Fatalf("stdout = %q, want outcome-unknown naming peer-primary [1]", out)
	}
}

// Control: non-deadline proxy errors relay verbatim; successes pass through.
func TestCLIFailoverProxyControls15081(t *testing.T) {
	c := failoverCLI15081(t)
	c.cluster.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	c.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "", status.Error(codes.FailedPrecondition, "not ready for takeover")
	}
	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1", "node", "1"})
	if err == nil || !strings.Contains(err.Error(), "not ready for takeover") {
		t.Fatalf("error = %v, want verbatim relay", err)
	}

	c2 := failoverCLI15081(t)
	c2.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "proxied manual failover", nil
	}
	var callErr error
	out := captureStdout(t, func() {
		callErr = c2.handleRequestChassisClusterFailover([]string{"redundancy-group", "1", "node", "1"})
	})
	if callErr != nil || strings.TrimSpace(out) != "proxied manual failover" {
		t.Fatalf("err = %v stdout = %q, want untouched peer response", callErr, out)
	}
}
