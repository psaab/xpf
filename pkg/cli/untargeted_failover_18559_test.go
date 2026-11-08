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

// #18559: the in-process CLI twin of pkg/grpcapi's
// untargeted_failover_18559_test.go. On the owner of a data RG with a live
// peer, `request chassis cluster failover redundancy-group N` runs the
// make-before-break transfer to the peer instead of the local resign.

func untargetedCLI18559(t *testing.T, owner bool, peer func(ctx context.Context, req *pb.SystemActionRequest) (string, error)) (*CLI, *cluster.Manager) {
	t.Helper()
	mgr := cluster.NewManager(0, 1)
	mgr.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 0, NodePriorities: map[int]int{0: 100, 1: 90}},
		{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
	}})
	// UpdateConfig's single-node election makes the RGs primary; set both
	// roles explicitly.
	local, peerState := cluster.StateSecondary, cluster.StatePrimary
	if owner {
		local, peerState = cluster.StatePrimary, cluster.StateSecondary
	}
	mgr.SetGroupStateForTesting(0, local)
	mgr.SetGroupStateForTesting(1, local)
	mgr.SetPeerGroupStateForTesting(1, peerState)
	return &CLI{cluster: mgr, peerSystemActionFn: peer}, mgr
}

// RED before #18559: the CLI called ManualFailover and never asked the peer.
func TestCLIUntargetedFailoverOnOwnerRunsPeerTransfer18559(t *testing.T) {
	var forwarded []string
	c, mgr := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		forwarded = append(forwarded, req.Action)
		return "Manual failover completed for redundancy group 1 (transfer committed)", nil
	})
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	})
	if callErr != nil {
		t.Fatalf("untargeted failover on the owner: %v", callErr)
	}
	if len(forwarded) != 1 || forwarded[0] != "cluster-failover:1:node1" {
		t.Fatalf("forwarded to the peer = %q, want exactly [cluster-failover:1:node1]", forwarded)
	}
	if !strings.Contains(out, "transfer committed") {
		t.Fatalf("stdout = %q, want the peer's transfer result", out)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned locally instead of leaving the demotion to the transfer's fence")
	}
}

// A transfer the peer refused before sending anything leaves this node
// primary, so the CLI falls back to the pre-#18559 local resign.
// A peer that is not takeover-ready refuses; the owner keeps the RG and the
// operator sees the peer's readiness reasons. RED before #18559.
func TestCLIUntargetedFailoverPeerNotReadyRefusesWithoutDemoting18559(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "", status.Error(codes.FailedPrecondition,
			"local redundancy group 1 not ready for explicit failover ready=false ready_since=<zero> reasons=[session sync not primed]")
	})
	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want the peer's FailedPrecondition refusal", err)
	}
	for _, want := range []string{"not ready for explicit failover", "reasons=[session sync not primed]", "no local resign"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner demoted although the peer refused the transfer")
	}
}

// No fabric address answered the dial: the request provably never reached the
// peer, so the CLI falls back to the local resign.
func TestCLIUntargetedFailoverDialFailureFallsBackToLocalResign18559(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, nil) // no seam, no fabric address: dialPeer returns nil
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	})
	if callErr != nil {
		t.Fatalf("fallback returned %v", callErr)
	}
	if mgr.IsLocalPrimary(1) || !strings.Contains(out, "Manual failover triggered for redundancy group 1") {
		t.Fatalf("local resign did not run: primary=%v stdout=%q", mgr.IsLocalPrimary(1), out)
	}
}

// An unknown outcome (proxy deadline, RG not yet on the peer) must not be
// resigned on top of. RED before #18559.
func TestCLIUntargetedFailoverUnknownOutcomeDoesNotResign18559(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "", status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	})
	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	if status.Code(err) != codes.Unknown {
		t.Fatalf("err = %v, want codes.Unknown", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned on top of a transfer whose outcome is unknown")
	}
}

// RG0 and the non-owner keep the local resign; nothing is proxied.
func TestCLIUntargetedFailoverStaysLocalResignOutsideOwnerDataRG18559(t *testing.T) {
	noProxy := func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		t.Errorf("unexpected peer transfer %q", req.Action)
		return "", status.Error(codes.Internal, "unexpected")
	}
	c, mgr := untargetedCLI18559(t, true, noProxy)
	_ = captureStdout(t, func() {
		if err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "0"}); err != nil {
			t.Fatalf("RG0: %v", err)
		}
	})
	if mgr.IsLocalPrimary(0) {
		t.Fatal("RG0 must keep the local resign")
	}
	c2, _ := untargetedCLI18559(t, false, noProxy)
	_ = captureStdout(t, func() {
		if err := c2.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"}); err != nil {
			t.Fatalf("non-owner: %v", err)
		}
	})
}

// #18585 + #18559: the CLI checks the cross-node clock before the transfer;
// a refusal sends nothing and falls back to the local resign.
func TestCLIUntargetedFailoverClockRefusalFallsBackToLocalResign18559(t *testing.T) {
	calls := 0
	c, mgr := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		calls++
		return "Manual failover completed for redundancy group 1 (transfer committed)", nil
	})
	mgr.NotePeerWallClockForTesting(-72 * time.Second)
	var callErr error
	_ = captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	})
	if callErr != nil {
		t.Fatalf("clock-refused transfer must fall back: %v", callErr)
	}
	if calls != 0 || mgr.IsLocalPrimary(1) {
		t.Fatalf("calls=%d primary=%v, want no fabric RPC and the local resign", calls, mgr.IsLocalPrimary(1))
	}
}
