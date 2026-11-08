package cli

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #18559: the in-process CLI twin of pkg/grpcapi's
// untargeted_failover_18559_test.go. On the owner of a data RG with a live
// peer, `request chassis cluster failover redundancy-group N` runs the
// make-before-break transfer to the peer instead of the local resign, under
// the same outcome rules. The *RealPath* cells dial a real in-process peer on
// 127.0.0.1 and need a usable loopback.

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
	var mgr *cluster.Manager
	c, m := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		forwarded = append(forwarded, req.Action)
		mgr.SetGroupStateForTesting(1, cluster.StateSecondary) // the transfer's fence
		return "Manual failover completed for redundancy group 1 (transfer committed)", nil
	})
	mgr = m
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
}

// A peer that is not takeover-ready refuses; the owner keeps the RG and the
// operator sees the peer's readiness reasons, as the peer's, with a next
// step. RED before #18559.
func TestCLIUntargetedFailoverPeerNotReadyRefusesWithoutDemoting18559(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "", status.Error(codes.FailedPrecondition,
			"local redundancy group 1 not ready for explicit failover ready=false ready_since=<zero> reasons=[session sync not primed]")
	})
	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want the peer's FailedPrecondition refusal", err)
	}
	for _, want := range []string{"the peer's redundancy group 1 not ready for explicit failover",
		"reasons=[session sync not primed]", "no local resign", "Next:", "safe only once node 1 shows Takeover ready"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner demoted although the peer refused the transfer")
	}
}

// No fabric address configured: the request provably never reached the peer,
// so the CLI falls back to the local resign, with the fallback text.
func TestCLIUntargetedFailoverDialFailureFallsBackToLocalResign18559(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, nil) // no seam, no fabric address: dialPeerReached returns nil, false
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	})
	if callErr != nil {
		t.Fatalf("fallback returned %v", callErr)
	}
	if want := clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteUnreachable); mgr.IsLocalPrimary(1) || strings.TrimSpace(out) != want {
		t.Fatalf("local resign did not run: primary=%v stdout=%q want %q", mgr.IsLocalPrimary(1), out, want)
	}
}

// An unknown outcome (proxy deadline, RG not yet on the peer) must not be
// resigned on top of, and its #16432 text passes through verbatim. RED
// before #18559.
func TestCLIUntargetedFailoverUnknownOutcomeDoesNotResign18559(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		return "", status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	})
	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	if status.Code(err) != codes.Unknown {
		t.Fatalf("err = %v, want codes.Unknown", err)
	}
	const want = "Cluster failover outcome unknown for redundancy group 1: forwarded request to node 1 timed out; redundancy group 1 is not primary on node 1 — verify ownership before retrying"
	if got := status.Convert(err).Message(); got != want {
		t.Fatalf("unknown-outcome text = %q, want verbatim %q", got, want)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned on top of a transfer whose outcome is unknown")
	}
}

// RG0 and the non-owner keep the local resign and its unchanged text; nothing
// is proxied.
func TestCLIUntargetedFailoverStaysLocalResignOutsideOwnerDataRG18559(t *testing.T) {
	noProxy := func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		t.Errorf("unexpected peer transfer %q", req.Action)
		return "", status.Error(codes.Internal, "unexpected")
	}
	c, mgr := untargetedCLI18559(t, true, noProxy)
	out := captureStdout(t, func() {
		if err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "0"}); err != nil {
			t.Fatalf("RG0: %v", err)
		}
	})
	if mgr.IsLocalPrimary(0) || strings.TrimSpace(out) != "Manual failover triggered for redundancy group 0" {
		t.Fatalf("RG0 must keep the local resign and its text: primary=%v out=%q", mgr.IsLocalPrimary(0), out)
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

// The peer answers "already primary" (both nodes claim RG1): whatever this
// node's cached view of the peer, the transfer is attempted, and the reply
// while this node is still primary at the same epoch ends the dual-active
// state with the fenced local resign.
func TestCLIUntargetedFailoverDualActiveResignsLocally18559(t *testing.T) {
	for _, known := range []bool{false, true} {
		calls := 0
		c, mgr := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
			calls++
			return "Redundancy group 1 is already primary on node 1", nil
		})
		if known {
			mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
		}
		out := captureStdout(t, func() {
			if err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"}); err != nil {
				t.Fatalf("known=%v: %v", known, err)
			}
		})
		if mgr.IsLocalPrimary(1) {
			t.Fatalf("known=%v: dual-active not ended", known)
		}
		if want := clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteDualActive); strings.TrimSpace(out) != want {
			t.Fatalf("known=%v: stdout = %q, want %q", known, out, want)
		}
		if calls != 1 {
			t.Fatalf("known=%v: transfer attempts = %d, want 1", known, calls)
		}
	}
}

// A stale cached "peer is primary" view must not resign the sole owner: the
// transfer is attempted and the peer's refusal is returned (Codex F1).
func TestCLIUntargetedFailoverStalePeerPrimaryViewDoesNotResign18559(t *testing.T) {
	calls := 0
	c, mgr := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		calls++
		return "", status.Error(codes.FailedPrecondition,
			"local redundancy group 1 not ready for explicit failover ready=false ready_since=<zero> reasons=[]")
	})
	mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	if calls != 1 || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("calls=%d err=%v, want one attempt and the peer's refusal", calls, err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the sole owner resigned on a stale peer view")
	}
}

// A newer move made this node primary again before the transfer's success
// reply: nothing resigns and the supersession is reported (Codex F2).
func TestCLIUntargetedFailoverSupersededReplyDoesNotResign18559(t *testing.T) {
	var mgr *cluster.Manager
	c, m := untargetedCLI18559(t, true, func(ctx context.Context, req *pb.SystemActionRequest) (string, error) {
		mgr.SetGroupStateForTesting(1, cluster.StateSecondary)
		mgr.SetGroupStateForTesting(1, cluster.StatePrimary)
		return "Manual failover completed for redundancy group 1 (transfer committed)", nil
	})
	mgr = m
	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), "newer move") ||
		!strings.Contains(err.Error(), "node 1 had replied:") {
		t.Fatalf("err = %v, want Aborted naming the newer move and the peer's reply", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the delayed reply resigned the owner a newer move installed")
	}
}

// The never-reached fallback is fenced to the epoch: a newer move during the
// dial (here inside fabricPeerAddrFn, which then finds no address) must not be
// undone by the fallback resign.
func TestCLIUntargetedFailoverFallbackFencedToEpoch18559(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, nil)
	c.fabricPeerAddrFn = func() []string {
		mgr.SetGroupStateForTesting(1, cluster.StateSecondary)
		mgr.SetGroupStateForTesting(1, cluster.StatePrimary)
		return nil
	}
	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("err = %v, want Aborted: the epoch moved before the fallback", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the fallback resigned the owner a newer move installed")
	}
}

// ---- real fabric transport ----------------------------------------------

type realCLIPeer18559 struct {
	pb.UnimplementedBpfrxServiceServer
	err   error
	calls atomic.Int32
}

func (p *realCLIPeer18559) SystemAction(_ context.Context, _ *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
	p.calls.Add(1)
	return nil, p.err
}

func realPathCLI18559(t *testing.T, peer *realCLIPeer18559) (*CLI, *cluster.Manager) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(srv, peer)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	c, mgr := untargetedCLI18559(t, true, nil)
	c.fabricPeerAddrFn = func() []string { return []string{"127.0.0.1"} }
	c.fabricPeerPort = lis.Addr().(*net.TCPAddr).Port
	return c, mgr
}

// The RPC was issued and failed (a transport error, or the peer's fabric
// verifier rejecting the token under clock skew): it reached the peer, so the
// error is returned and nothing resigns. Drives the real SystemAction return
// (requestPeerSystemActionSent's post-RPC sent=true); the gRPC frontend gives
// the same peer the same outcome.
func TestCLIUntargetedFailoverRealPathRPCErrorDoesNotResign18559(t *testing.T) {
	for _, perr := range []error{
		status.Error(codes.Unavailable, "transport is closing"),
		status.Error(codes.Unauthenticated, "fabric RPC authentication failed: invalid auth token"),
	} {
		peer := &realCLIPeer18559{err: perr}
		c, mgr := realPathCLI18559(t, peer)
		var callErr error
		_ = captureStdout(t, func() {
			callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
		})
		if peer.calls.Load() != 1 {
			t.Fatalf("%v: peer SystemAction calls = %d, want 1", perr, peer.calls.Load())
		}
		if status.Code(callErr) != status.Code(perr) || !strings.Contains(callErr.Error(), "no local resign") {
			t.Fatalf("err = %v, want %v named as the transfer's", callErr, status.Code(perr))
		}
		if !mgr.IsLocalPrimary(1) {
			t.Fatalf("%v: the owner resigned on top of a request the peer received", perr)
		}
	}
}

// Nothing listens on the fabric port: transport absence, the real-transport
// fallback.
func TestCLIUntargetedFailoverRealPathNoListenerFallsBack18559(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	_ = lis.Close()
	c, mgr := untargetedCLI18559(t, true, nil)
	c.fabricPeerAddrFn = func() []string { return []string{"127.0.0.1"} }
	c.fabricPeerPort = port
	out := captureStdout(t, func() {
		if err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"}); err != nil {
			t.Fatalf("transport absence must fall back: %v", err)
		}
	})
	if mgr.IsLocalPrimary(1) || strings.TrimSpace(out) != clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteUnreachable) {
		t.Fatalf("fallback did not run: primary=%v out=%q", mgr.IsLocalPrimary(1), out)
	}
}
