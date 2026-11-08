package grpcapi

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

// #18559: `request chassis cluster failover redundancy-group N` run on the
// OWNER of a data RG used to be Manager.ManualFailover: the owner demoted at
// once and the peer promoted on its next heartbeat, so everything the owner
// fabric-redirected in between died on the peer's HA-inactive gate (H1's
// planned moves, 71-336 ms on loss). It now runs the node-targeted,
// make-before-break transfer to the peer. The remote CLI (`cli -c`) reaches
// this handler, so these cells drive SystemAction itself.
//
// The cells named *RealPath* drive the REAL fabric dial and SystemAction RPC
// against an in-process gRPC peer on 127.0.0.1 (the #8597/#10440 seam,
// peerFabricGRPCPort); they need a usable loopback, so run them outside the
// lo-down testguard namespace.

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
	var mgr *cluster.Manager
	s, m := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		forwarded = append(forwarded, req.Action)
		// The committed transfer demoted this node through its #5640 fence.
		mgr.SetGroupStateForTesting(1, cluster.StateSecondary)
		return &pb.SystemActionResponse{Message: untargetedTransferOK18559}, nil
	})
	mgr = m
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
	if got := failoverCount18559(mgr, 1); got != 0 {
		t.Fatalf("FailoverCount = %d: the owner ran a local resign on top of the committed transfer", got)
	}
}

// notReady18559 is the refusal RequestPeerFailover returns on a peer that is
// not takeover-ready, as the peer's gRPC handler wraps it.
var notReady18559 = status.Error(codes.FailedPrecondition,
	"local redundancy group 1 not ready for explicit failover ready=false ready_since=<zero> reasons=[session sync not primed]")

// A peer that is not takeover-ready refuses before it sends anything. The
// owner must NOT resign into it: demoting to a peer that will not promote
// strands the RG (#18731 class). The refusal reaches the operator with the
// peer's readiness reasons, worded as the PEER's group, and a next step. RED
// before #18559: the handler resigned and reported "triggered".
func TestUntargetedFailoverPeerNotReadyRefusesWithoutDemoting18559(t *testing.T) {
	calls := 0
	s, mgr := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		calls++
		return nil, notReady18559
	})
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want the peer's FailedPrecondition refusal", err)
	}
	for _, want := range []string{"the peer's redundancy group 1 not ready for explicit failover",
		"reasons=[session sync not primed]", "node 1", "no local resign", "Next:",
		"safe only once node 1 shows Takeover ready"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}
	if calls != 1 {
		t.Fatalf("transfer attempts = %d, want 1", calls)
	}
	if !mgr.IsLocalPrimary(1) || failoverCount18559(mgr, 1) != 0 {
		t.Fatal("the owner demoted although the peer refused the transfer")
	}
}

// A request that provably never reached the peer (no fabric address
// configured) falls back to the pre-#18559 local resign, with a reply that
// says so.
func TestUntargetedFailoverDialFailureFallsBackToLocalResign18559(t *testing.T) {
	s, mgr := untargetedServer18559(t, true, true, nil) // no seam: the real dialPeer runs and finds no fabric address
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if err != nil {
		t.Fatalf("a transfer that never reached the peer must fall back to the local resign: %v", err)
	}
	if want := clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteUnreachable); resp.GetMessage() != want {
		t.Fatalf("message = %q, want the distinguishable fallback text %q", resp.GetMessage(), want)
	}
	if mgr.IsLocalPrimary(1) {
		t.Fatal("local resign did not run after the dial failure")
	}
}

// unknown18559 is the #16432 verify-before-retry text the deadline
// reconciliation returns when node1 does not own RG1 afterwards.
const unknown18559 = "Cluster failover outcome unknown for redundancy group 1: forwarded request to node 1 timed out; redundancy group 1 is not primary on node 1 — verify ownership before retrying"

// A transfer whose outcome is unknown (the proxy deadline reconciled with the
// RG not yet on the peer) may still commit, so the owner must not resign on
// top of it, and the #16432 verify-before-retry text passes through verbatim.
// RED before #18559: the handler resigned and reported success.
func TestUntargetedFailoverUnknownOutcomeDoesNotResign18559(t *testing.T) {
	s, mgr := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	})
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.Unknown {
		t.Fatalf("err = %v, want codes.Unknown (outcome unknown, verify before retrying)", err)
	}
	if got := status.Convert(err).Message(); got != unknown18559 {
		t.Fatalf("unknown-outcome text = %q, want the #16432 text verbatim %q", got, unknown18559)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned on top of a transfer whose outcome is unknown")
	}
}

// The untargeted form keeps its local-resign meaning where there is nothing
// to make before the break: RG0, a node that does not own the RG, a dead peer,
// and a request the peer forwarded to us (never re-proxied). Each replies the
// unchanged pre-#18559 text.
func TestUntargetedFailoverStaysLocalResignOutsideOwnerDataRG18559(t *testing.T) {
	noProxy := func(t *testing.T) func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
			t.Errorf("unexpected peer transfer %q", req.Action)
			return nil, status.Error(codes.Internal, "unexpected")
		}
	}
	t.Run("RG0 on the owner", func(t *testing.T) {
		s, mgr := untargetedServer18559(t, true, true, noProxy(t))
		resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:0"})
		if err != nil {
			t.Fatalf("RG0 untargeted failover: %v", err)
		}
		if mgr.IsLocalPrimary(0) || resp.GetMessage() != "Manual failover triggered for redundancy group 0" {
			t.Fatalf("RG0 must keep the local resign and its text: primary=%v msg=%q", mgr.IsLocalPrimary(0), resp.GetMessage())
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
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if err != nil {
		t.Fatalf("clock-refused transfer must fall back to the local resign: %v", err)
	}
	if calls != 0 {
		t.Fatalf("a clock-refused transfer must not reach the fabric; calls=%d", calls)
	}
	if mgr.IsLocalPrimary(1) || resp.GetMessage() != clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteUnreachable) {
		t.Fatalf("local resign did not run after the clock refusal: primary=%v msg=%q", mgr.IsLocalPrimary(1), resp.GetMessage())
	}
}

// A caller that cancelled before the outcome was known gets its context
// error, and nothing resigns: it cannot observe an ownership change.
func TestUntargetedFailoverCanceledCallerDoesNotResign18559(t *testing.T) {
	s, mgr := untargetedServer18559(t, true, true, nil)
	s.fabricPeerAddrFn = func() []string { return []string{"127.0.0.1"} }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.SystemAction(ctx, &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.Canceled {
		t.Fatalf("err = %v, want the caller's Canceled", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("a cancelled request still resigned the owner")
	}
}

// ---- dual-active, stale views and superseded replies ---------------------

// twoNode18559 builds node0 (owner of RG1) and node1, with node0's peer seam
// calling node1's REAL SystemAction handler as the fabric interceptor would
// (forwarded marker). node1Primary is node1's ACTUAL role; node0Sees is
// node0's cached (heartbeat) view of node1's role.
func twoNode18559(t *testing.T, node1Primary bool, node0Sees cluster.NodeState) (*Server, *cluster.Manager, *cluster.Manager, *atomic.Int32) {
	t.Helper()
	n1 := cluster.NewManager(1, 22)
	n1.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 0, NodePriorities: map[int]int{0: 100, 1: 90}},
		{ID: 1, NodePriorities: map[int]int{0: 100, 1: 90}},
	}})
	role := cluster.StateSecondary
	if node1Primary {
		role = cluster.StatePrimary
	}
	n1.SetGroupStateForTesting(0, cluster.StateSecondary)
	n1.SetGroupStateForTesting(1, role)
	n1.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
	node1 := &Server{cluster: n1}
	calls := &atomic.Int32{}
	s, n0 := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		calls.Add(1)
		return node1.SystemAction(withPeerMarkers(context.Background(), peerMarkers{forwarded: true}), req)
	})
	n0.SetPeerGroupStateForTesting(1, node0Sees)
	return s, n0, n1, calls
}

// Both nodes really primary. Whether node0's cached view already shows it or
// not, the transfer is attempted, node1's REAL handler answers "already
// primary", and node0 resigns (fenced to its unchanged epoch): the
// dual-active state ends from the CLI.
func TestUntargetedFailoverDualActiveResignsLocally18559(t *testing.T) {
	for _, sees := range []cluster.NodeState{cluster.StatePrimary, cluster.StateSecondary} {
		s, n0, n1, calls := twoNode18559(t, true, sees)
		resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
		if err != nil {
			t.Fatalf("view %v: dual-active untargeted failover: %v", sees, err)
		}
		if calls.Load() != 1 {
			t.Fatalf("view %v: transfer attempts = %d, want 1 (the decision rests on the peer's answer)", sees, calls.Load())
		}
		if n0.IsLocalPrimary(1) || !n1.IsLocalPrimary(1) {
			t.Fatalf("view %v: dual-active not ended: node0 primary=%v node1 primary=%v", sees, n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
		}
		if want := clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteDualActive); resp.GetMessage() != want {
			t.Fatalf("view %v: message = %q, want %q", sees, resp.GetMessage(), want)
		}
	}
}

// node0's cached view says node1 is primary, but node1 is actually secondary
// (it lost a dual-active election and its next heartbeat has not arrived).
// The transfer must still be attempted; node1's REAL handler cannot complete
// it here (no session sync) and refuses, so node0 — the sole owner — must stay
// primary. Before cycle 2 the cached view alone resigned node0 (Codex F1).
func TestUntargetedFailoverStalePeerPrimaryViewDoesNotResign18559(t *testing.T) {
	s, n0, n1, calls := twoNode18559(t, false, cluster.StatePrimary)
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if calls.Load() != 1 {
		t.Fatalf("transfer attempts = %d, want 1", calls.Load())
	}
	if err == nil || !strings.Contains(err.Error(), "no local resign") {
		t.Fatalf("err = %v, want node1's refusal returned as the transfer's", err)
	}
	if !n0.IsLocalPrimary(1) || n1.IsLocalPrimary(1) || failoverCount18559(n0, 1) != 0 {
		t.Fatalf("the sole owner resigned on a stale peer view: node0 primary=%v node1 primary=%v", n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
	}
}

// The transfer committed (node0 demoted) and a NEWER move made node0 primary
// again before the first transfer's success reply arrived: the newer owner
// stands, nothing resigns, and the supersession is reported (Codex F2).
func TestUntargetedFailoverSupersededReplyDoesNotResign18559(t *testing.T) {
	var mgr *cluster.Manager
	s, m := untargetedServer18559(t, true, true, func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		mgr.SetGroupStateForTesting(1, cluster.StateSecondary) // the transfer's fence
		mgr.SetGroupStateForTesting(1, cluster.StatePrimary)   // a newer move back
		return &pb.SystemActionResponse{Message: untargetedTransferOK18559}, nil
	})
	mgr = m
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), "newer move") ||
		!strings.Contains(err.Error(), "node 1 had replied: "+untargetedTransferOK18559) {
		t.Fatalf("err = %v, want Aborted naming the newer move and the peer's reply", err)
	}
	if !mgr.IsLocalPrimary(1) || failoverCount18559(mgr, 1) != 0 {
		t.Fatal("the delayed reply resigned the owner a newer move installed")
	}
}

// The never-reached fallback is fenced too: if this node lost and regained
// the RG while the dial ran (a newer move), the fallback must not resign the
// newer owner. The epoch flips inside the dial (fabricPeerAddrFn), which then
// finds no address.
func TestUntargetedFailoverFallbackFencedToEpoch18559(t *testing.T) {
	s, mgr := untargetedServer18559(t, true, true, nil)
	s.fabricPeerAddrFn = func() []string {
		mgr.SetGroupStateForTesting(1, cluster.StateSecondary)
		mgr.SetGroupStateForTesting(1, cluster.StatePrimary)
		return nil
	}
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("err = %v, want Aborted: the epoch moved before the fallback", err)
	}
	if !mgr.IsLocalPrimary(1) || failoverCount18559(mgr, 1) != 0 {
		t.Fatal("the fallback resigned the owner a newer move installed")
	}
}

// The caller cancels while the peer answers "already primary": the
// dual-active post-check must not resign for a caller that is gone (Codex F3).
func TestUntargetedFailoverCanceledCallerDualActiveDoesNotResign18559(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, mgr := untargetedServer18559(t, true, true, func(context.Context, *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		cancel()
		return &pb.SystemActionResponse{Message: "Redundancy group 1 is already primary on node 1"}, nil
	})
	_, err := s.SystemAction(ctx, &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.Canceled {
		t.Fatalf("err = %v, want the caller's Canceled", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("a cancelled caller still got the dual-active resign")
	}
}

// ---- real fabric transport ----------------------------------------------

// realPeer18559 is an in-process fabric peer. probe is GetStatus's answer
// (nil = OK), probeDelay delays it, action runs inside SystemAction.
type realPeer18559 struct {
	pb.UnimplementedBpfrxServiceServer
	probe      error
	probeDelay time.Duration
	// probeSeq, when set, answers the nth probe with probeSeq[n] (the last
	// entry repeats): one listener answering two fabric addresses
	// differently.
	probeSeq []error
	probes   atomic.Int32
	action   func(*pb.SystemActionRequest) (*pb.SystemActionResponse, error)
	calls    atomic.Int32
}

func (p *realPeer18559) GetStatus(ctx context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	if p.probeDelay > 0 {
		select {
		case <-time.After(p.probeDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if n := int(p.probes.Add(1)) - 1; len(p.probeSeq) > 0 {
		return nil, p.probeSeq[min(n, len(p.probeSeq)-1)]
	}
	if p.probe != nil {
		return nil, p.probe
	}
	return &pb.GetStatusResponse{}, nil
}

func (p *realPeer18559) SystemAction(_ context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
	p.calls.Add(1)
	return p.action(req)
}

// realPathServer18559 starts peer on an ephemeral loopback port, points
// dialPeer at it and returns node0 (owner, RG1, live peer) with NO seam.
func realPathServer18559(t *testing.T, peer *realPeer18559) (*Server, *cluster.Manager) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(srv, peer)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	old := peerFabricGRPCPort
	peerFabricGRPCPort = port
	t.Cleanup(func() { peerFabricGRPCPort = old })
	s, mgr := untargetedServer18559(t, true, true, nil)
	s.fabricPeerAddrFn = func() []string { return []string{"127.0.0.1"} }
	return s, mgr
}

// The RPC was issued and the peer failed it: it may have been delivered, so
// the error is returned and nothing resigns on top of it. Drives the real
// SystemAction return (proxyPeerSystemActionSent's post-RPC sent=true).
func TestUntargetedFailoverRealPathRPCErrorAfterDialDoesNotResign18559(t *testing.T) {
	peer := &realPeer18559{action: func(*pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.Unavailable, "transport is closing")
	}}
	s, mgr := realPathServer18559(t, peer)
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if peer.calls.Load() != 1 {
		t.Fatalf("peer SystemAction calls = %d, want 1", peer.calls.Load())
	}
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "no local resign") {
		t.Fatalf("err = %v, want the post-dial Unavailable, named as the transfer's", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned on top of a request the peer received")
	}
}

// The peer reports a deadline: reconciled to an unknown outcome, returned
// verbatim, no resign. Real transport.
func TestUntargetedFailoverRealPathUnknownOutcomeDoesNotResign18559(t *testing.T) {
	peer := &realPeer18559{action: func(*pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		return nil, status.Error(codes.DeadlineExceeded, "failover ACK timeout")
	}}
	s, mgr := realPathServer18559(t, peer)
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.Unknown || status.Convert(err).Message() != unknown18559 {
		t.Fatalf("err = %v, want codes.Unknown with the #16432 text verbatim", err)
	}
	if !mgr.IsLocalPrimary(1) {
		t.Fatal("the owner resigned on top of an unknown outcome")
	}
}

// The transfer demoted this node at its applied-ACK and then failed: its
// abort or the #5079 lease restores the node, so nothing resigns on top of
// it. Real transport.
func TestUntargetedFailoverRealPathAfterOwnerAckDoesNotResign18559(t *testing.T) {
	var mgr *cluster.Manager
	peer := &realPeer18559{action: func(*pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		mgr.SetGroupStateForTesting(1, cluster.StateSecondaryHold)
		return nil, status.Error(codes.FailedPrecondition, "failover commit for redundancy group 1 failed")
	}}
	s, m := realPathServer18559(t, peer)
	mgr = m
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want the transfer's FailedPrecondition", err)
	}
	if got := failoverCount18559(mgr, 1); got != 0 {
		t.Fatalf("FailoverCount = %d: a local resign ran on top of a transfer that had already demoted this node", got)
	}
}

// A peer that ACCEPTED the connection and then failed the authenticated
// GetStatus probe was reached, whatever the probe said: an Unauthenticated
// fabric token (clock skew under the #18585 60 s refusal), or a probe slower
// than its 2 s. The error is returned and nothing resigns — the same outcome
// the in-process CLI gives the same peer.
func TestUntargetedFailoverRealPathProbeAnsweredIsReached18559(t *testing.T) {
	for _, tc := range []struct {
		name     string
		peer     *realPeer18559
		addrs    []string
		wantCode codes.Code
		wantText string
	}{
		// The peer's own status survives (the CLI twin returns the same code).
		{"probe Unauthenticated", &realPeer18559{probe: status.Error(codes.Unauthenticated,
			"fabric RPC authentication failed: invalid auth token")}, []string{"127.0.0.1"},
			codes.Unauthenticated, "chronyc tracking"},
		// A later address that refuses TCP must not overwrite it.
		{"probe Unauthenticated, then a refused address", &realPeer18559{probe: status.Error(codes.Unauthenticated,
			"fabric RPC authentication failed: invalid auth token")}, []string{"127.0.0.1", "127.0.0.2"},
			codes.Unauthenticated, "chronyc tracking"},
		// Two addresses that both answer: the FIRST answer is returned, not
		// overwritten by the second (one listener, two probe replies).
		{"two answering addresses keep the first", &realPeer18559{probeSeq: []error{
			status.Error(codes.Unauthenticated, "fabric RPC authentication failed: invalid auth token"),
			status.Error(codes.PermissionDenied, "fabric RPC not allowed for this peer"),
		}}, []string{"127.0.0.1", "127.0.0.1"}, codes.Unauthenticated, "invalid auth token"},
		// A probe that timed out after the connect is reached, not an answer.
		{"probe slower than 2 s", &realPeer18559{probeDelay: 3 * time.Second}, []string{"127.0.0.1"},
			codes.Unavailable, "fabric path to node 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.peer.action = func(*pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
				return &pb.SystemActionResponse{Message: untargetedTransferOK18559}, nil
			}
			s, mgr := realPathServer18559(t, tc.peer)
			s.fabricPeerAddrFn = func() []string { return tc.addrs }
			_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
			if status.Code(err) != tc.wantCode || !strings.Contains(err.Error(), "no local resign") ||
				!strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("err = %v, want %v naming %q, returned as the transfer's", err, tc.wantCode, tc.wantText)
			}
			if !mgr.IsLocalPrimary(1) {
				t.Fatal("the owner fell back to the local resign although the peer accepted the connection")
			}
		})
	}
}

// No fabric address accepts a connection (nothing listens): transport
// absence, the only real-transport fallback.
func TestUntargetedFailoverRealPathNoListenerFallsBack18559(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	_ = lis.Close()
	old := peerFabricGRPCPort
	peerFabricGRPCPort = port
	t.Cleanup(func() { peerFabricGRPCPort = old })
	s, mgr := untargetedServer18559(t, true, true, nil)
	s.fabricPeerAddrFn = func() []string { return []string{"127.0.0.1"} }
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if err != nil {
		t.Fatalf("transport absence must fall back: %v", err)
	}
	if resp.GetMessage() != clusterfailover.LocalResignMessage(1, clusterfailover.ResignNoteUnreachable) || mgr.IsLocalPrimary(1) {
		t.Fatalf("fallback did not run: msg=%q primary=%v", resp.GetMessage(), mgr.IsLocalPrimary(1))
	}
}
