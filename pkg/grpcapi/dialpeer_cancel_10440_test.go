package grpcapi

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #10440 (GEMINI-049-088): dialPeer must honor caller cancellation during its
// GetStatus liveness probes. Each probe previously ran under
// context.WithTimeout(context.Background(), 2*time.Second), so a canceled or
// short-deadline inbound request left its server goroutine probing for up to
// ~2s per fabric after the client was gone — and each probe consumes the
// peer's session-walk limiter slot plus a full v4/v6 session-table walk.
//
// The cells drive the REAL dialPeer against a real in-process gRPC peer whose
// GetStatus blocks until its context ends and counts entries. A cell calling a
// helper (or asserting on a timeout the production path never consults) would
// pass against a dialPeer that still probes under Background.

// blockingPeer10440 is a fake peer whose GetStatus never answers on its own:
// it records the entry and waits for the RPC context to end. Against a
// dialPeer that ignores caller cancellation the probe therefore runs to the
// full 2s probe budget per fabric address; against the fixed one it never runs
// at all (canceled caller) or ends at the caller deadline.
type blockingPeer10440 struct {
	pb.UnimplementedBpfrxServiceServer
	entered atomic.Int64
}

func (p *blockingPeer10440) GetStatus(ctx context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	p.entered.Add(1)
	select {
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	case <-time.After(30 * time.Second):
		return &pb.GetStatusResponse{}, nil
	}
}

// startBlockingPeer10440 serves a blockingPeer10440 on an ephemeral port and
// points dialPeer at it via peerFabricGRPCPort (same seam as the #8597 cells).
func startBlockingPeer10440(t *testing.T) (host string, entered *atomic.Int64) {
	t.Helper()
	peer := &blockingPeer10440{}
	lis, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	srv := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(srv, peer)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	h, p, serr := net.SplitHostPort(lis.Addr().String())
	if serr != nil {
		t.Fatalf("split %q: %v", lis.Addr(), serr)
	}
	old := peerFabricGRPCPort
	peerFabricGRPCPort = p
	t.Cleanup(func() { peerFabricGRPCPort = old })
	return h, &peer.entered
}

// Canceled callers must abort fast with no probe and no per-fabric wait. Two
// fabric addresses bound the stacking directly: an ignoring dialPeer spends
// ~2s on EACH (4s total) and enters the peer twice; the fixed one returns
// before any probe. The 1s bound is ~1000x headroom over the fixed path
// (microseconds, no I/O) and 2-4x inside the broken one.
func TestDialPeerCanceledContextAbortsFast_10440(t *testing.T) {
	host, entered := startBlockingPeer10440(t)
	s := &Server{fabricPeerAddrFn: func() []string { return []string{host, host} }}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	conn, err := s.dialPeer(ctx)
	elapsed := time.Since(start)

	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("#10440: dialPeer with an already-canceled context must fail, got a connection after %v", elapsed)
	}
	if got := status.Code(err); got != codes.Canceled {
		t.Errorf("#10440: canceled caller must surface Canceled, got %v (%v)", got, err)
	}
	if elapsed >= time.Second {
		t.Errorf("#10440: canceled caller waited %v for probes that must not run (budget: <1s)", elapsed)
	}
	if n := entered.Load(); n != 0 {
		t.Errorf("#10440: canceled caller drove %d peer probe(s); no GetStatus may run after cancel", n)
	}
}

// A short caller deadline must bind the probe: the wait ends at the caller
// deadline with DeadlineExceeded, not at the 2s probe budget.
func TestDialPeerDeadlinePropagation_10440(t *testing.T) {
	host, entered := startBlockingPeer10440(t)
	s := &Server{fabricPeerAddrFn: func() []string { return []string{host} }}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := s.dialPeer(ctx)
	elapsed := time.Since(start)
	if conn != nil {
		_ = conn.Close()
	}

	if err == nil {
		t.Fatalf("#10440: dialPeer past the caller deadline must fail, got a connection after %v", elapsed)
	}
	if got := status.Code(err); got != codes.DeadlineExceeded {
		t.Errorf("#10440: expired caller deadline must surface DeadlineExceeded, got %v (%v)", got, err)
	}
	if elapsed >= time.Second {
		t.Errorf("#10440: 250ms caller deadline waited %v (the 2s probe budget ran instead)", elapsed)
	}
	if n := entered.Load(); n > 1 {
		t.Errorf("#10440: deadline probe entered the peer %d times; only one fabric probe may start before cancellation", n)
	}
}

// CONTROL: threading the caller context must not change the healthy path — a
// live peer with a live context still connects.
func TestDialPeerNormalProbeUnaffected_10440(t *testing.T) {
	conn, err := dialProbePeer(t, nil)
	if err != nil {
		t.Fatalf("#10440 control: a healthy peer must still connect: %v", err)
	}
	if conn == nil {
		t.Fatal("#10440 control: a reachable peer must yield a usable connection")
	}
	_ = conn.Close()
}
