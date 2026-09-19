package grpcapi

import (
	"context"
	"net"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #8597 (muse-spark-review-004 K28): a peer that answers ResourceExhausted is
// ALIVE, and `dialPeer` must not record it as a failed connection.
//
// `dialPeer` uses `GetStatus` purely as a liveness probe. On the peer that RPC
// takes a `sessionWalkLimiter` slot and drives a full v4+v6 `SessionCount()`
// (#5782), so a peer already at scan capacity answers ResourceExhausted —
// and treating that as a dial failure reported a BUSY peer as an UNREACHABLE
// one. The operator then acts on "the fabric is down" when the fabric is fine.
//
// A ResourceExhausted reply is strictly STRONGER evidence of liveness than a
// success: the connection was accepted, the PSK authenticated, the #4122
// allowlist admitted the method, and the handler ran far enough to reach its own
// limiter. None of that happens on a dead peer.
//
// The cells drive the REAL `dialPeer` against a real in-process gRPC server on
// an ephemeral port. A cell calling an error-classification helper would pass
// against a `dialPeer` that had stopped consulting it, which is the shape this
// campaign has been caught by before.

type probeServer struct {
	pb.UnimplementedBpfrxServiceServer
	err error
}

func (p *probeServer) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &pb.GetStatusResponse{}, nil
}

// startProbePeer runs a gRPC server whose GetStatus returns err (or success for
// nil) and returns its host and port.
func startProbePeer(t *testing.T, err error) (host, port string) {
	t.Helper()
	lis, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	srv := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(srv, &probeServer{err: err})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	h, p, serr := net.SplitHostPort(lis.Addr().String())
	if serr != nil {
		t.Fatalf("split %q: %v", lis.Addr(), serr)
	}
	return h, p
}

func dialProbePeer(t *testing.T, probeErr error) (*grpc.ClientConn, error) {
	t.Helper()
	host, port := startProbePeer(t, probeErr)
	old := peerFabricGRPCPort
	peerFabricGRPCPort = port
	t.Cleanup(func() { peerFabricGRPCPort = old })

	s := &Server{fabricPeerAddrFn: func() []string { return []string{host} }}
	return s.dialPeer(context.Background())
}

func TestPeerAtScanCapacityIsReachable_8597(t *testing.T) {
	conn, err := dialProbePeer(t, status.Error(codes.ResourceExhausted,
		"session scan concurrency limit reached; retry shortly"))
	if err != nil {
		t.Fatalf("#8597: a peer answering ResourceExhausted is ALIVE — it accepted the "+
			"connection, authenticated, and ran the handler far enough to hit its own "+
			"limiter. Reporting it as unreachable sends the operator after a fabric fault "+
			"that does not exist. err = %v", err)
	}
	if conn == nil {
		t.Fatal("#8597: a reachable peer must yield a usable connection")
	}
	_ = conn.Close()
}

func TestPeerProbeControls_8597(t *testing.T) {
	// CONTROL 1: a healthy peer still connects. If this failed, the row above
	// would be measuring a dialPeer that accepts everything.
	conn, err := dialProbePeer(t, nil)
	if err != nil {
		t.Fatalf("a healthy peer must connect: %v", err)
	}
	_ = conn.Close()

	// CONTROL 2: a genuinely failing peer must STILL be reported as failed.
	// This is the row an over-broad fix breaks — treating every probe error as
	// liveness would satisfy the subject cell and hand out connections to dead
	// peers, which is worse than the defect.
	if _, err := dialProbePeer(t, status.Error(codes.Internal, "boom")); err == nil {
		t.Fatal("#8597: a peer failing the probe for any reason OTHER than scan capacity " +
			"must still be reported as unreachable")
	}
}
