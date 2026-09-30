package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var streamArgsTestKey11082 = []byte("0123456789abcdef0123456789abcdef")

func mintStreamArgsToken11082(t *testing.T, method string, req *pb.MonitorInterfaceRequest) string {
	t.Helper()
	digest, err := fabricRequestDigest(req)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	tok := fabricAuthTokenHexForDigest(streamArgsTestKey11082, time.Now(), method, digest)
	if tok == "" {
		t.Fatal("mint produced empty token")
	}
	return tok
}

func TestVerifyFabricStreamArgsToken11082(t *testing.T) {
	const method = "/xpf.v1.BpfrxService/MonitorInterface"
	reqA := &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/0"}
	reqB := &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/1"}
	tok := mintStreamArgsToken11082(t, method, reqA)
	keys := [][]byte{streamArgsTestKey11082}
	if !verifyFabricStreamArgsToken(keys, tok, method, reqA) {
		t.Fatal("args-bound token must verify against the minted request")
	}
	if verifyFabricStreamArgsToken(keys, tok, method, reqB) {
		t.Fatal("token minted for ge-0/0/0 must NOT verify for ge-0/0/1 (replay with different args)")
	}
	if verifyFabricStreamArgsToken([][]byte{[]byte("ffffffffffffffffffffffffffffffff")}, tok, method, reqA) {
		t.Fatal("token must not verify under the wrong key")
	}
}

// TestMonitorInterfaceArgsBinding11082 drives the handler: a token minted
// for THESE args passes auth; the same token against different args is
// Unauthenticated; no token takes the counted legacy fallback.
func TestMonitorInterfaceArgsBinding11082(t *testing.T) {
	const method = "/xpf.v1.BpfrxService/MonitorInterface"
	run := func(req *pb.MonitorInterfaceRequest, tok string) error {
		s := monitorBudgetStore9891(t)
		s.fabricAuthKeyFn = func() []byte { return streamArgsTestKey11082 }
		md := metadata.MD{}
		if tok != "" {
			md.Set(fabricAuthArgsBoundKey, tok)
		}
		ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), md))
		defer cancel()
		errc := make(chan error, 1)
		go func() {
			errc <- s.MonitorInterface(req, &capMonitorStream9891{ctx: ctx, cancel: cancel})
		}()
		select {
		case err := <-errc:
			return err
		case <-time.After(5 * time.Second):
			cancel()
			<-errc
			// Accepted streams run until cancelled; reaching the timeout
			// with no auth error IS the accept signal.
			return nil
		}
	}

	// Matching args: must NOT fail authentication.
	reqA := &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/0"}
	if err := run(reqA, mintStreamArgsToken11082(t, method, reqA)); err != nil && status.Code(err) == codes.Unauthenticated {
		t.Fatalf("matching args token rejected: %v", err)
	}

	// Mismatched args: the captured-token replay this issue closes.
	reqB := &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/1"}
	if err := run(reqB, mintStreamArgsToken11082(t, method, reqA)); err == nil || status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replayed token with different args must be Unauthenticated, got: %v", err)
	}

	// Legacy: no args token passes the handler (method token checked by the
	// interceptor, not here) and counts the fallback.
	before := FabricStreamArgsUnboundTotal()
	if err := run(reqA, ""); err != nil && status.Code(err) == codes.Unauthenticated {
		t.Fatalf("legacy method-only stream must not be rejected by the handler: %v", err)
	}
	if got := FabricStreamArgsUnboundTotal(); got != before+1 {
		t.Fatalf("fallback counter = %d, want %d", got, before+1)
	}
}
