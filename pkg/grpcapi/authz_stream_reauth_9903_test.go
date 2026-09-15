package grpcapi

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #9903 F-128 — STEP-0 repro: the revoked-before-herr ordering.
// The existing 9051 test's handler returns nil on ctx-done, so the revoked
// channel is always consulted. A production-shape handler (blocking
// Recv/Send, returning the ctx error — server_diag_monitor.go) returns
// Canceled/Unavailable INSTEAD of PermissionDenied pre-fix, by timing.

// TestRevokedStreamReportsPermissionDeniedDespiteHandlerCtxError demotes
// the principal mid-stream with a handler that returns its context error
// (the production shape). Pre-fix the handler's Canceled wins (RED);
// post-fix the consulted-first revocation wins (GREEN), deterministically.
func TestRevokedStreamReportsPermissionDeniedDespiteHandlerCtxError9903(t *testing.T) {
	usePasswdFixture5278(t)
	shortenStreamReauth9051(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278)})
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/MonitorInterface"

	entered := make(chan struct{})
	handler := func(_ any, stream grpc.ServerStream) error {
		close(entered)
		<-stream.Context().Done()
		return stream.Context().Err()
	}

	errc := make(chan error, 1)
	go func() {
		errc <- s.principalStreamInterceptor(nil,
			fakeServerStream9051{ctx: ctxWithPeerUID(authzUIDReadOnly)},
			&grpc.StreamServerInfo{FullMethod: full}, handler)
	}()

	select {
	case <-entered:
	case err := <-errc:
		t.Fatalf("the stream was refused at open, so nothing is being measured: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never ran")
	}

	revokeInStore9051(t, s)

	select {
	case err := <-errc:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a revoked stream must end with PermissionDenied even when the handler returns its ctx error, got %v (code %v)", err, status.Code(err))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stream outlived the revocation")
	}
}

// TestHandlerOnlyErrorIsPreserved9903 is the narrowness half: a handler
// failure with NO revocation must still return the handler's own error —
// the revoked-first reorder must not swallow genuine failures.
func TestHandlerOnlyErrorIsPreserved9903(t *testing.T) {
	usePasswdFixture5278(t)
	shortenStreamReauth9051(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278)})
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/MonitorInterface"

	want := errors.New("boom: genuine handler failure")
	handler := func(_ any, _ grpc.ServerStream) error { return want }

	err := s.principalStreamInterceptor(nil,
		fakeServerStream9051{ctx: ctxWithPeerUID(authzUIDReadOnly)},
		&grpc.StreamServerInfo{FullMethod: full}, handler)
	if !errors.Is(err, want) {
		t.Fatalf("a handler-only failure must return the handler error, got %v", err)
	}
}

// TestRevokedStreamReportsPermissionDenied9903 runs the demote regression
// five times: the send-before-cancel ordering makes revoked-first
// deterministic, not merely likely.
func TestRevokedStreamReportsPermissionDenied9903(t *testing.T) {
	for range 5 {
		TestRevokedStreamReportsPermissionDeniedDespiteHandlerCtxError9903(t)
	}
}
