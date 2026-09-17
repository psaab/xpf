package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #4589 A8-01: the Rollback MUTATION RPC had no n<0 guard, so a negative n
// flowed into store.Rollback(n) → history.Get(n-1) → history.Get(<0) → the
// opaque "history position -1 out of range" store error. Reject it up front
// with a clear message. Unlike ShowRollback (#4556, which rejects n<=0), the
// mutation keeps n==0 valid (Junos `rollback 0` = revert to active), so only
// n<0 is rejected.
//
// RED-on-revert: dropping the n<0 guard returns the store's out-of-range
// error (still InvalidArgument, but the confusing "out of range" message and
// no guard on the raw wire value).
func TestRollbackRejectsNegativeN(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	s := &Server{store: store}
	for _, n := range []int32{-1, -5} {
		_, err := s.Rollback(ctxWithPeerUID(0), &pb.RollbackRequest{N: n})
		if err == nil {
			t.Fatalf("n=%d: expected error, got nil", n)
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("n=%d: status = %v, want InvalidArgument", n, status.Code(err))
		}
		if !strings.Contains(err.Error(), "rollback index must be non-negative") {
			t.Fatalf("n=%d: error = %q, want substring %q", n, err.Error(), "rollback index must be non-negative")
		}
		if strings.Contains(err.Error(), "out of range") {
			t.Fatalf("n=%d: error leaked the opaque store message %q", n, err.Error())
		}
	}
}

// n==0 (revert to active) is unchanged by the guard: a fresh store rolls back
// to its active config cleanly.
func TestRollbackAcceptsZeroN(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	s := &Server{store: store}
	if _, err := s.Rollback(ctxWithPeerUID(0), &pb.RollbackRequest{N: 0}); err != nil {
		t.Fatalf("n=0 (revert to active) rejected by the negative-n guard: %v", err)
	}
}
