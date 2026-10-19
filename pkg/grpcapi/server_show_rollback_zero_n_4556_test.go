package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestShowRollbackRejectsNonPositiveN originally pinned #4556 M-01:
// n<=0 rejected instead of history.Get(-1)'s opaque error. #15657
// V45-03 supersedes the n==0 half: Junos rollback 0 IS the active
// configuration, so n=0 now renders active (see
// TestShowRollbackZeroRendersActive15657 in
// rollback_compare_active_15657_test.go). Only negative wire values
// stay rejected, with a clear non-negative message.
func TestShowRollbackRejectsNonPositiveN(t *testing.T) {
	s := &Server{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	for _, n := range []int32{-1, -5} {
		_, err := s.ShowRollback(context.Background(), &pb.ShowRollbackRequest{N: n})
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

// TestShowRollbackAcceptsSlotOne asserts n=1 is unchanged by the M-01 guard:
// a real committed rollback slot 1 still renders. One Commit() pushes the
// prior (empty) active into history slot 1.
func TestShowRollbackAcceptsSlotOne(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet("set system host-name rollback-fixture"); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	s := &Server{store: store}

	resp, err := s.ShowRollback(context.Background(), &pb.ShowRollbackRequest{N: 1})
	if err != nil {
		t.Fatalf("n=1: unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("n=1: nil response")
	}
}
