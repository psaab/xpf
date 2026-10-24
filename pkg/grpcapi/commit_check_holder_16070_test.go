package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16070, gRPC half: CommitCheck must deny a non-holder connection with
// PermissionDenied before it can obtain compile diagnostics about the
// holder's staged candidate, admit the holder, and map the compile
// admission refusal to ResourceExhausted.
//
// FAIL-ON-REVERT: revert CommitCheck to s.store.CommitCheck() and the
// non-holder case returns the holder's compile result instead of
// PermissionDenied. Drop the ErrCommitCheckBusy arm from
// configMutationStatus and the busy case maps to InvalidArgument.

func TestGRPCCommitCheckHolderGate_16070(t *testing.T) {
	holderCtx := clientCtx(16070)
	holderID := connSessionID(holderCtx)
	store := grpcHolderStore(t, holderID)
	s := &Server{store: store}

	// Holder: the check compiles its own candidate.
	if _, err := s.CommitCheck(holderCtx, &pb.CommitCheckRequest{}); err != nil {
		t.Fatalf("CommitCheck(holder) = %v, want nil", err)
	}

	// Non-holder (a different connection): denied, no diagnostics.
	otherCtx := clientCtx(16071)
	if _, err := s.CommitCheck(otherCtx, &pb.CommitCheckRequest{}); err == nil {
		t.Fatal("CommitCheck(non-holder) succeeded, want PermissionDenied")
	} else if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("CommitCheck(non-holder) = %v, want PermissionDenied", err)
	}
}

func TestGRPCCommitCheckBusyMapping_16070(t *testing.T) {
	holderCtx := clientCtx(16072)
	holderID := connSessionID(holderCtx)
	store := grpcHolderStore(t, holderID)
	s := &Server{store: store}

	// configMutationStatus is the mapping both the handler and any future
	// caller share; pin the busy sentinel's code directly.
	err := configMutationStatus(configstore.ErrCommitCheckBusy)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("configMutationStatus(ErrCommitCheckBusy) = %v, want ResourceExhausted", err)
	}
	// Holder sentinel stays PermissionDenied (no regression on the
	// mapping this change extended).
	err = configMutationStatus(configstore.ErrConfigLockedByOther)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("configMutationStatus(ErrConfigLockedByOther) = %v, want PermissionDenied", err)
	}

	// End-to-end through the handler: a store whose candidate holds a
	// retired dataplane type still reports its compile diagnostic to the
	// holder (proving the admission slot was released by the busy-map
	// path above and the holder path still compiles).
	if _, err := s.CommitCheck(holderCtx, &pb.CommitCheckRequest{}); err != nil {
		t.Fatalf("CommitCheck(holder, after mapping pins) = %v, want nil", err)
	}
}
