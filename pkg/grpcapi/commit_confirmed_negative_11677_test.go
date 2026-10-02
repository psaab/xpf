package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCCommitConfirmedRejectsNegativeMinutes_11677(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	called := false
	s := &Server{
		store: store,
		commitConfirmedFn: func(context.Context, configstore.CommitAuthority, int) (*config.Config, error) {
			called = true
			return store.CommitConfirmed(-1)
		},
	}

	_, err := s.CommitConfirmed(clientCtx(1111), &pb.CommitConfirmedRequest{Minutes: -1})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument || !strings.Contains(st.Message(), "non-negative") {
		t.Fatalf("CommitConfirmed(-1) error = %v; want InvalidArgument identifying the invalid timeout", err)
	}
	if called {
		t.Fatal("gRPC handler invoked commitConfirmedFn for a negative timeout")
	}
	if store.IsConfirmPending() {
		t.Fatal("negative gRPC timeout armed a confirm window")
	}
}
