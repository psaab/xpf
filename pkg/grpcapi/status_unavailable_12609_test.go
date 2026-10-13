package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type unavailableStatusDP12609 struct{ grpcRuntime }

func (*unavailableStatusDP12609) IsLoaded() bool { return true }
func (*unavailableStatusDP12609) SessionCountContext(context.Context) (int, int, error) {
	return 0, 0, dataplane.ErrNotPublished
}

func TestGetStatusUnpublishedCountMapsUnavailable12609(t *testing.T) {
	s := &Server{dp: &unavailableStatusDP12609{}, store: newConfigStore(t, t.TempDir()+"/xpf.conf")}
	resp, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
	if resp != nil || status.Code(err) != codes.Unavailable {
		t.Fatalf("GetStatus = (%v, %v), want nil response and Unavailable", resp, err)
	}
}
