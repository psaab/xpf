package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type grpcV6CancelDP12609 struct {
	grpcRuntime
	v4Visits int
	v6Visits int
	cancel   context.CancelFunc
}

func (*grpcV6CancelDP12609) IsLoaded() bool                    { return true }
func (*grpcV6CancelDP12609) GetMapStats() []dataplane.MapStats { return nil }

func (d *grpcV6CancelDP12609) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for range sessionWalkCancelInterval9060 {
		d.v4Visits++
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{}) {
			break
		}
	}
	return nil
}

func (d *grpcV6CancelDP12609) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.v6Visits++
	fn(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{})
	d.cancel()
	return nil
}

func TestGetStatusCancellationDuringV612609(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dp := &grpcV6CancelDP12609{cancel: cancel}
	s := &Server{dp: dp, store: newConfigStore(t, t.TempDir()+"/xpf.conf")}
	resp, err := s.GetStatus(ctx, &pb.GetStatusRequest{})
	if resp != nil || status.Code(err) != codes.Canceled {
		t.Fatalf("GetStatus = (%v, %v), want nil response and Canceled", resp, err)
	}
	if dp.v4Visits != sessionWalkCancelInterval9060 || dp.v6Visits != 1 {
		t.Fatalf("walks v4=%d v6=%d, want complete v4 and canceled v6 pass", dp.v4Visits, dp.v6Visits)
	}
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("session-walk slot retained after v6 cancellation: %v", err)
	}
	release()
}

func TestShowBuffersDetailCancellationReleasesSlot12609(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dp := &grpcV6CancelDP12609{cancel: cancel}
	s := &Server{dp: dp, store: newConfigStore(t, t.TempDir()+"/xpf.conf")}
	resp, err := s.ShowText(ctx, &pb.ShowTextRequest{Topic: "buffers-detail"})
	if resp != nil || status.Code(err) != codes.Canceled {
		t.Fatalf("ShowText(buffers-detail) = (%v, %v), want nil response and Canceled", resp, err)
	}
	if dp.v4Visits != sessionWalkCancelInterval9060 || dp.v6Visits != 1 {
		t.Fatalf("walks v4=%d v6=%d, want complete v4 and canceled v6 pass", dp.v4Visits, dp.v6Visits)
	}
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("session-walk slot retained after buffers-detail cancellation: %v", err)
	}
	release()
}

func TestGetStatusExpiredDeadlineThroughHandler12609(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	dp := &grpcV6CancelDP12609{cancel: func() {}}
	s := &Server{dp: dp, store: newConfigStore(t, t.TempDir()+"/xpf.conf")}
	resp, err := s.GetStatus(ctx, &pb.GetStatusRequest{})
	if resp != nil || status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("GetStatus = (%v, %v), want nil response and DeadlineExceeded", resp, err)
	}
	if dp.v4Visits != 0 || dp.v6Visits != 0 {
		t.Fatalf("expired request walked v4/v6 %d/%d times", dp.v4Visits, dp.v6Visits)
	}
}
