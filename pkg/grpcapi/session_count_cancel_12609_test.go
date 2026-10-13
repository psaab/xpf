package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type cancelCountDP12609 struct {
	grpcRuntime
	cancel   context.CancelFunc
	v4Visits int
	v6Walks  int
}

func (*cancelCountDP12609) IsLoaded() bool { return true }

func (d *cancelCountDP12609) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i := 0; i < 4096; i++ {
		d.v4Visits++
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{}) {
			return nil
		}
		if d.v4Visits == sessionWalkCancelInterval9060-1 {
			d.cancel()
		}
	}
	return nil
}

func (d *cancelCountDP12609) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.v6Walks++
	return nil
}

func (*cancelCountDP12609) GetMapStats() []dataplane.MapStats { return nil }

func TestBackendSessionCountStopsOnCancellation12609(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dp := &cancelCountDP12609{cancel: cancel}
	v4, v6, err := backendSessionCountContext(ctx, dp)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("backendSessionCountContext error=%v, want context.Canceled", err)
	}
	if v4 != 0 || v6 != 0 {
		t.Fatalf("partial count returned: v4=%d v6=%d", v4, v6)
	}
	if dp.v4Visits != sessionWalkCancelInterval9060 || dp.v6Walks != 0 {
		t.Fatalf("walks v4=%d v6=%d, want sampled v4 stop and no v6", dp.v4Visits, dp.v6Walks)
	}
}

func TestGetStatusSessionCountCancellation12609(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dp := &cancelCountDP12609{cancel: cancel}
	s := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	resp, err := s.GetStatus(ctx, &pb.GetStatusRequest{})
	if resp != nil || status.Code(err) != codes.Canceled {
		t.Fatalf("GetStatus = (%v, %v), want nil response and Canceled", resp, err)
	}
	if dp.v4Visits != sessionWalkCancelInterval9060 || dp.v6Walks != 0 {
		t.Fatalf("walks v4=%d v6=%d, want sampled v4 stop and no v6", dp.v4Visits, dp.v6Walks)
	}
	release, acquireErr := sessionWalkLimiter.Acquire()
	if acquireErr != nil {
		t.Fatalf("session-walk slot retained after cancellation: %v", acquireErr)
	}
	release()
}

func TestShowBuffersSessionCountCancellation12609(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dp := &cancelCountDP12609{cancel: cancel}
	s := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	resp, err := s.ShowText(ctx, &pb.ShowTextRequest{Topic: "buffers"})
	if resp != nil || status.Code(err) != codes.Canceled {
		t.Fatalf("ShowText(buffers) = (%v, %v), want nil response and Canceled", resp, err)
	}
	if dp.v4Visits != sessionWalkCancelInterval9060 || dp.v6Walks != 0 {
		t.Fatalf("walks v4=%d v6=%d, want sampled v4 stop and no v6", dp.v4Visits, dp.v6Walks)
	}
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("session-walk slot retained after buffers cancellation: %v", err)
	}
	release()
}

func TestBackendSessionCountExpiredDeadline12609(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	dp := &cancelCountDP12609{cancel: cancel}
	v4, v6, err := backendSessionCountContext(ctx, dp)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("backendSessionCountContext error=%v, want context.DeadlineExceeded", err)
	}
	if v4 != 0 || v6 != 0 || dp.v4Visits != 0 || dp.v6Walks != 0 {
		t.Fatalf("expired context produced counts/walks: v4=%d v6=%d visits=%d/%d", v4, v6, dp.v4Visits, dp.v6Walks)
	}
}
