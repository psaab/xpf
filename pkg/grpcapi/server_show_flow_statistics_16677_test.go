// #16677: ShowText "flow-statistics" ran an unadmitted, uncancellable
// full v4+v6 session-table walk (via grpcSessionCount on
// context.Background(), error discarded) and printed a walk failure
// as "Current sessions: 0". It now AcquireCtx's the shared
// sessionWalkLimiter, threads the ShowText ctx into the walk, and
// returns walk failures as errors.
//
// FAIL-ON-REVERT: removing the AcquireCtx gate makes the saturated
// case render instead of returning ResourceExhausted; restoring the
// discarded error makes the walk-error case render "Current
// sessions: 0" instead of failing; restoring context.Background()
// makes the cancellation case hang/walk instead of aborting.
package grpcapi

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// flowStatsDP is a grpcRuntime that counts via SessionCountContext and
// records how many times the walk was entered and which ctx it saw.
type flowStatsDP struct {
	*dataplane.Manager
	v4, v6   int
	countErr error
	calls    int32
	ctxSeen  atomic.Value // context.Context
}

func (*flowStatsDP) IsLoaded() bool { return true }

func (d *flowStatsDP) SessionCountContext(ctx context.Context) (int, int, error) {
	atomic.AddInt32(&d.calls, 1)
	d.ctxSeen.Store(ctx)
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	if d.countErr != nil {
		return 0, 0, d.countErr
	}
	return d.v4, d.v6, nil
}
func TestShowTextFlowStatisticsAdmission16677(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("pre-acquire only slot: %v", err)
	}
	dp := &flowStatsDP{Manager: dataplane.New(), v4: 3, v6: 5}
	s := newViewServer(t, dp)

	_, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "flow-statistics"})
	if !isResourceExhausted(err) {
		release()
		t.Fatalf("ShowText flow-statistics with saturated limiter: err = %v, want codes.ResourceExhausted", err)
	}
	if n := atomic.LoadInt32(&dp.calls); n != 0 {
		release()
		t.Fatalf("session-count walk ran %d times despite saturated limiter", n)
	}

	release()
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "flow-statistics"})
	if err != nil {
		t.Fatalf("ShowText flow-statistics after release: %v", err)
	}
	if !strings.Contains(resp.Output, "Current sessions:") || !strings.Contains(resp.Output, "8") {
		t.Fatalf("admitted render missing current-sessions total 8; got:\n%s", resp.Output)
	}
	if n := atomic.LoadInt32(&dp.calls); n != 1 {
		t.Fatalf("session-count walk calls = %d, want 1", n)
	}
}

func TestShowTextFlowStatisticsWalkErrorNotZero16677(t *testing.T) {
	dp := &flowStatsDP{Manager: dataplane.New(), countErr: errors.New("helper restart: session map closed")}
	s := newViewServer(t, dp)

	_, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "flow-statistics"})
	if err == nil {
		t.Fatal("ShowText flow-statistics returned nil on walk failure; want error, not Current sessions: 0")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("walk failure code = %v, want Internal; err: %v", status.Code(err), err)
	}
	if n := atomic.LoadInt32(&dp.calls); n != 1 {
		t.Fatalf("session-count walk calls = %d, want 1", n)
	}
}

func TestShowTextFlowStatisticsCancelledCtx16677(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dp := &flowStatsDP{Manager: dataplane.New(), v4: 1, v6: 1}
	// Make the walk observe the ctx like the real backend: fail if cancelled.
	dp.countErr = nil
	s := newViewServer(t, dp)

	_, err := s.ShowText(ctx, &pb.ShowTextRequest{Topic: "flow-statistics"})
	if err == nil {
		t.Fatal("ShowText flow-statistics with cancelled ctx returned nil; want cancellation error")
	}
	// The walk must have received a cancellable ctx (not Background):
	// either SessionCountContext saw the cancelled ctx, or AcquireCtx/
	// backend short-circuited on it. Assert the code is Canceled.
	if status.Code(err) != codes.Canceled {
		t.Fatalf("cancelled ctx code = %v, want Canceled; err: %v (walk calls=%d)", status.Code(err), err, atomic.LoadInt32(&dp.calls))
	}
}

// The ctx threaded into the walk is the ShowText ctx (via the
// AcquireCtx lease), not context.Background().
func TestShowFlowStatisticsThreadsShowTextCtx16677(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "showtext-marker")
	dp := &flowStatsDP{Manager: dataplane.New(), v4: 2, v6: 0}
	s := newViewServer(t, dp)

	if _, err := s.ShowText(ctx, &pb.ShowTextRequest{Topic: "flow-statistics"}); err != nil {
		t.Fatalf("ShowText flow-statistics: %v", err)
	}
	seen, _ := dp.ctxSeen.Load().(context.Context)
	if seen == nil {
		t.Fatal("SessionCountContext never called")
	}
	if seen.Value(ctxKey{}) != "showtext-marker" {
		t.Fatal("walk ctx does not carry the ShowText ctx value; context.Background() regression?")
	}
}

// Positive control: counter-read failure still renders with the #3345
// warning (unchanged behaviour) when the walk succeeds.
func TestShowFlowStatisticsCounterWarningPreserved16677(t *testing.T) {
	dp := &counterFaultGRPCDP{Manager: dataplane.New()}
	s := newViewServer(t, dp)

	var buf strings.Builder
	if err := s.showFlowStatistics(context.Background(), &buf); err != nil {
		t.Fatalf("showFlowStatistics: %v", err)
	}
	if !strings.Contains(buf.String(), "warning") {
		t.Fatalf("output lacks counter-read warning; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "Current sessions:") {
		t.Fatalf("output lacks Current sessions line; got:\n%s", buf.String())
	}
}
