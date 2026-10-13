// #5782: SessionCount() is a full v4+v6 session-map iteration holding the
// per-bucket BPF-map locks for O(table) — the SAME lock-contention DoS class
// #5708 bounded for the IterateSessions* read-scans, but reachable UNGATED via
// two client surfaces: the GetStatus RPC and `show system buffers[-detail]`
// (ShowText). Both now draw from the shared diagcmd.SessionWalkLimiter and fail
// fast with ResourceExhausted on contention, exactly like the read-scans and
// sessions-top.
//
// FAIL-ON-REVERT: remove the sessionWalkLimiter.Acquire() gate from GetStatus /
// showBuffers / showBuffersDetail and an over-cap call proceeds straight to the
// SessionCount walk and returns a normal response — the ResourceExhausted +
// "SessionCount not walked" assertions below go RED.
package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// countBoundDP is a grpcRuntime fake: IsLoaded true, a controllable SessionCount
// that records whether it was invoked (so a gated over-cap call proves it did
// NOT walk), and empty map stats (so showBuffers takes the non-userspace-provider
// branch and reaches the SessionCount call). Embeds *dataplane.Manager for the
// rest of the interface, mirroring boundSessionDP (#5708).
type countBoundDP struct {
	*dataplane.Manager
	v4, v6     int
	countCalls int32
}

func (*countBoundDP) IsLoaded() bool { return true }

func (d *countBoundDP) SessionCount() (int, int) {
	atomic.AddInt32(&d.countCalls, 1)
	return d.v4, d.v6
}

func (d *countBoundDP) SessionCountContext(context.Context) (int, int, error) {
	return d.v4, d.v6, nil
}

func (*countBoundDP) GetMapStats() []dataplane.MapStats { return nil }

func newCountBoundServer(t *testing.T, dp *countBoundDP) *Server {
	t.Helper()
	return &Server{
		dp:    dp,
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
}

// GetStatus's SessionCount walk is gated: a saturated limiter → ResourceExhausted
// with NO walk; after a slot frees → the correct count.
func TestGRPCGetStatusSessionCountBound_5782(t *testing.T) {
	orig := sessionWalkLimiter
	t.Cleanup(func() { sessionWalkLimiter = orig })
	sessionWalkLimiter = diagcmd.NewLimiter(1)

	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only slot: %v", err)
	}

	dp := &countBoundDP{Manager: dataplane.New(), v4: 3, v6: 5}
	s := newCountBoundServer(t, dp)

	_, err = s.GetStatus(context.Background(), &pb.GetStatusRequest{})
	if !isResourceExhausted(err) {
		release()
		t.Fatalf("GetStatus with a saturated session-walk limiter: err = %v, want codes.ResourceExhausted (admission gate not consulted)", err)
	}
	if n := atomic.LoadInt32(&dp.countCalls); n != 0 {
		release()
		t.Fatalf("SessionCount walked %d times despite a saturated limiter — the gate must fail fast BEFORE the walk", n)
	}

	release()
	resp, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus after slot release: %v", err)
	}
	if resp.SessionCount != 8 {
		t.Fatalf("GetStatus SessionCount = %d, want 8 (v4=3 + v6=5) — the admitted path must return the real count", resp.SessionCount)
	}
}

// `show system buffers` and `... detail` (ShowText topics) are gated identically:
// a saturated limiter → ResourceExhausted (ShowText returns the handler error
// verbatim) with NO walk; released → the session-count line renders.
func TestGRPCShowBuffersSessionCountBound_5782(t *testing.T) {
	for _, topic := range []string{"buffers", "buffers-detail"} {
		t.Run(topic, func(t *testing.T) {
			orig := sessionWalkLimiter
			t.Cleanup(func() { sessionWalkLimiter = orig })
			sessionWalkLimiter = diagcmd.NewLimiter(1)

			release, err := sessionWalkLimiter.Acquire()
			if err != nil {
				t.Fatalf("failed to pre-acquire the only slot: %v", err)
			}

			dp := &countBoundDP{Manager: dataplane.New(), v4: 3, v6: 5}
			s := newCountBoundServer(t, dp)

			_, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
			if !isResourceExhausted(err) {
				release()
				t.Fatalf("ShowText %q with a saturated limiter: err = %v, want codes.ResourceExhausted", topic, err)
			}
			if n := atomic.LoadInt32(&dp.countCalls); n != 0 {
				release()
				t.Fatalf("%s: SessionCount walked %d times despite a saturated limiter", topic, n)
			}

			release()
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
			if err != nil {
				t.Fatalf("ShowText %q after slot release: %v", topic, err)
			}
			if !strings.Contains(resp.Output, "Active sessions: 3 IPv4, 5 IPv6, 8 total") {
				t.Fatalf("%s: admitted render missing the session-count line; got:\n%s", topic, resp.Output)
			}
		})
	}
}

// The gated SessionCount surfaces draw from the PROCESS-WIDE
// diagcmd.SessionWalkLimiter — the SAME instance the REST + gRPC read-scans use
// — so a mix of scrapers cannot collectively exceed the aggregate budget.
// Saturating the shared singleton directly must make GetStatus ResourceExhausted.
func TestGRPCSessionCountDrawsFromSharedLimiter_5782(t *testing.T) {
	if sessionWalkLimiter != diagcmd.SessionWalkLimiter {
		t.Fatal("grpcapi sessionWalkLimiter is not the shared diagcmd.SessionWalkLimiter instance; the SessionCount budget is not aggregated with the read-scans")
	}
	var releases []func()
	t.Cleanup(func() {
		for _, r := range releases {
			r()
		}
	})
	for {
		rel, err := diagcmd.SessionWalkLimiter.Acquire()
		if err != nil {
			break
		}
		releases = append(releases, rel)
	}
	if len(releases) == 0 {
		t.Fatal("could not acquire any slot on the shared limiter")
	}

	dp := &countBoundDP{Manager: dataplane.New(), v4: 1, v6: 1}
	s := newCountBoundServer(t, dp)
	if _, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{}); !isResourceExhausted(err) {
		t.Fatalf("GetStatus with the shared limiter saturated: err = %v, want codes.ResourceExhausted (handler not drawing from the shared instance)", err)
	}
}
