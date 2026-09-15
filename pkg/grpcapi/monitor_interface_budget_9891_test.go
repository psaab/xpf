package grpcapi

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// #9891: MonitorInterface was the one monitor stream with no subscriber budget
// and no send deadline — a 1s ticker, an unbounded for loop, and a blocking
// stream.Send with no admission gate. Sibling MonitorPacketDrop refuses past
// its EventBuffer cap and Ping/Traceroute refuse past diagLimiter; this one
// admitted without limit and a slow consumer parked its goroutine.

// capMonitorStream9891 is a MonitorInterface server stream that records frames
// and stays alive until its context is cancelled, holding its subscriber slot.
type capMonitorStream9891 struct {
	ctx    context.Context
	cancel context.CancelFunc
	frames atomic.Int64
}

func (m *capMonitorStream9891) Send(*pb.MonitorInterfaceResponse) error {
	m.frames.Add(1)
	return nil
}
func (m *capMonitorStream9891) Context() context.Context     { return m.ctx }
func (m *capMonitorStream9891) SetHeader(metadata.MD) error  { return nil }
func (m *capMonitorStream9891) SendHeader(metadata.MD) error { return nil }
func (m *capMonitorStream9891) SetTrailer(metadata.MD)       {}
func (m *capMonitorStream9891) SendMsg(any) error            { return nil }
func (m *capMonitorStream9891) RecvMsg(any) error            { return nil }

func monitorBudgetStore9891(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride("system { host-name fw; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Server{store: store, dp: &fanoutStatusDP{}}
}

func waitForFrames9891(t *testing.T, streams []*capMonitorStream9891, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok := true
		for _, st := range streams {
			if st.frames.Load() < want {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			counts := make([]int64, len(streams))
			for i, st := range streams {
				counts[i] = st.frames.Load()
			}
			t.Fatalf("streams did not reach %d frames within %v: %v", want, timeout, counts)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMonitorInterfaceRejectsOverCap_9891 pins the #9891 admission cap: with a
// 3-slot budget, 4 concurrent subscribers admit 3 and refuse the 4th with
// ResourceExhausted (0 frames, no ticker, no goroutine held), while the
// admitted 3 keep receiving across a tick boundary.
//
// FAIL-ON-REVERT: removing the Acquire branch admits the 4th — it emits a
// frame instead of returning ResourceExhausted — so the refusal assertion
// fires RED.
func TestMonitorInterfaceRejectsOverCap_9891(t *testing.T) {
	orig := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(3)
	t.Cleanup(func() { monitorInterfaceLimiter = orig })

	s := monitorBudgetStore9891(t)

	const admitted, total = 3, 4
	streams := make([]*capMonitorStream9891, total)
	errc := make([]chan error, total)
	for i := range streams {
		ctx, cancel := context.WithCancel(context.Background())
		streams[i] = &capMonitorStream9891{ctx: ctx, cancel: cancel}
		errc[i] = make(chan error, 1)
		go func(idx int) {
			errc[idx] <- s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, streams[idx])
		}(i)
	}
	refusedIdx := -1
	defer func() {
		for _, st := range streams {
			st.cancel()
		}
		for i := range errc {
			if i == refusedIdx {
				continue
			}
			select {
			case <-errc[i]:
			case <-time.After(5 * time.Second):
				t.Errorf("stream %d did not exit after cancel", i)
			}
		}
	}()

	// The 4th must be refused fail-fast. It returns ResourceExhausted without
	// emitting; the admitted 3 stay in the tick loop (no error yet).
	deadline := time.Now().Add(5 * time.Second)
	for refusedIdx < 0 && time.Now().Before(deadline) {
		for i := range errc {
			select {
			case err := <-errc[i]:
				if status.Code(err) != codes.ResourceExhausted {
					t.Fatalf("stream %d over-cap err = %v, want ResourceExhausted", i, err)
				}
				if got := streams[i].frames.Load(); got != 0 {
					t.Fatalf("refused stream %d emitted %d frames, want 0 (refusal must precede the ticker)", i, got)
				}
				refusedIdx = i
			default:
			}
		}
		if refusedIdx < 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if refusedIdx < 0 {
		t.Fatal("no stream was refused past the 3-slot cap (the N+1th was admitted → unbounded)")
	}

	// The admitted 3 keep receiving: first frame immediately, second past the
	// 1s tick.
	var live []*capMonitorStream9891
	for i, st := range streams {
		if i != refusedIdx {
			live = append(live, st)
		}
	}
	if len(live) != admitted {
		t.Fatalf("live streams = %d, want %d", len(live), admitted)
	}
	waitForFrames9891(t, live, 1, 5*time.Second)
	waitForFrames9891(t, live, 2, 5*time.Second)

	if got := monitorInterfaceLimiter.InFlight(); got != admitted {
		t.Fatalf("InFlight while held = %d, want %d", got, admitted)
	}
}

// TestMonitorInterfaceTeardownFreesSlot_9891 proves the `defer release()`
// returns the subscriber slot: an admitted stream holds the only slot (a probe
// acquire fails), and once its context is cancelled the probe succeeds.
func TestMonitorInterfaceTeardownFreesSlot_9891(t *testing.T) {
	orig := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { monitorInterfaceLimiter = orig })

	s := monitorBudgetStore9891(t)
	ctx, cancel := context.WithCancel(context.Background())
	st := &capMonitorStream9891{ctx: ctx, cancel: cancel}
	errc := make(chan error, 1)
	go func() {
		errc <- s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, st)
	}()

	waitForFrames9891(t, []*capMonitorStream9891{st}, 1, 5*time.Second)

	if _, err := monitorInterfaceLimiter.Acquire(); err == nil {
		t.Fatal("probe acquire succeeded while a stream holds the only slot (the stream is not holding admission)")
	}

	cancel()
	select {
	case err := <-errc:
		if err != context.Canceled {
			t.Fatalf("teardown err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not exit after cancel")
	}

	release, err := monitorInterfaceLimiter.Acquire()
	if err != nil {
		t.Fatalf("probe acquire after teardown failed: %v (the slot leaked)", err)
	}
	release()
	if got := monitorInterfaceLimiter.InFlight(); got != 0 {
		t.Fatalf("InFlight after drain = %d, want 0", got)
	}
}

// blockingMonitorStream9891 parks its writer exactly as a full socket buffer
// does: Send blocks until the stream context is done, or forever if the
// handler never returns.
type blockingMonitorStream9891 struct {
	ctx   context.Context
	calls atomic.Int64
}

func (m *blockingMonitorStream9891) Send(*pb.MonitorInterfaceResponse) error {
	m.calls.Add(1)
	<-m.ctx.Done()
	return m.ctx.Err()
}
func (m *blockingMonitorStream9891) Context() context.Context     { return m.ctx }
func (m *blockingMonitorStream9891) SetHeader(metadata.MD) error  { return nil }
func (m *blockingMonitorStream9891) SendHeader(metadata.MD) error { return nil }
func (m *blockingMonitorStream9891) SetTrailer(metadata.MD)       {}
func (m *blockingMonitorStream9891) SendMsg(any) error            { return nil }
func (m *blockingMonitorStream9891) RecvMsg(any) error            { return nil }

// TestMonitorInterfaceSlowConsumerTimesOut_9891 pins the per-write send bound:
// a consumer whose Send never completes must not park the handler goroutine
// past the deadline. With a compressed 200ms budget the RPC returns
// DeadlineExceeded promptly instead of hanging.
//
// FAIL-ON-REVERT: sending via bare stream.Send blocks until ctx cancel — with
// no test cancel armed the handler never returns and this cell times out RED.
func TestMonitorInterfaceSlowConsumerTimesOut_9891(t *testing.T) {
	origTimeout := monitorInterfaceSendTimeout
	monitorInterfaceSendTimeout = 200 * time.Millisecond
	t.Cleanup(func() { monitorInterfaceSendTimeout = origTimeout })

	origLim := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(4)
	t.Cleanup(func() { monitorInterfaceLimiter = origLim })

	s := monitorBudgetStore9891(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &blockingMonitorStream9891{ctx: ctx}

	start := time.Now()
	err := s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, st)
	elapsed := time.Since(start)

	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("slow-consumer err = %v, want DeadlineExceeded (err=%v)", status.Code(err), err)
	}
	if st.calls.Load() < 1 {
		t.Fatal("slow-consumer stream never reached Send, so this proves nothing about the send bound")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("slow-consumer Send parked the handler for %v (no send deadline)", elapsed)
	}
	t.Logf("slow consumer severed after %v (budget %v)", elapsed, monitorInterfaceSendTimeout)
}

// TestMonitorInterfaceLimiterIsSharedInstance_9891 restates the premise the
// budget rests on: the gRPC alias points at the process-wide limiter, so the
// documented cap and the metrics registry observe the same instance.
func TestMonitorInterfaceLimiterIsSharedInstance_9891(t *testing.T) {
	if monitorInterfaceLimiter != diagcmd.MonitorInterfaceLimiter {
		t.Fatal("monitorInterfaceLimiter is not diagcmd.MonitorInterfaceLimiter; admission draws on an undocumented budget")
	}
	if diagcmd.MonitorInterfaceLimiter.Cap() != diagcmd.MaxConcurrentMonitorInterfaceStreams {
		t.Fatalf("MonitorInterfaceLimiter cap = %d, want MaxConcurrentMonitorInterfaceStreams = %d",
			diagcmd.MonitorInterfaceLimiter.Cap(), diagcmd.MaxConcurrentMonitorInterfaceStreams)
	}
	if diagcmd.MaxConcurrentMonitorInterfaceStreams != 64 {
		t.Fatalf("MaxConcurrentMonitorInterfaceStreams = %d, want 64 (the sibling EventBuffer streaming budget)", diagcmd.MaxConcurrentMonitorInterfaceStreams)
	}
	var found bool
	for _, nl := range diagcmd.AllLimiters() {
		if nl.Name == "monitor_interface" && nl.Limiter == diagcmd.MonitorInterfaceLimiter {
			found = true
		}
	}
	if !found {
		t.Fatal("monitor_interface missing from diagcmd.AllLimiters(); its refusals are unexported")
	}
}

// TestMonitorInterfaceValidationCostsNoSlot_9891 is the negative control: a
// NotFound validation failure must not consume admission. With the only slot
// held, a request for an unknown interface still returns NotFound rather than
// ResourceExhausted — the bound is taken after validation, not at the handler.
func TestMonitorInterfaceValidationCostsNoSlot_9891(t *testing.T) {
	orig := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { monitorInterfaceLimiter = orig })

	release, err := monitorInterfaceLimiter.Acquire()
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	defer release()

	s := monitorBudgetStore9891(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &capMonitorStream9891{ctx: ctx, cancel: cancel}
	err = s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "ge-9/9/9-nonexistent"}, st)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown-interface with saturated limiter code = %v, want NotFound (validation must not take a slot); err=%v", status.Code(err), err)
	}
}
