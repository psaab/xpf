package grpcapi

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// #14980 (D35-01): Ping/Traceroute called stream.Send inline in the
// streamDiagCmd scan goroutine, with the diagLimiter slot released only by
// the handler's defer. grpc-go Send has no deadline: a client that stops
// draining parks Send, the scan goroutine never returns, streamDiagCmd's
// c.Wait() never returns, and the handler never reaches its defer — one
// stuck client pinned a process-wide diag slot indefinitely, four pinned
// all of MaxConcurrentDiagnostics (=4) for gRPC AND REST.
//
// The fix bounds each Send (sendDiagFrame, diagStreamSendTimeout): on
// sever the handler returns DeadlineExceeded promptly and the slot
// TRANSFERS to the Send worker, freed only when Send unblocks (handler
// return cancels the stream ctx in real grpc-go, unblocking the quota
// wait). These tests reproduce the exact mechanism with a Send that blocks
// until explicitly released, a fake streamDiag that emits one line through
// the real sendFn wiring, and a compressed send timeout.
//
// RED on master: Ping/Traceroute never return (watchdog fires) and the
// slot stays held. GREEN post-fix: prompt DeadlineExceeded, slot held
// while the worker is parked (no premature release), slot freed once the
// parked Send is unblocked.

// blockingPingStream blocks in Send until sendRelease is closed, modelling
// a client that filled its flow-control window and stopped reading.
type blockingPingStream struct {
	ctx         context.Context
	sendEntered chan struct{}
	sendRelease chan struct{}
	sent        atomic.Int32
}

func newBlockingPingStream(ctx context.Context) *blockingPingStream {
	return &blockingPingStream{ctx: ctx, sendEntered: make(chan struct{}), sendRelease: make(chan struct{})}
}

func (f *blockingPingStream) Send(*pb.PingResponse) error {
	f.sent.Add(1)
	select {
	case <-f.sendEntered:
	default:
		close(f.sendEntered)
	}
	<-f.sendRelease
	return nil
}
func (f *blockingPingStream) Context() context.Context     { return f.ctx }
func (f *blockingPingStream) SetHeader(metadata.MD) error  { return nil }
func (f *blockingPingStream) SendHeader(metadata.MD) error { return nil }
func (f *blockingPingStream) SetTrailer(metadata.MD)       {}
func (f *blockingPingStream) SendMsg(any) error            { return nil }
func (f *blockingPingStream) RecvMsg(any) error            { return nil }

type blockingTracerouteStream struct {
	ctx         context.Context
	sendEntered chan struct{}
	sendRelease chan struct{}
	sent        atomic.Int32
}

func newBlockingTracerouteStream(ctx context.Context) *blockingTracerouteStream {
	return &blockingTracerouteStream{ctx: ctx, sendEntered: make(chan struct{}), sendRelease: make(chan struct{})}
}

func (f *blockingTracerouteStream) Send(*pb.TracerouteResponse) error {
	f.sent.Add(1)
	select {
	case <-f.sendEntered:
	default:
		close(f.sendEntered)
	}
	<-f.sendRelease
	return nil
}
func (f *blockingTracerouteStream) Context() context.Context     { return f.ctx }
func (f *blockingTracerouteStream) SetHeader(metadata.MD) error  { return nil }
func (f *blockingTracerouteStream) SendHeader(metadata.MD) error { return nil }
func (f *blockingTracerouteStream) SetTrailer(metadata.MD)       {}
func (f *blockingTracerouteStream) SendMsg(any) error            { return nil }
func (f *blockingTracerouteStream) RecvMsg(any) error            { return nil }

// swapDiagSeams14980 installs a limiter of capN, a fake streamDiag that
// emits exactly one line through the handler's real sendFn (so the test
// exercises the Send bound, not a stubbed-away send), and a compressed
// per-write timeout. Restored on cleanup.
func swapDiagSeams14980(t *testing.T, capN int) {
	t.Helper()
	origLimiter := diagLimiter
	origStream := streamDiag
	origTimeout := diagStreamSendTimeout
	t.Cleanup(func() {
		diagLimiter = origLimiter
		streamDiag = origStream
		diagStreamSendTimeout = origTimeout
	})
	diagLimiter = diagcmd.NewLimiter(capN)
	diagStreamSendTimeout = 150 * time.Millisecond
	streamDiag = func(ctx context.Context, timeout time.Duration, cmd []string, sendFn func(string) error) error {
		return sendFn("64 bytes from 192.0.2.1")
	}
}

func TestDiagSendBound14980PingSlowConsumerSeversAndTransfers(t *testing.T) {
	swapDiagSeams14980(t, 1)
	s := &Server{}
	stream := newBlockingPingStream(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.Ping(&pb.PingRequest{Target: "192.0.2.1"}, stream) }()

	select {
	case <-stream.sendEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("fake diagnostic never reached Send")
	}

	// The handler must sever within the per-write bound, not hang in Send.
	start := time.Now()
	select {
	case err := <-done:
		if status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("Ping err = %v (code %v), want DeadlineExceeded slow-consumer sever", err, status.Code(err))
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("Ping severed only after %v, want ~diagStreamSendTimeout", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ping did not return within 5s of a blocked Send: diag slot pinned indefinitely (#14980)")
	}

	// Transfer, not premature release: while the Send worker is still
	// parked the slot must remain held, so no second diagnostic is admitted.
	if got := diagLimiter.InFlight(); got != 1 {
		t.Fatalf("InFlight after sever = %d, want 1 (slot transferred to parked Send worker, not freed early)", got)
	}
	freshStream := newBlockingPingStream(context.Background())
	close(freshStream.sendRelease) // would succeed instantly if (wrongly) admitted
	if err := s.Ping(&pb.PingRequest{Target: "192.0.2.1"}, freshStream); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second Ping while worker parked = %v, want ResourceExhausted (slot must stay held)", err)
	}

	// Unblocking Send (what stream-ctx cancel does in real grpc-go when the
	// handler returns) must free the transferred slot.
	close(stream.sendRelease)
	deadline := time.Now().Add(5 * time.Second)
	for diagLimiter.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("transferred slot never freed after parked Send unblocked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// And the budget is usable again.
	okStream := newBlockingPingStream(context.Background())
	close(okStream.sendRelease)
	if err := s.Ping(&pb.PingRequest{Target: "192.0.2.1"}, okStream); err != nil {
		t.Fatalf("Ping after drain failed: %v (limiter not released)", err)
	}
}

func TestDiagSendBound14980TracerouteSlowConsumerSeversAndTransfers(t *testing.T) {
	swapDiagSeams14980(t, 1)
	s := &Server{}
	stream := newBlockingTracerouteStream(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.Traceroute(&pb.TracerouteRequest{Target: "192.0.2.1"}, stream) }()

	select {
	case <-stream.sendEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("fake diagnostic never reached Send")
	}
	select {
	case err := <-done:
		if status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("Traceroute err = %v (code %v), want DeadlineExceeded slow-consumer sever", err, status.Code(err))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Traceroute did not return within 5s of a blocked Send: diag slot pinned indefinitely (#14980)")
	}
	if got := diagLimiter.InFlight(); got != 1 {
		t.Fatalf("InFlight after sever = %d, want 1 (transferred to parked worker)", got)
	}
	close(stream.sendRelease)
	deadline := time.Now().Add(5 * time.Second)
	for diagLimiter.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("transferred slot never freed after parked Send unblocked")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDiagSendBound14980FourStuckClientsCannotPinBudget proves the D35-01
// consequence directly: with the production cap of 4, four non-draining
// clients sever and (after their Sends unblock) the whole budget is
// reclaimed — pre-fix each handler hung forever holding its slot.
func TestDiagSendBound14980FourStuckClientsCannotPinBudget(t *testing.T) {
	swapDiagSeams14980(t, 4)
	s := &Server{}

	streams := make([]*blockingPingStream, 4)
	errs := make([]chan error, 4)
	for i := range 4 {
		streams[i] = newBlockingPingStream(context.Background())
		errs[i] = make(chan error, 1)
		st := streams[i]
		go func() { errs[i] <- s.Ping(&pb.PingRequest{Target: "192.0.2.1"}, st) }()
	}
	for i := range 4 {
		select {
		case err := <-errs[i]:
			if status.Code(err) != codes.DeadlineExceeded {
				t.Fatalf("stuck Ping %d err = %v, want DeadlineExceeded", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("stuck Ping %d never severed: budget pin (#14980)", i)
		}
	}
	if got := diagLimiter.InFlight(); got != 4 {
		t.Fatalf("InFlight with 4 parked workers = %d, want 4 (transferred, not leaked-free)", got)
	}
	for _, st := range streams {
		close(st.sendRelease)
	}
	deadline := time.Now().Add(5 * time.Second)
	for diagLimiter.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("budget never reclaimed: InFlight=%d", diagLimiter.InFlight())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDiagSendBound14980HealthySendUnchanged is the adjacent control: a
// client that drains instantly gets its line and a nil error, and the slot
// is released by the normal (non-transferred) path.
func TestDiagSendBound14980HealthySendUnchanged(t *testing.T) {
	swapDiagSeams14980(t, 1)
	s := &Server{}
	stream := newBlockingPingStream(context.Background())
	close(stream.sendRelease) // Send returns immediately

	if err := s.Ping(&pb.PingRequest{Target: "192.0.2.1"}, stream); err != nil {
		t.Fatalf("healthy Ping failed: %v", err)
	}
	if stream.sent.Load() != 1 {
		t.Fatalf("Send calls = %d, want 1", stream.sent.Load())
	}
	if got := diagLimiter.InFlight(); got != 0 {
		t.Fatalf("InFlight after healthy Ping = %d, want 0", got)
	}
}

// TestDiagSendBound14980CtxCancelTransfers pins the reauth/cancel leg
// (authz_stream_reauth_9051.go cancels only the wrapper ctx, not the
// transport Send — #14150 class): cancelling the stream context while Send
// is parked must sever the handler with the ctx error AND transfer the
// slot, not free it while the worker is still parked.
func TestDiagSendBound14980CtxCancelTransfers(t *testing.T) {
	swapDiagSeams14980(t, 1)
	// Large send timeout: only ctx cancellation can sever this one.
	diagStreamSendTimeout = 30 * time.Second
	s := &Server{}
	ctx, cancel := context.WithCancel(context.Background())
	stream := newBlockingPingStream(ctx)

	done := make(chan error, 1)
	go func() { done <- s.Ping(&pb.PingRequest{Target: "192.0.2.1"}, stream) }()
	select {
	case <-stream.sendEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("fake diagnostic never reached Send")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Ping after ctx cancel = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ping did not sever on ctx cancel while Send parked")
	}
	if got := diagLimiter.InFlight(); got != 1 {
		t.Fatalf("InFlight after ctx-cancel sever = %d, want 1 (transferred)", got)
	}
	close(stream.sendRelease)
	deadline := time.Now().Add(5 * time.Second)
	for diagLimiter.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("transferred slot never freed after parked Send unblocked (ctx path)")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSendDiagFrame14980BoundarySendFreesSlotExactlyOnce pins the timer
// boundary: a Send completing exactly as the timer fires lands either on
// the fast path (success, caller still owns the slot) or the terminal
// sever path (DeadlineExceeded, xfer=true, worker/boundary owns the
// release). Scheduling decides which; both must end with the slot freed
// exactly once — never leaked, never double-freed, never continued
// slotless under a success the caller thinks it still owns.
func TestSendDiagFrame14980BoundarySendFreesSlotExactlyOnce(t *testing.T) {
	origTimeout := diagStreamSendTimeout
	t.Cleanup(func() { diagStreamSendTimeout = origTimeout })
	diagStreamSendTimeout = 100 * time.Millisecond

	lim := diagcmd.NewLimiter(1)
	release, err := lim.Acquire()
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	send := func() error {
		time.Sleep(100 * time.Millisecond)
		return nil
	}
	err, xfer := sendDiagFrame(context.Background(), send, release)
	// The timer (100ms) and Send (100ms) race: either the timer wins and
	// the sever is terminal (err non-nil), or the fast path wins by a
	// hair and returns success WITH the caller still owning the slot —
	// also acceptable, since Send completed and nothing continues
	// slotless (handler-defers release it). What must never happen is a
	// success the caller believes it still owns while the worker already
	// freed the slot — unobservable directly, so assert the invariant
	// jointly: if transferred, the caller-owned defer is disarmed and the
	// worker/handler-boundary release frees it; if not transferred, the
	// caller's own release (this defer-equivalent) frees it. Either way
	// the slot ends freed exactly once below.
	if !xfer {
		release()
	}
	// Whether the handler (boundary drain) or the worker released, the slot
	// must end freed exactly once — poll briefly for the worker path.
	deadline := time.Now().Add(5 * time.Second)
	for lim.InFlight() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("slot leaked on boundary path: InFlight=%d (xfer=%v)", lim.InFlight(), xfer)
		}
		time.Sleep(5 * time.Millisecond)
	}
	rel2, err := lim.Acquire()
	if err != nil {
		t.Fatalf("re-acquire after boundary sever failed: %v", err)
	}
	rel2()
}
