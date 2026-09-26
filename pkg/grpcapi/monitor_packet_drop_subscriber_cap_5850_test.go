package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// #5850: MonitorPacketDrop is a request-created stream on the loopback-but-
// UNAUTHENTICATED gRPC listener. It used the UNCAPPED EventBuffer.Subscribe, so
// any local process could open an unbounded number of packet-drop streams —
// each adding a buffered channel AND expanding the synchronous O(N) per-event
// fan-out — exhausting memory + event-production CPU. The fix routes it through
// the cap-enforcing TrySubscribe (like the REST SSE surface, #4484 L-2) and
// rejects an over-cap stream with codes.ResourceExhausted.

// fillEventBufToCap subscribes via the capped TrySubscribe until the buffer
// rejects, leaving it exactly AT its subscriber cap and returning the live
// subscriptions (the caller closes them).
func fillEventBufToCap(t *testing.T, eb *logging.EventBuffer) []*logging.Subscription {
	t.Helper()
	var subs []*logging.Subscription
	for i := 0; i < 100000; i++ {
		s := eb.TrySubscribe(1)
		if s == nil {
			return subs
		}
		subs = append(subs, s)
	}
	t.Fatal("event buffer never reached its subscriber cap")
	return nil
}

func waitUntil5850(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestMonitorPacketDropRejectsOverCap_5850 pins the #5850 admission cap: with the
// EventBuffer already at its subscriber cap, a further MonitorPacketDrop RPC must
// be REJECTED with ResourceExhausted rather than admitted (which would bypass the
// cap → unbounded fan-out DoS).
//
// FAIL-ON-REVERT: swapping back to the uncapped Subscribe admits the over-cap
// stream — it enters the stream loop and the bounded context returns
// DeadlineExceeded, NOT ResourceExhausted — so this assertion fires RED.
func TestMonitorPacketDropRejectsOverCap_5850(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	subs := fillEventBufToCap(t, eb)
	defer func() {
		for _, s := range subs {
			s.Close()
		}
	}()
	if len(subs) == 0 {
		t.Fatal("expected the buffer to admit at least one subscriber before the cap")
	}

	// REST SSE and gRPC share this EventBuffer admission counter. Exercise the
	// same TrySubscribe path used by SSE before measuring the gRPC refusal.
	beforeRefusals := eb.SubscriberRefusals()
	if sse := eb.TrySubscribe(128); sse != nil {
		sse.Close()
		t.Fatal("precondition: SSE admission unexpectedly succeeded at the subscriber cap")
	}
	if got := eb.SubscriberRefusals(); got != beforeRefusals+1 {
		t.Fatalf("shared subscriber refusals after SSE denial = %d, want %d", got, beforeRefusals+1)
	}

	s := &Server{store: packetDropTestStore(t), eventBuf: eb}
	// Bounded context so a fail-on-revert (admitted → enters the stream loop)
	// returns a fast DeadlineExceeded instead of hanging; with the cap the RPC
	// returns ResourceExhausted BEFORE it ever subscribes, so the timeout is
	// never reached.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.MonitorPacketDrop(&pb.MonitorPacketDropRequest{Node: "local"}, &mockPacketDropStream{ctx: ctx})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over-cap MonitorPacketDrop code = %v, want ResourceExhausted "+
			"(the unauthenticated gRPC stream bypassed the subscriber cap → unbounded fan-out DoS); err=%v",
			status.Code(err), err)
	}
	if got := eb.SubscriberRefusals(); got != beforeRefusals+2 {
		t.Fatalf("shared subscriber refusals after SSE + gRPC denial = %d, want %d", got, beforeRefusals+2)
	}
}

// TestMonitorPacketDropTeardownFreesSlot_5850 proves MonitorPacketDrop's
// `defer sub.Close()` unsubscribes on stream teardown, freeing its cap slot: an
// admitted stream holds a slot (a probe TrySubscribe fails at cap), and once its
// context is cancelled the slot is released (the probe then succeeds).
func TestMonitorPacketDropTeardownFreesSlot_5850(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	subs := fillEventBufToCap(t, eb)
	defer func() {
		for _, s := range subs {
			s.Close()
		}
	}()
	if len(subs) == 0 {
		t.Fatal("cap must be >= 1")
	}
	// Free exactly one slot so the MonitorPacketDrop stream can take it.
	subs[len(subs)-1].Close()
	subs = subs[:len(subs)-1]

	s := &Server{store: packetDropTestStore(t), eventBuf: eb}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- s.MonitorPacketDrop(&pb.MonitorPacketDropRequest{Node: "local"}, &mockPacketDropStream{ctx: ctx})
	}()

	// Wait until the stream has taken the last slot: a probe TrySubscribe fails.
	if !waitUntil5850(2*time.Second, func() bool {
		p := eb.TrySubscribe(1)
		if p == nil {
			return true // at cap → the stream holds its slot
		}
		p.Close() // not full yet — release the probe and keep waiting
		return false
	}) {
		cancel()
		<-errc
		t.Fatal("MonitorPacketDrop never took a subscriber slot")
	}

	// Tear the stream down; its defer sub.Close() must free the slot.
	cancel()
	if err := <-errc; err != context.Canceled {
		t.Fatalf("MonitorPacketDrop teardown err = %v, want context.Canceled", err)
	}
	p := eb.TrySubscribe(1)
	if p == nil {
		t.Fatal("subscriber slot NOT freed after MonitorPacketDrop teardown (defer Close did not unsubscribe)")
	}
	p.Close()
}

// blockedPacketDropSendStream10910 separates the reauth-visible handler context
// from the transport context that owns a blocked Send. The test cancels the
// latter after handler return to model grpc-go tearing down the transport.
type blockedPacketDropSendStream10910 struct {
	handlerCtx context.Context
	sendCtx    context.Context
	started    chan struct{}
	exited     chan struct{}
}

func (m *blockedPacketDropSendStream10910) Send(*pb.MonitorPacketDropResponse) error {
	m.started <- struct{}{}
	<-m.sendCtx.Done()
	close(m.exited)
	return m.sendCtx.Err()
}
func (m *blockedPacketDropSendStream10910) Context() context.Context     { return m.handlerCtx }
func (m *blockedPacketDropSendStream10910) SetHeader(metadata.MD) error  { return nil }
func (m *blockedPacketDropSendStream10910) SendHeader(metadata.MD) error { return nil }
func (m *blockedPacketDropSendStream10910) SetTrailer(metadata.MD)       {}
func (m *blockedPacketDropSendStream10910) SendMsg(any) error            { return nil }
func (m *blockedPacketDropSendStream10910) RecvMsg(any) error            { return nil }

// TestMonitorPacketDropSlowSendReleasesSlotOnTimeoutAndReauth_10910 proves
// that a count=0 stream cannot park forever in Send and retain the shared SSE
// admission slot. Both a per-Send timeout and stream-context cancellation
// return the handler; grpc-go's transport teardown then unblocks the worker,
// which closes the transferred EventBuffer subscription.
func TestMonitorPacketDropSlowSendReleasesSlotOnTimeoutAndReauth_10910(t *testing.T) {
	oldTimeout := monitorPacketDropSendTimeout
	monitorPacketDropSendTimeout = 50 * time.Millisecond
	t.Cleanup(func() { monitorPacketDropSendTimeout = oldTimeout })

	for _, tc := range []struct {
		name       string
		reauth     bool
		wantStatus codes.Code
	}{
		{name: "send timeout", wantStatus: codes.DeadlineExceeded},
		{name: "reauth cancellation", reauth: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eb := logging.NewEventBuffer(16)
			subs := fillEventBufToCap(t, eb)
			if len(subs) == 0 {
				t.Fatal("event buffer admitted no subscriptions")
			}
			subs[len(subs)-1].Close()
			subs = subs[:len(subs)-1]
			defer func() {
				for _, sub := range subs {
					sub.Close()
				}
			}()

			handlerCtx, cancelHandler := context.WithCancel(context.Background())
			defer cancelHandler()
			sendCtx, cancelSend := context.WithCancel(context.Background())
			defer cancelSend()
			stream := &blockedPacketDropSendStream10910{
				handlerCtx: handlerCtx,
				sendCtx:    sendCtx,
				started:    make(chan struct{}, 1),
				exited:     make(chan struct{}),
			}
			s := &Server{store: packetDropTestStore(t), eventBuf: eb}
			done := make(chan error, 1)
			go func() {
				done <- s.MonitorPacketDrop(&pb.MonitorPacketDropRequest{
					Node: "local", Count: 0,
				}, stream)
			}()

			select {
			case <-stream.started:
			case <-time.After(2 * time.Second):
				cancelHandler()
				cancelSend()
				<-done
				t.Fatal("MonitorPacketDrop never entered its blocked Send")
			}
			// This direct TrySubscribe is the same admission operation both
			// REST SSE handlers use. The monitor must own the last slot.
			if probe := eb.TrySubscribe(128); probe != nil {
				probe.Close()
				cancelHandler()
				cancelSend()
				<-done
				t.Fatal("blocked MonitorPacketDrop did not hold its shared admission slot")
			}

			if tc.reauth {
				cancelHandler()
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(2 * time.Second):
				cancelHandler()
				cancelSend()
				<-done
				t.Fatal("blocked Send parked MonitorPacketDrop despite timeout/reauth")
			}
			if tc.reauth {
				if err != context.Canceled {
					t.Fatalf("reauth cancellation returned %v, want context.Canceled", err)
				}
			} else if got := status.Code(err); got != tc.wantStatus {
				t.Fatalf("blocked Send returned code %v, want %v (err=%v)", got, tc.wantStatus, err)
			}

			// A timed-out/re-authenticated Send worker still owns the
			// subscription until transport teardown unblocks that Send.
			if probe := eb.TrySubscribe(128); probe != nil {
				probe.Close()
				t.Fatal("subscriber slot was released while its Send worker remained blocked")
			}
			cancelSend()
			select {
			case <-stream.exited:
			case <-time.After(2 * time.Second):
				t.Fatal("blocked Send worker did not exit after transport cancellation")
			}
			if !waitUntil5850(2*time.Second, func() bool {
				probe := eb.TrySubscribe(128)
				if probe == nil {
					return false
				}
				probe.Close()
				return true
			}) {
				t.Fatal("shared SSE admission did not succeed after Send timeout/reauth teardown")
			}
		})
	}
}
