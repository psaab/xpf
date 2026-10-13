package userspace

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// waitForConnected spins until the helper connection is accepted or the deadline
// elapses.
func waitForConnected(t *testing.T, es *EventStream) {
	t.Helper()
	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestEventStreamUndecodableSessionFrameForcesResyncAndAdvances_5483_6130 pins
// the corrected fix: a COMPLETE but semantically undecodable SESSION frame must
//
//  1. force a full resync (onFullResync fires, SessionSyncResyncs bumps) — the
//     #5483 anti-divergence guarantee — AND
//  2. ADVANCE the watermark PAST its sequence and KEEP the connection alive
//     (#6130 loop-break), so the helper's replay buffer trims the frame and it
//     is never re-sent verbatim.
//
// The #6130 defect in the naive #5483 fix (b9cb3eb34): it forced the resync but
// WITHHELD the ACK and dropped the connection. Because the frame is PRESENT on
// the wire (not a #2874 gap), the Rust replay buffer re-sends it verbatim on
// every reconnect and `has_gap` never parks a re-baselining barrier for it — a
// deterministic resync/reconnect busy-loop. Advancing the watermark under cover
// of the table-truth resync breaks the loop without reintroducing divergence.
//
// Parent-RED map (target-count 1): revert handleSessionDecodeFailure to NOT
// advance the watermark + have the caller `return` instead of `continue`
// (restoring b9cb3eb34). Then:
//   - line "assert applied advanced past the hole" (lastAppliedSeq >= 2) goes
//     RED: the reverted path leaves lastAppliedSeq stuck at the baseline (1),
//     because the connection is dropped at seq 2 and the recovery frame at seq 3
//     is never read.
//   - the "recovery frame dispatched" assertion also goes RED (seq 3 never
//     reaches onEvent on the dropped connection).
//
// The resync/SessionSyncResyncs/DecodeErrors assertions stay GREEN across the
// revert, so the advance is the single behaviour under test.
func TestEventStreamUndecodableSessionFrameForcesResyncAndAdvances_5483_6130(t *testing.T) {
	sockPath := filepath.Join(shortSockDir9322(t), "test-events.sock")

	es := NewEventStream(sockPath)
	dispatched := make(chan uint64, 4)
	es.SetOnEvent(func(_ uint8, seq uint64, _ SessionDeltaInfo) bool {
		dispatched <- seq
		return true
	})
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream: %v", err)
	}
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	waitForConnected(t, es)

	good := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	// seq 1: decodable baseline — establishes the contiguous watermark at 1.
	if err := writeFrame(conn, EventTypeSessionOpen, 1, good); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if got := <-dispatched; got != 1 {
		t.Fatalf("baseline dispatched seq = %d, want 1", got)
	}

	// seq 2: a COMPLETE session-open frame (full 64-byte payload) with an invalid
	// address family — decodeSessionEvent returns ok=false. Present-but-
	// undecodable, NOT truncated on the wire.
	undecodable := append([]byte(nil), good...)
	undecodable[0] = 7 // invalid AddrFamily (valid: 4/6) -> decode fails
	if err := writeFrame(conn, EventTypeSessionOpen, 2, undecodable); err != nil {
		t.Fatalf("write seq 2 (undecodable): %v", err)
	}

	// seq 3: a decodable session frame on the SAME connection. With the fix the
	// connection survives the undecodable frame and this is dispatched, proving
	// no reconnect loop and normal recovery. In the reverted (buggy) path the
	// connection was dropped at seq 2 and this is never read.
	if err := writeFrame(conn, EventTypeSessionOpen, 3, good); err != nil {
		t.Fatalf("write seq 3: %v", err)
	}

	select {
	case got := <-dispatched:
		if got != 3 {
			t.Fatalf("recovery frame dispatched seq = %d, want 3 (connection must survive "+
				"the undecodable frame — #6130 loop-break)", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery frame after an undecodable session frame was not dispatched: " +
			"the connection was dropped (the #6130 resync/reconnect loop), or the watermark " +
			"was withheld and the frame never advanced")
	}

	// #5483 anti-divergence: the undecodable frame forced exactly one resync.
	if !resyncCalled.Load() {
		t.Fatal("undecodable session frame did not trigger onFullResync (#5483)")
	}
	if got := es.SessionSyncResyncs.Load(); got != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1", got)
	}
	if got := es.DecodeErrors.Load(); got != 1 {
		t.Fatalf("DecodeErrors = %d, want 1", got)
	}
	// #6130 loop-break: the watermark advanced PAST the undecodable seq (2). It is
	// at 3 here because the recovery frame was applied; the hard invariant is that
	// it moved past 2, so the helper's replay buffer trims the undecodable frame
	// (front.seq <= acked) and never re-sends it.
	if applied := es.lastAppliedSeq.Load(); applied < 2 {
		t.Fatalf("lastAppliedSeq = %d, want >= 2 — the watermark must advance PAST the "+
			"present-but-undecodable frame so the helper trims it and does not re-send it "+
			"verbatim (the #6130 resync/reconnect loop)", applied)
	}
}

// TestEventStreamPersistentUndecodableSessionFramesDoNotLoop_6130 is the core
// #6130 regression: a PERSISTENTLY-undecodable session stream (every session
// frame rejected, as under a codec bug / version-skewed helper) must NOT wedge.
// The watermark advances past EVERY undecodable frame on ONE connection (no
// reconnect churn), and the resync trigger is RATE-LIMITED to a bounded count
// rather than firing once per frame (which would hammer the shared control
// socket and flood the log). The stream then recovers on the next decodable
// frame.
//
// Parent-RED map (target-count 1): revert handleSessionDecodeFailure so the
// caller `return`s without advancing (b9cb3eb34). Then the connection drops at
// the FIRST undecodable frame (seq 2); seqs 3, 4 and the recovery frame 5 are
// never read on it, lastAppliedSeq stays at the baseline (1), and the recovery
// assertion times out — all RED. With the fix all four post-baseline frames are
// processed on the one connection.
func TestEventStreamPersistentUndecodableSessionFramesDoNotLoop_6130(t *testing.T) {
	sockPath := filepath.Join(shortSockDir9322(t), "test-events.sock")

	es := NewEventStream(sockPath)
	dispatched := make(chan uint64, 8)
	es.SetOnEvent(func(_ uint8, seq uint64, _ SessionDeltaInfo) bool {
		dispatched <- seq
		return true
	})
	var resyncs atomic.Int64
	es.SetOnFullResync(func() bool {
		resyncs.Add(1)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream: %v", err)
	}
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	waitForConnected(t, es)

	good := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	undecodable := append([]byte(nil), good...)
	undecodable[0] = 7 // invalid AddrFamily -> persistent decode failure

	// seq 1: decodable baseline.
	if err := writeFrame(conn, EventTypeSessionOpen, 1, good); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if got := <-dispatched; got != 1 {
		t.Fatalf("baseline dispatched seq = %d, want 1", got)
	}

	// seqs 2..4: three back-to-back undecodable session frames on ONE connection.
	for seq := uint64(2); seq <= 4; seq++ {
		if err := writeFrame(conn, EventTypeSessionOpen, seq, undecodable); err != nil {
			t.Fatalf("write undecodable seq %d: %v", seq, err)
		}
	}

	// seq 5: a decodable frame proving the stream recovered on the SAME
	// connection (no reconnect).
	if err := writeFrame(conn, EventTypeSessionOpen, 5, good); err != nil {
		t.Fatalf("write seq 5: %v", err)
	}
	select {
	case got := <-dispatched:
		if got != 5 {
			t.Fatalf("recovery frame dispatched seq = %d, want 5", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not recover after persistent undecodable frames: the connection " +
			"was dropped (the #6130 loop) instead of advancing past each undecodable frame")
	}

	// Loop-break: the watermark advanced past ALL undecodable frames to the
	// recovery frame.
	if applied := es.lastAppliedSeq.Load(); applied < 4 {
		t.Fatalf("lastAppliedSeq = %d, want >= 4 — the watermark must advance past every "+
			"persistently-undecodable frame (#6130)", applied)
	}
	// All three undecodable frames were accounted.
	if got := es.DecodeErrors.Load(); got != 3 {
		t.Fatalf("DecodeErrors = %d, want 3", got)
	}
	// Bounded, rate-limited resyncs: the three rapid undecodable frames fall
	// inside one decodeFailureResyncInterval, so exactly ONE resync fires and the
	// other two are suppressed — NOT one resync per frame (the control-socket
	// hammer the loop would produce).
	if got := resyncs.Load(); got != 1 {
		t.Fatalf("onFullResync fired %d times, want 1 — the resync must be rate-limited so a "+
			"persistently-undecodable stream cannot hammer the control socket (#6130)", got)
	}
	if got := es.SessionSyncResyncs.Load(); got != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1", got)
	}
	if got := es.DecodeResyncSuppressed.Load(); got != 2 {
		t.Fatalf("DecodeResyncSuppressed = %d, want 2 (the two rate-limited undecodable frames)", got)
	}
}

// TestEventStreamUndecodableTelemetryFrameStillSkips_5483 pins the SCOPE of the
// fix: the hard sync-break applies to SESSION frames ONLY. A COMPLETE but
// undecodable TELEMETRY (RT_FLOW) frame stays tolerable to skip — it carries no
// HA session state, so it must NOT force a resync. The reader accounts it
// (DecodeErrors + drop counter), advances the watermark past it
// (markDroppedFrameApplied), and keeps the connection alive.
//
// Fail-on-revert guard: if the session hard-break policy were mistakenly widened
// to telemetry frames, onFullResync would fire and the following telemetry frame
// would not be dispatched.
func TestEventStreamUndecodableTelemetryFrameStillSkips_5483(t *testing.T) {
	sockPath := filepath.Join(shortSockDir9322(t), "test-events.sock")

	es := NewEventStream(sockPath)
	gotSeqs := make(chan uint64, 4)
	es.SetOnRawDataplaneEvent(func(seq uint64, _ []byte) { gotSeqs <- seq })
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream: %v", err)
	}
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	waitForConnected(t, es)

	goodTelemetry := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)

	// seq 1: an undecodable telemetry frame (too short to match the frame's
	// event-type gate) — skipped, watermark advanced.
	if err := writeFrame(conn, EventFrameTypePolicyDeny, 1, []byte{4, 6}); err != nil {
		t.Fatalf("write seq 1 (undecodable telemetry): %v", err)
	}
	// seq 2: a valid telemetry frame that must still be dispatched over the
	// still-alive connection.
	if err := writeFrame(conn, EventFrameTypePolicyDeny, 2, goodTelemetry); err != nil {
		t.Fatalf("write seq 2: %v", err)
	}

	select {
	case s := <-gotSeqs:
		if s != 2 {
			t.Fatalf("dispatched telemetry seq = %d, want 2", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid telemetry frame after an undecodable telemetry frame was not dispatched")
	}

	if resyncCalled.Load() {
		t.Fatal("an undecodable TELEMETRY frame must NOT force a resync (#5483 scope: session frames only)")
	}
	if got := es.SessionSyncResyncs.Load(); got != 0 {
		t.Fatalf("SessionSyncResyncs = %d, want 0 for an undecodable telemetry frame", got)
	}
}
