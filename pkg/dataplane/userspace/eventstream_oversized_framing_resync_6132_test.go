package userspace

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Test_oversized_session_frame_recovers_via_resync_not_replay_loop_6132 pins the
// #6132 fix: a session frame whose DECLARED length exceeds the sanity bound
// (`length > 1024`) — an oversized / framing-corrupt frame — must NOT drop the
// connection forever in a replay loop. Like #6130's undecodable-decode path, the
// frame is PRESENT on the wire, so the helper's Rust replay buffer re-sends it
// verbatim on reconnect with no `has_gap` self-heal barrier; the pre-#6132 bare
// `return` therefore produced a deterministic drop -> reconnect -> replay -> drop
// storm.
//
// The recovery must:
//  1. force a rate-limited full resync (onFullResync fires, SessionSyncResyncs
//     bumps) so the peer is re-baselined from table truth — the corrupt frame is
//     REFUSED, never decoded or applied (security posture preserved); AND
//  2. ADVANCE the watermark PAST the oversized frame and KEEP the connection
//     alive (well-framed sub-path: the declared length is within the discard
//     ceiling, so the reader drains it and re-aligns on the next header), so a
//     following frame is consumed on the SAME connection.
//
// Parent-RED map (target-count 1): revert handleOversizedFrame's call site to the
// pre-#6132 bare `return` (`slog.Warn(...); es.DecodeErrors.Add(1); return`).
// Then:
//   - the connection drops at the oversized frame (seq 2), the recovery frame
//     (seq 3) is never read, and the "recovery frame dispatched" assertion TIMES
//     OUT (RED, assertion failure); AND
//   - lastAppliedSeq stays at the baseline (1) — the "watermark advanced past the
//     hole" assertion (>= 2) goes RED.
//
// The resync / SessionSyncResyncs / DecodeErrors assertions also exercise the new
// path, but the connection-survival + watermark-advance are the behaviours the
// revert breaks.
func Test_oversized_session_frame_recovers_via_resync_not_replay_loop_6132(t *testing.T) {
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

	// seq 2: an oversized session frame — declared length 2000 bytes, above the
	// 1024 sanity bound but within the discard ceiling (well-framed: the payload
	// is really 2000 bytes on the wire, so draining it re-aligns cleanly on the
	// next header). The reader must REFUSE it (never decode) yet keep the
	// connection.
	oversized := make([]byte, 2000)
	if err := writeFrame(conn, EventTypeSessionOpen, 2, oversized); err != nil {
		t.Fatalf("write seq 2 (oversized): %v", err)
	}

	// seq 3: a decodable session frame on the SAME connection. With the fix the
	// connection survives the oversized frame and this is dispatched, proving no
	// reconnect loop and normal recovery. In the reverted (buggy) path the
	// connection was dropped at seq 2 and this is never read.
	if err := writeFrame(conn, EventTypeSessionOpen, 3, good); err != nil {
		t.Fatalf("write seq 3: %v", err)
	}

	select {
	case got := <-dispatched:
		if got != 3 {
			t.Fatalf("recovery frame dispatched seq = %d, want 3 (connection must survive "+
				"the oversized frame — #6132 loop-break)", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery frame after an oversized session frame was not dispatched: the " +
			"connection was dropped (the #6132 drop -> reconnect -> replay loop) instead of " +
			"discarding the oversized frame and advancing past it")
	}

	// Anti-divergence: the oversized frame forced exactly one resync (rate-limited),
	// re-baselining the peer from table truth.
	if !resyncCalled.Load() {
		t.Fatal("oversized session frame did not trigger onFullResync (#6132)")
	}
	if got := es.SessionSyncResyncs.Load(); got != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1", got)
	}
	if got := es.DecodeErrors.Load(); got != 1 {
		t.Fatalf("DecodeErrors = %d, want 1", got)
	}
	// Loop-break: the watermark advanced PAST the oversized seq (2). It is at 3
	// here because the recovery frame was applied; the hard invariant is that it
	// moved past 2, so the helper's replay buffer trims the oversized frame
	// (front.seq <= acked) and never re-sends it.
	if applied := es.lastAppliedSeq.Load(); applied < 2 {
		t.Fatalf("lastAppliedSeq = %d, want >= 2 — the watermark must advance PAST the "+
			"oversized frame so the helper trims it and does not re-send it verbatim "+
			"(the #6132 replay loop)", applied)
	}
}

// Test_persistent_oversized_session_frames_do_not_replay_loop_6132 is the
// persistent-stream variant: a run of oversized session frames (as a
// version-skewed / buggy encoder would emit) must NOT wedge the stream. The
// watermark advances past EVERY oversized frame on ONE connection (no reconnect
// churn), the resync trigger is RATE-LIMITED to a bounded count rather than
// firing once per frame (which would hammer the shared control socket and flood
// the log), and the stream recovers on the next decodable frame.
//
// Parent-RED map (target-count 1): revert the call site to the pre-#6132 bare
// `return`. The connection then drops at the FIRST oversized frame (seq 2); seqs
// 3, 4 and the recovery frame 5 are never read on it, lastAppliedSeq stays at the
// baseline (1), and the recovery assertion times out — all RED.
func Test_persistent_oversized_session_frames_do_not_replay_loop_6132(t *testing.T) {
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
	oversized := make([]byte, 2000) // declared length 2000 > 1024, within ceiling

	// seq 1: decodable baseline.
	if err := writeFrame(conn, EventTypeSessionOpen, 1, good); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if got := <-dispatched; got != 1 {
		t.Fatalf("baseline dispatched seq = %d, want 1", got)
	}

	// seqs 2..4: three back-to-back oversized session frames on ONE connection.
	for seq := uint64(2); seq <= 4; seq++ {
		if err := writeFrame(conn, EventTypeSessionOpen, seq, oversized); err != nil {
			t.Fatalf("write oversized seq %d: %v", seq, err)
		}
	}

	// seq 5: a decodable frame proving the stream recovered on the SAME connection
	// (no reconnect).
	if err := writeFrame(conn, EventTypeSessionOpen, 5, good); err != nil {
		t.Fatalf("write seq 5: %v", err)
	}
	select {
	case got := <-dispatched:
		if got != 5 {
			t.Fatalf("recovery frame dispatched seq = %d, want 5", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not recover after persistent oversized frames: the connection " +
			"was dropped (the #6132 loop) instead of advancing past each oversized frame")
	}

	// Loop-break: the watermark advanced past ALL oversized frames to the recovery
	// frame.
	if applied := es.lastAppliedSeq.Load(); applied < 4 {
		t.Fatalf("lastAppliedSeq = %d, want >= 4 — the watermark must advance past every "+
			"persistently-oversized frame (#6132)", applied)
	}
	// All three oversized frames were accounted.
	if got := es.DecodeErrors.Load(); got != 3 {
		t.Fatalf("DecodeErrors = %d, want 3", got)
	}
	// Bounded, rate-limited resyncs: the three rapid oversized frames fall inside
	// one decodeFailureResyncInterval, so exactly ONE resync fires and the other
	// two are suppressed — NOT one resync per frame (the control-socket hammer the
	// loop would produce).
	if got := resyncs.Load(); got != 1 {
		t.Fatalf("onFullResync fired %d times, want 1 — the resync must be rate-limited so a "+
			"persistently-oversized stream cannot hammer the control socket (#6132)", got)
	}
	if got := es.SessionSyncResyncs.Load(); got != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1", got)
	}
	if got := es.DecodeResyncSuppressed.Load(); got != 2 {
		t.Fatalf("DecodeResyncSuppressed = %d, want 2 (the two rate-limited oversized frames)", got)
	}
}
