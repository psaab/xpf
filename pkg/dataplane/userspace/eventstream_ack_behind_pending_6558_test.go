// #6558: the event stream ACKed past queued-but-unapplied session deltas,
// defeating the withhold-ACK replay contract.
//
// The issue states the mechanism as "ACKs on receipt/enqueue". That is NOT what
// the code did, and it matters, because the fix for the stated mechanism would
// have been a no-op. The normal path is strictly receive -> apply -> ACK:
// dispatchOrQueueSessionFrame only calls markFrameApplied AFTER onEvent returns
// true, and a callback returning false enqueues without marking. Those halves
// are already pinned (TestEventStreamSessionCallbackFalseWithholdsAck and its
// FullResync/dataplane twins).
//
// The real window is the INTERACTION nobody tested. dispatchOrQueue* returns
// TRUE after a successful enqueue, so the reader keeps reading with frames
// still queued unapplied. Five refusal paths then advanced lastAppliedSeq with
// no pending-queue check at all:
//
//	markDroppedFrameApplied   telemetry payload/type mismatch, decode failure,
//	                          unknown frame type (#1394)
//	handleSessionDecodeFailure  undecodable session frame (#5483/#6130)
//	handleOversizedFrame        oversized / framing-desync (#6132/#6160) — and
//	                            this one FLUSHES the ACK immediately
//
// So: enqueue delta N unapplied -> receive refused frame N+1 -> lastAppliedSeq
// jumps to N+1 -> the cumulative ACK names N+1. The helper trims its replay
// buffer on `front.seq <= acked` (event_stream/control.rs), and the daemon
// CLEARS its pending queue on the next accept (clearPendingCallbackFrames), so
// delta N is gone from both sides. The oversized path does both in one shot:
// flush the ACK, then drop the connection.
//
// Each of the three refusal fixes reasoned correctly about the REFUSED FRAME
// ITSELF and none reasoned about frames still queued BEHIND it — the pending
// queue did not exist when the first was written. docs/session-sync-
// architecture.md already names this exact pathology for the sibling #5483
// path ("a later lossy telemetry frame would then advance the cumulative ACK
// past the unapplied session seq ... the standby diverged with no recovery");
// #6558 is the same pathology reached through the pending-queue door.
//
// FAIL-ON-REVERT: restore the bare `es.markFrameApplied(seq)` in
// applyRefusedFrameInOrder (i.e. drop the hasPendingCallbackFrames branch) and
// every case below goes RED — the ACK names the refused frame while the delta
// behind it is still unapplied.
package userspace

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// dialEventStream starts a stream with NO onEvent wired and returns a connected
// client. No callback is the state that makes the FIRST session frame queue,
// which is the precondition every case here needs.
func dialEventStream(t *testing.T) (*EventStream, net.Conn) {
	t.Helper()
	sockPath := filepath.Join(shortSockDir9322(t), "test-events.sock")
	es := NewEventStream(sockPath)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream: %v", err)
	}
	t.Cleanup(func() { es.Close() })

	deadline := time.Now().Add(2 * time.Second)
	var conn net.Conn
	for {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial %s: %v", sockPath, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() { conn.Close() })

	for !es.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("event stream did not become connected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return es, conn
}

func sessionOpenPayload6558() []byte {
	return buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
}

// waitAppliedAtLeast gives the reader goroutine time to consume a frame without
// asserting a fixed sleep. It polls the RECEIVE watermark, which every refusal
// path advances immediately (that is the loop-break, and it is deliberately NOT
// what this file is asserting on) — so it is a "the reader has processed the
// frame" signal that is independent of the ACK property under test.
func waitRecvAtLeast(t *testing.T, es *EventStream, seq uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for es.lastRecvSeq.Load() < seq {
		if time.Now().After(deadline) {
			t.Fatalf("reader never consumed seq %d (lastRecvSeq = %d)", seq, es.lastRecvSeq.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRefusedFrameDoesNotAckPastQueuedDelta6558 is the core probe, run over
// every refusal path that reaches the watermark.
func TestRefusedFrameDoesNotAckPastQueuedDelta6558(t *testing.T) {
	cases := []struct {
		name string
		// write emits the refused frame at seq 2 on an already-non-empty queue.
		write func(t *testing.T, conn net.Conn)
	}{
		{
			// #1394 default arm: an unknown frame type.
			name: "unknown-frame-type",
			write: func(t *testing.T, conn net.Conn) {
				if err := writeFrame(conn, 250, 2, nil); err != nil {
					t.Fatalf("write unknown frame: %v", err)
				}
			},
		},
		{
			// Telemetry payload whose type-byte does not match the frame.
			name: "dataplane-payload-mismatch",
			write: func(t *testing.T, conn net.Conn) {
				if err := writeFrame(conn, EventFrameTypePolicyDeny, 2, []byte{0xFF}); err != nil {
					t.Fatalf("write mismatched dataplane frame: %v", err)
				}
			},
		},
		{
			// #5483/#6130: a COMPLETE but undecodable session frame.
			name: "undecodable-session-frame",
			write: func(t *testing.T, conn net.Conn) {
				if err := writeFrame(conn, EventTypeSessionOpen, 2, []byte{0x01, 0x02}); err != nil {
					t.Fatalf("write undecodable session frame: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			es, conn := dialEventStream(t)

			// Seq 1: a real session delta with NO callback wired, so it is
			// enqueued UNAPPLIED and the ACK is correctly withheld.
			if err := writeFrame(conn, EventTypeSessionOpen, 1, sessionOpenPayload6558()); err != nil {
				t.Fatalf("write session delta: %v", err)
			}
			waitRecvAtLeast(t, es, 1)
			if applied := es.lastAppliedSeq.Load(); applied != 0 {
				t.Fatalf("precondition broken: lastAppliedSeq = %d after queuing an "+
					"unapplied delta, want 0 — the fixture is not exercising the "+
					"withhold-ACK path at all", applied)
			}

			// Seq 2: the refused frame, arriving BEHIND the queued delta.
			tc.write(t, conn)
			waitRecvAtLeast(t, es, 2)

			if applied := es.lastAppliedSeq.Load(); applied >= 2 {
				t.Fatalf("lastAppliedSeq = %d after a refused frame at seq 2 landed behind "+
					"an UNAPPLIED delta at seq 1. The cumulative ACK now claims seq 1 is "+
					"durable: the helper trims its replay buffer on front.seq <= acked and "+
					"the daemon clears its pending queue on the next accept, so that delta "+
					"is unrecoverable on both sides (#6558).", applied)
			}

			// And no ACK may reach the wire either — the watermark is the
			// mechanism, the ACK frame is the observable consequence.
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if typ, seq, _, err := readFrame(conn); err == nil {
				t.Fatalf("stream sent an ACK (type %d seq %d) while seq 1 was still "+
					"queued unapplied", typ, seq)
			}

			// Now wire the callback. The queue drains IN ORDER — the delta
			// first, then the refused frame's marker — and only then may the
			// ACK reach 2.
			es.SetOnEvent(func(uint8, uint64, SessionDeltaInfo) bool { return true })
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			typ, seq, _, err := readFrame(conn)
			if err != nil {
				t.Fatalf("no ACK after the callback was wired: %v (the refused frame's "+
					"place in the queue must still be released once the frames ahead of "+
					"it apply, or the stream wedges)", err)
			}
			if typ != EventTypeAck {
				t.Fatalf("frame after callback wired = type %d, want ACK", typ)
			}
			if seq != 2 {
				t.Fatalf("ACK seq = %d, want 2 (both the applied delta and the refused "+
					"frame's marker must have drained)", seq)
			}
		})
	}
}

// TestRefusedFrameStillAcksWithAnEmptyQueue6558 is the negative control.
//
// The in-order rule must NOT become "never advance on a refusal". #6130 and
// #6132 advance past a refused frame ON PURPOSE: without it the helper replays
// a frame that will only be refused again, which is a wedge. With an empty
// queue there is nothing to be behind, so the advance is immediate — exactly
// the pre-#6558 behaviour, and exactly what TestEventStreamUnknownFrameDropsAndAcks
// and TestEventStreamMalformedDataplaneEventDropsAndAcks already assert.
//
// This restates it against the NEW code path so a fix that over-corrected
// (queueing the marker unconditionally, where nothing would ever drain it
// without a callback) is caught here rather than in a wedged cluster.
func TestRefusedFrameStillAcksWithAnEmptyQueue6558(t *testing.T) {
	es, conn := dialEventStream(t)

	if err := writeFrame(conn, 250, 7, nil); err != nil {
		t.Fatalf("write unknown frame: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, seq, _, err := readFrame(conn)
	if err != nil {
		t.Fatalf("no ACK for a refused frame on an EMPTY queue: %v — the loop-break "+
			"was over-corrected; the helper will replay a frame that can only be "+
			"refused again (#6130 wedge)", err)
	}
	if typ != EventTypeAck || seq != 7 {
		t.Fatalf("ack = type %d seq %d, want ACK seq 7", typ, seq)
	}
	if got := es.UnknownFrameDrops.Load(); got != 1 {
		t.Fatalf("UnknownFrameDrops = %d, want 1", got)
	}
}

// TestMarkFrameAppliedIsMonotonic6558 covers the secondary defect the same
// window produced.
//
// markFrameApplied was a bare Store. Once a refusal path had jumped
// lastAppliedSeq ahead, the later IN-ORDER flush of the queued frame behind it
// would REWIND the watermark — and a rewound watermark is silently swallowed by
// sendAckIfNeeded's `applied <= acked` guard (no ACK is ever sent again until
// the stream passes the old high-water mark) and can regress SendDrainRequest's
// fence, which reads lastAppliedSeq directly.
//
// The in-order rule makes the rewind unreachable through the readLoop, so this
// asserts the invariant at the function rather than through a scenario the fix
// has just eliminated: a probe that can only be driven via the repaired path
// would test the repair, not the property.
func TestMarkFrameAppliedIsMonotonic6558(t *testing.T) {
	es := NewEventStream(filepath.Join(t.TempDir(), "unused.sock"))

	es.markFrameApplied(10)
	if got := es.lastAppliedSeq.Load(); got != 10 {
		t.Fatalf("lastAppliedSeq = %d, want 10", got)
	}
	es.markFrameApplied(4)
	if got := es.lastAppliedSeq.Load(); got != 10 {
		t.Fatalf("lastAppliedSeq = %d after applying an EARLIER seq, want it to stay 10. "+
			"A rewound applied-watermark is swallowed by sendAckIfNeeded's "+
			"`applied <= acked` guard and can regress SendDrainRequest's fence (#6558).", got)
	}
	es.markFrameApplied(11)
	if got := es.lastAppliedSeq.Load(); got != 11 {
		t.Fatalf("lastAppliedSeq = %d, want 11 — monotonicity must not block real progress", got)
	}
	// ackBatch counts frames handled, not watermark movement: it must advance
	// on all three calls, including the one the monotonic guard ignored.
	if got := es.ackBatch.Load(); got != 3 {
		t.Fatalf("ackBatch = %d, want 3 (the guard must not change ACK batching)", got)
	}
}

// TestDroppedMarkerTypeIsNotALiveFrameType6558 arms the precondition the
// marker's handling rests on.
//
// A dropped marker is dispatched by its `dropped` flag, which the flush checks
// BEFORE the type switch — so its typ is nominally irrelevant. That is only
// true while pendingDroppedMarkerType is outside the allocated protocol range:
// if 0 were ever handed to a real frame type, a marker that reached the switch
// (through a future refactor, or through the `default:` arm this branch
// currently shadows) would be dispatched as real traffic against a payload
// that does not exist.
//
// Cheap, and it is the kind of coupling that breaks silently: the protocol
// constants live in protocol_events.go and nothing there points back here.
func TestDroppedMarkerTypeIsNotALiveFrameType6558(t *testing.T) {
	live := map[uint8]string{
		EventTypeSessionOpen:        "EventTypeSessionOpen",
		EventTypeSessionClose:       "EventTypeSessionClose",
		EventTypeSessionUpdate:      "EventTypeSessionUpdate",
		EventTypeAck:                "EventTypeAck",
		EventTypePause:              "EventTypePause",
		EventTypeResume:             "EventTypeResume",
		EventTypeDrainRequest:       "EventTypeDrainRequest",
		EventTypeDrainComplete:      "EventTypeDrainComplete",
		EventTypeFullResync:         "EventTypeFullResync",
		EventTypeKeepalive:          "EventTypeKeepalive",
		EventFrameTypePolicyDeny:    "EventFrameTypePolicyDeny",
		EventFrameTypeScreenDrop:    "EventFrameTypeScreenDrop",
		EventFrameTypeFilterLog:     "EventFrameTypeFilterLog",
		EventFrameTypeSessionClose:  "EventFrameTypeSessionClose",
		EventFrameTypeSessionCreate: "EventFrameTypeSessionCreate",
	}
	if name, ok := live[pendingDroppedMarkerType]; ok {
		t.Fatalf("pendingDroppedMarkerType (%d) collides with the live frame type %s — "+
			"a #6558 dropped marker reaching the flush's type switch would be dispatched "+
			"as real traffic against a payload it does not carry", pendingDroppedMarkerType, name)
	}
}
