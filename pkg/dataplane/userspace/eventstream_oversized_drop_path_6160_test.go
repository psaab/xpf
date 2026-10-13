package userspace

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// waitForDisconnected spins until the helper connection has been torn down or the
// deadline elapses. It is the drop-path counterpart to waitForConnected: after
// handleOversizedFrame returns false the reader loop returns, acceptLoop closes
// the connection, and IsConnected flips back to false.
func waitForDisconnected(t *testing.T, es *EventStream) {
	t.Helper()
	dl := time.Now().Add(2 * time.Second)
	for es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("still connected")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// writeOversizedFrameHeader writes a frame header whose DECLARED length field is
// decoupled from the number of actual payload bytes that follow it on the wire.
// The production writeFrame test helper always sets the declared length equal to
// len(payload), so it can only build a WELL-FRAMED frame — it cannot express
// either handleOversizedFrame drop trigger:
//
//   - the > 64KB trigger: a header declaring length >
//     maxDiscardableOversizedFrameBytes with NO payload bytes at all. The reader
//     never drains an over-ceiling length (draining a desynced or pathologically
//     large length could block the reader), so it goes straight to the drop tail
//     (flush advanced ACK, then drop); only the 16-byte header is on the wire.
//   - the failed/short-drain trigger: a header declaring an IN-ceiling length
//     (1024 < len <= 64KB) followed by FEWER real bytes than declared. The reader
//     trusts the in-ceiling length and tries to io.CopyN exactly `declared` bytes,
//     but the drain hits EOF early and errors, falling through to the SAME drop
//     tail.
func writeOversizedFrameHeader(w io.Writer, typ uint8, seq uint64, declaredLen uint32, actual []byte) error {
	var hdr [EventFrameHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], declaredLen)
	hdr[4] = typ
	binary.LittleEndian.PutUint64(hdr[8:16], seq)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(actual) > 0 {
		if _, err := w.Write(actual); err != nil {
			return err
		}
	}
	return nil
}

// readAckThenDrop reads frames from the CLIENT (helper) side of the event socket
// until the connection is dropped (EOF / reset) or the deadline elapses. It
// reports two independent drop-path invariants:
//
//   - sawAck: an Ack frame with seq >= wantAckSeq was observed. This is the
//     advanced-watermark ACK the drop path flushes via sendAckIfNeeded so the Rust
//     helper trims the refused frame from its replay buffer (front.seq <= acked)
//     and NEVER re-sends it verbatim — the loop-break that keeps a genuine framing
//     desync from re-establishing the #6132 drop -> reconnect -> replay storm.
//   - dropped: the connection was actually torn down (handleOversizedFrame
//     returned false -> readLoop returned -> acceptLoop closed the conn). A
//     deadline hit while the socket is still readable reports dropped=false — the
//     connection WRONGLY survived the refused frame.
//
// The ackLoop's 100ms ticker is an independent ACK source, so the loop tolerates a
// leading Ack for the seq-1 baseline and only latches sawAck on seq >= wantAckSeq.
func readAckThenDrop(t *testing.T, conn net.Conn, wantAckSeq uint64, deadline time.Duration) (sawAck, dropped bool) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	for {
		typ, seq, _, err := readFrame(conn)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Deadline hit with the socket still open: the connection was
				// not dropped.
				return sawAck, false
			}
			// EOF / reset: the connection was dropped.
			return sawAck, true
		}
		if typ == EventTypeAck && seq >= wantAckSeq {
			sawAck = true
		}
	}
}

// Test_oversized_session_frame_over_ceiling_drops_and_flushes_ack_6160 covers the
// FIRST drop trigger of handleOversizedFrame (#6159, issue #6160): a declared
// length ABOVE maxDiscardableOversizedFrameBytes (64KB). That length is NOT
// trusted to re-align the byte stream, so the reader must NOT drain it — it flushes
// the advanced ACK and DROPS the connection (returns false -> readLoop returns) to
// re-establish framing cleanly on reconnect. The #6132 regression tests only cover
// the well-framed discard-and-realign branch (return true); this covers the drop
// exit.
//
// Parent-RED map (COVERAGE test — the neutralization inverts an EXISTING invariant):
// change handleOversizedFrame's terminal `return false` to `return true`. The frame
// is then wrongly KEPT: sendAckIfNeeded still flushes ACK(2) but the reader
// `continue`s and blocks on the next (absent) header instead of dropping. The
// `dropped` assertion goes RED ("connection was NOT dropped") — the drop, not the
// ACK, is the behaviour the revert breaks here (the ACK is flushed on both paths).
func Test_oversized_session_frame_over_ceiling_drops_and_flushes_ack_6160(t *testing.T) {
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

	// seq 2: an oversized frame whose DECLARED length is ABOVE the discard ceiling.
	// The reader must not trust that length to re-align the byte stream, so it never
	// drains it — it flushes the advanced ACK and drops the connection. Only the
	// 16-byte header is on the wire (the drop path reads no payload).
	overCeiling := uint32(maxDiscardableOversizedFrameBytes + 1)
	if err := writeOversizedFrameHeader(conn, EventTypeSessionOpen, 2, overCeiling, nil); err != nil {
		t.Fatalf("write seq 2 (over-ceiling oversized): %v", err)
	}

	// The drop path flushes the advanced ACK (seq 2) then drops the connection.
	sawAck, dropped := readAckThenDrop(t, conn, 2, 2*time.Second)
	if !sawAck {
		t.Fatal("over-ceiling oversized frame: the advanced ACK (seq 2) was not flushed on the " +
			"drop path — sendAckIfNeeded must flush so the helper trims the refused frame from its " +
			"replay buffer (front.seq <= acked) and does not re-send it (#6160)")
	}
	if !dropped {
		t.Fatal("over-ceiling oversized frame: the connection was NOT dropped — " +
			"handleOversizedFrame must return false for length > maxDiscardableOversizedFrameBytes " +
			"so readLoop returns and framing is re-established on reconnect (#6160)")
	}

	// The connection lifecycle flipped to disconnected (readLoop returned).
	waitForDisconnected(t, es)

	// Anti-divergence + accounting: the refused frame forced exactly one rate-limited
	// resync (re-baselining the peer from table truth), was counted as a decode
	// error, and the watermark advanced PAST it so a reconnect does NOT replay it.
	if !resyncCalled.Load() {
		t.Fatal("over-ceiling oversized frame did not trigger onFullResync (#6160)")
	}
	if got := es.SessionSyncResyncs.Load(); got != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1", got)
	}
	if got := es.DecodeErrors.Load(); got != 1 {
		t.Fatalf("DecodeErrors = %d, want 1", got)
	}
	if applied := es.lastAppliedSeq.Load(); applied < 2 {
		t.Fatalf("lastAppliedSeq = %d, want >= 2 — the watermark must advance PAST the oversized "+
			"frame so the helper trims it (front.seq <= acked) and never re-sends it verbatim", applied)
	}
	if acked := es.LastAckedSequence(); acked < 2 {
		t.Fatalf("LastAckedSequence = %d, want >= 2 — the drop path must flush the advanced ACK so "+
			"the helper trims the refused frame", acked)
	}
}

// Test_oversized_session_frame_short_drain_drops_and_flushes_ack_6160 covers the
// SECOND drop trigger of handleOversizedFrame (#6159, issue #6160): a declared
// length WITHIN the discard ceiling (1024 < len <= 64KB) whose drain FAILS because
// fewer bytes than declared are actually on the wire. io.CopyN errors (short /
// desynced stream) and the reader falls through to the SAME flush-ACK + drop tail
// as the > 64KB trigger — it must NOT keep the connection just because the length
// looked in-ceiling. The #6132 regression tests always write a genuinely
// well-framed payload (bytes present), so this fall-through is untested.
//
// The client half-closes its write side (CloseWrite) after the short payload so the
// server's drain hits EOF promptly; the client READ half stays open, so the
// advanced ACK the drop path flushes is observable on the wire.
//
// Parent-RED map (COVERAGE test — the neutralization inverts an EXISTING invariant):
// drop the failed-drain fall-through by ignoring io.CopyN's error, e.g.
//
//	if length <= maxDiscardableOversizedFrameBytes {
//	    _, _ = io.CopyN(io.Discard, conn, int64(length))
//	    return true // was: if err == nil { return true }
//	}
//
// The reader then returns true on the short drain and NEVER calls sendAckIfNeeded,
// so the advanced ACK is not flushed synchronously before the (client-close-driven)
// teardown. The `sawAck` assertion goes RED ("advanced ACK was not flushed") — the
// synchronous ACK flush, not the drop (the half-close forces a drop either way), is
// the behaviour the revert breaks here.
func Test_oversized_session_frame_short_drain_drops_and_flushes_ack_6160(t *testing.T) {
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
	uconn := conn.(*net.UnixConn)
	waitForConnected(t, es)

	good := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)

	// seq 1: decodable baseline — establishes the contiguous watermark at 1.
	if err := writeFrame(uconn, EventTypeSessionOpen, 1, good); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if got := <-dispatched; got != 1 {
		t.Fatalf("baseline dispatched seq = %d, want 1", got)
	}

	// seq 2: an IN-ceiling oversized frame (declared 2000: 1024 < 2000 <= 64KB) whose
	// ACTUAL payload is SHORT (100 bytes), then the write half is closed. The reader
	// trusts the in-ceiling length and tries to drain 2000 bytes, but io.CopyN hits
	// EOF after 100 and errors, so it falls through to the drop path: flush the
	// advanced ACK + drop.
	declared := uint32(2000)
	if err := writeOversizedFrameHeader(uconn, EventTypeSessionOpen, 2, declared, make([]byte, 100)); err != nil {
		t.Fatalf("write seq 2 (short-drain oversized): %v", err)
	}
	if err := uconn.CloseWrite(); err != nil {
		t.Fatalf("close write half: %v", err)
	}

	// The drop path flushes the advanced ACK (seq 2) then drops the connection.
	sawAck, dropped := readAckThenDrop(t, conn, 2, 2*time.Second)
	if !sawAck {
		t.Fatal("short-drain oversized frame: the advanced ACK (seq 2) was not flushed on the " +
			"drop path — a failed / short drain must fall through to sendAckIfNeeded so the helper " +
			"trims the refused frame and does not re-send it (#6160)")
	}
	if !dropped {
		t.Fatal("short-drain oversized frame: the connection was NOT dropped — a failed drain must " +
			"return false so readLoop returns and framing is re-established on reconnect (#6160)")
	}

	// The connection lifecycle flipped to disconnected (readLoop returned).
	waitForDisconnected(t, es)

	// Same anti-divergence + accounting invariants as the over-ceiling trigger.
	if !resyncCalled.Load() {
		t.Fatal("short-drain oversized frame did not trigger onFullResync (#6160)")
	}
	if got := es.SessionSyncResyncs.Load(); got != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1", got)
	}
	if got := es.DecodeErrors.Load(); got != 1 {
		t.Fatalf("DecodeErrors = %d, want 1", got)
	}
	if applied := es.lastAppliedSeq.Load(); applied < 2 {
		t.Fatalf("lastAppliedSeq = %d, want >= 2 — the watermark must advance PAST the oversized "+
			"frame so the helper trims it and never re-sends it verbatim", applied)
	}
}
