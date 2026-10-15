package userspace

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// #13238 (D5-09): a refused session frame (undecodable or oversized) that
// arrives across a sequence gap (seq > prevSeq+1) must be treated as the
// #2874 gap it is — SeqGaps counted, unconditional full resync, connection
// dropped, and the cumulative ACK must NOT advance past the missing seqs.
// Pre-fix, handleSessionDecodeFailure / handleOversizedFrame ran before the
// gap check, counted no gap, and — when a decode failure inside the 2s
// rate-limit window suppressed the resync — silently ACKed past the hole.
//
// Parent-RED map: on pristine master both tests fail — SeqGaps stays 0,
// SessionSyncResyncs stays 0, DecodeResyncSuppressed becomes 1,
// lastAppliedSeq jumps to 10, and the connection survives.

func gap13238Setup(t *testing.T) (*EventStream, net.Conn, chan uint64, *atomic.Int64, []byte) {
	t.Helper()
	sockPath := filepath.Join(shortSockDir9322(t), "test-events.sock")
	es := NewEventStream(sockPath)
	dispatched := make(chan uint64, 4)
	es.SetOnEvent(func(_ uint8, seq uint64, _ SessionDeltaInfo) bool {
		dispatched <- seq
		return true
	})
	var resyncCalls atomic.Int64
	es.SetOnFullResync(func() bool {
		resyncCalls.Add(1)
		return true
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream: %v", err)
	}
	t.Cleanup(es.Close)
	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	waitForConnected(t, es)
	good := buildSessionOpenV4Payload(
		6, 1000, 80,
		[4]byte{10, 0, 1, 1}, [4]byte{10, 0, 2, 1},
		[4]byte{}, [4]byte{},
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		[6]byte{}, [6]byte{}, [4]byte{},
	)
	if err := writeFrame(conn, EventTypeSessionOpen, 1, good); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if got := <-dispatched; got != 1 {
		t.Fatalf("baseline dispatched seq = %d, want 1", got)
	}
	// Prime the decode-failure rate limiter as if a malformed frame fired a
	// resync moments ago — the exact window in which the gap was masked.
	es.lastDecodeResyncNanos.Store(time.Now().UnixNano())
	return es, conn, dispatched, &resyncCalls, good
}

func assertGap13238(t *testing.T, es *EventStream, resyncCalls *atomic.Int64) {
	t.Helper()
	waitForDisconnected(t, es)
	if got := es.SeqGaps.Load(); got != 1 {
		t.Fatalf("SeqGaps = %d, want 1 — gap across a refused frame must be counted (#13238)", got)
	}
	if got := es.SessionSyncResyncs.Load(); got != 1 {
		t.Fatalf("SessionSyncResyncs = %d, want 1 — gap must force an unconditional resync, not the rate-limited one (#13238)", got)
	}
	if got := resyncCalls.Load(); got != 1 {
		t.Fatalf("onFullResync calls = %d, want 1 (#13238)", got)
	}
	if got := es.DecodeResyncSuppressed.Load(); got != 0 {
		t.Fatalf("DecodeResyncSuppressed = %d, want 0 — the gap path must not be rate-limited (#13238)", got)
	}
	if got := es.lastAppliedSeq.Load(); got != 1 {
		t.Fatalf("lastAppliedSeq = %d, want 1 — ACK must not advance past missing seqs 2..9 (#13238)", got)
	}
}

func TestEventStreamUndecodableFrameAcrossGapIsGap_13238(t *testing.T) {
	es, conn, _, resyncCalls, good := gap13238Setup(t)
	undecodable := append([]byte(nil), good...)
	undecodable[0] = 7 // invalid AddrFamily -> decode fails
	if err := writeFrame(conn, EventTypeSessionOpen, 10, undecodable); err != nil {
		t.Fatalf("write seq 10 (undecodable, gap 2..9): %v", err)
	}
	assertGap13238(t, es, resyncCalls)
}

func TestEventStreamOversizedFrameAcrossGapIsGap_13238(t *testing.T) {
	es, conn, _, resyncCalls, _ := gap13238Setup(t)
	oversized := make([]byte, 2000) // >1024 sanity bound, within discard ceiling
	if err := writeFrame(conn, EventTypeSessionOpen, 10, oversized); err != nil {
		t.Fatalf("write seq 10 (oversized, gap 2..9): %v", err)
	}
	assertGap13238(t, es, resyncCalls)
}

// Over-ceiling headers may be desync garbage, so their sequence number must
// not bypass the existing rate-limited oversized-frame resync policy.
func TestEventStreamOverCeilingGarbageHeaderDoesNotTriggerSessionGap_13238(t *testing.T) {
	es, conn, _, resyncCalls, _ := gap13238Setup(t)
	declaredLength := uint32(maxDiscardableOversizedFrameBytes + 1)
	if err := writeOversizedFrameHeader(conn, EventTypeSessionOpen, 10, declaredLength, nil); err != nil {
		t.Fatalf("write over-ceiling garbage header: %v", err)
	}
	waitForDisconnected(t, es)
	if got := es.SeqGaps.Load(); got != 0 {
		t.Fatalf("SeqGaps = %d, want 0 for untrusted over-ceiling header", got)
	}
	if got := es.SessionSyncResyncs.Load(); got != 0 {
		t.Fatalf("SessionSyncResyncs = %d, want 0 for untrusted over-ceiling header", got)
	}
	if got := resyncCalls.Load(); got != 0 {
		t.Fatalf("onFullResync calls = %d, want 0 for untrusted over-ceiling header", got)
	}
	if got := es.DecodeResyncSuppressed.Load(); got != 1 {
		t.Fatalf("DecodeResyncSuppressed = %d, want 1 for rate-limited oversized resync", got)
	}
	if got := es.lastAppliedSeq.Load(); got != 1 {
		t.Fatalf("lastAppliedSeq = %d, want 1; untrusted sequence must not advance ACK", got)
	}
}
