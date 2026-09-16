package userspace

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// STEP-0 RED cells for psaab/xpf#9915 (F-046, F-123, F-125). Each asserts the
// intended invariant and FAILS on base; kept as regression coverage.

// F-046: a sequence gap first observed on a telemetry frame lives in the GLOBAL
// seq space, so the hole may hold a session open/close. It must trigger the
// session-sync resync path (rate-limited) instead of being silently skipped —
// while the stream stays alive (telemetry remains lossy, no reconnect).
func TestEventStreamTelemetryGapForcesRateLimitedResync_9915(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	gotSeqs := make(chan uint64, 4)
	es.SetOnRawDataplaneEvent(func(seq uint64, _ []byte) {
		gotSeqs <- seq
	})
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)

	if err := writeFrame(conn, EventFrameTypePolicyDeny, 1, payload); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if err := writeFrame(conn, EventFrameTypePolicyDeny, 5, payload); err != nil {
		t.Fatalf("write seq 5: %v", err)
	}

	// Both frames are still dispatched (lossy telemetry, no drop).
	want := map[uint64]bool{1: false, 5: false}
	dl = time.Now().Add(2 * time.Second)
	for {
		select {
		case s := <-gotSeqs:
			want[s] = true
		case <-time.After(time.Until(dl)):
		}
		if want[1] && want[5] {
			break
		}
		if time.Now().After(dl) {
			t.Fatalf("telemetry frames not all dispatched: %v", want)
		}
	}

	// Adjudicated design: the gap forces the session-sync resync path through a
	// DEDICATED telemetry-gap limiter + counter (debounced): routine telemetry
	// loss must neither spend nor starve the shared 2s session-decode budget,
	// and SessionSyncResyncs stays session-only.
	if es.SeqGaps.Load() != 1 {
		t.Fatalf("SeqGaps = %d, want 1", es.SeqGaps.Load())
	}
	if !resyncCalled.Load() {
		t.Fatal("telemetry-frame gap did not trigger the session-sync resync path (F-046)")
	}
	// The dedicated TelemetryGapResyncs counter assert lands at GREEN (the
	// counter does not exist on base); the callback above already proves the
	// trigger behaviorally on both revisions.
	if got := es.SessionSyncResyncs.Load(); got != 0 {
		t.Fatalf("SessionSyncResyncs = %d, want 0: telemetry gaps must not spend the session resync budget (F-046)", got)
	}
	if got := es.telemetryGapResyncs.Load(); got != 1 {
		t.Fatalf("TelemetryGapResyncs = %d, want 1 for a telemetry gap (F-046)", got)
	}
	if !es.IsConnected() {
		t.Fatal("telemetry gap must not drop the stream; resync without reconnect")
	}
	dl = time.Now().Add(2 * time.Second)
	for es.lastAppliedSeq.Load() != 5 {
		if time.Now().After(dl) {
			t.Fatalf("telemetry lastAppliedSeq = %d, want 5", es.lastAppliedSeq.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// F-046 control: contiguous telemetry (no gap) must NOT trigger any resync —
// the gap is the trigger, not the telemetry itself. Passes on base and post-fix.
func TestEventStreamContiguousTelemetryTriggersNoResync_9915(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

	es := NewEventStream(sockPath)
	gotSeqs := make(chan uint64, 8)
	es.SetOnRawDataplaneEvent(func(seq uint64, _ []byte) {
		gotSeqs <- seq
	})
	var resyncCalled atomic.Bool
	es.SetOnFullResync(func() bool {
		resyncCalled.Store(true)
		return true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	es.Start(ctx)
	defer es.Close()

	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	dl := time.Now().Add(2 * time.Second)
	for !es.IsConnected() {
		if time.Now().After(dl) {
			t.Fatal("not connected")
		}
		time.Sleep(10 * time.Millisecond)
	}

	payload := buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000,
		1, 2,
		0, 77,
		0,
	)

	for _, seq := range []uint64{1, 2, 3} {
		if err := writeFrame(conn, EventFrameTypePolicyDeny, seq, payload); err != nil {
			t.Fatalf("write seq %d: %v", seq, err)
		}
	}
	for i := range 3 {
		select {
		case <-gotSeqs:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of 3 contiguous frames dispatched", i)
		}
	}
	// Settle past any async trigger, then assert silence.
	time.Sleep(150 * time.Millisecond)
	if es.SeqGaps.Load() != 0 {
		t.Fatalf("SeqGaps = %d, want 0 for contiguous telemetry", es.SeqGaps.Load())
	}
	if resyncCalled.Load() {
		t.Fatal("contiguous telemetry must not trigger a resync (F-046 control)")
	}
	if got := es.SessionSyncResyncs.Load(); got != 0 {
		t.Fatalf("SessionSyncResyncs = %d, want 0 for contiguous telemetry", got)
	}
}

// F-123: handleOversizedFrame must not advance the watermark to a desync garbage
// seq. Only a strictly contiguous seq (seq == prevSeq+1) keeps the #6160
// loop-break; anything else is payload bytes misread as a header.
func TestOversizedDesyncSeqDoesNotAdvanceWatermark_9915(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

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
	es.Start(ctx)
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
	if err := writeFrame(conn, EventTypeSessionOpen, 1, good); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if got := <-dispatched; got != 1 {
		t.Fatalf("baseline dispatched seq = %d, want 1", got)
	}

	// An over-ceiling "header" whose seq is desync garbage, not a real seq.
	const garbage = uint64(0xDEADBEEFCAFEBABE)
	overCeiling := uint32(maxDiscardableOversizedFrameBytes + 1)
	if err := writeOversizedFrameHeader(conn, EventTypeSessionOpen, garbage, overCeiling, nil); err != nil {
		t.Fatalf("write garbage-seq oversized header: %v", err)
	}
	waitForDisconnected(t, es)

	if !resyncCalled.Load() {
		t.Fatal("CONTROL: oversized frame must still trigger the rate-limited resync")
	}
	if got := es.lastRecvSeq.Load(); got == garbage {
		t.Fatalf("lastRecvSeq advanced to desync garbage %d; the honest watermark must stand (F-123)", got)
	}
	if got := es.lastAppliedSeq.Load(); got == garbage {
		t.Fatalf("lastAppliedSeq advanced to desync garbage %d (F-123)", got)
	}
	if got := es.LastAckedSequence(); got == garbage {
		t.Fatalf("flushed ACK %d is desync garbage; the helper would trim live frames (F-123)", got)
	}
}

// F-123 boundary: strict contiguity — an over-ceiling seq just +2 past the
// baseline must NOT advance. A permissive near-contiguous bound (e.g. <=1024)
// would cumulatively ACK across unknown frames; only seq==prevSeq+1 may move
// the watermark. Fails on base AND under any permissive bound.
func TestOversizedPlusTwoSeqDoesNotAdvanceWatermark_9915(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

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
	es.Start(ctx)
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
	if err := writeFrame(conn, EventTypeSessionOpen, 1, good); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if got := <-dispatched; got != 1 {
		t.Fatalf("baseline dispatched seq = %d, want 1", got)
	}

	// Over-ceiling header at seq 3: contiguous-adjacent is 2, so 3 is refused.
	overCeiling := uint32(maxDiscardableOversizedFrameBytes + 1)
	if err := writeOversizedFrameHeader(conn, EventTypeSessionOpen, 3, overCeiling, nil); err != nil {
		t.Fatalf("write seq-3 oversized header: %v", err)
	}
	waitForDisconnected(t, es)

	if !resyncCalled.Load() {
		t.Fatal("CONTROL: oversized frame must still trigger the rate-limited resync")
	}
	if got := es.lastRecvSeq.Load(); got != 1 {
		t.Fatalf("lastRecvSeq = %d, want 1 (honest baseline); +2 is not contiguous (F-123)", got)
	}
	if got := es.lastAppliedSeq.Load(); got != 1 {
		t.Fatalf("lastAppliedSeq = %d, want 1 (F-123)", got)
	}
	if got := es.LastAckedSequence(); got > 1 {
		t.Fatalf("flushed ACK %d advanced past the honest baseline 1 (F-123)", got)
	}
}

// F-123 control: a strictly contiguous over-ceiling seq keeps the #6160
// loop-break — the watermark advances past it so the drop trims it instead of
// replay-looping. Passes on base and post-fix.
func TestOversizedNearContiguousSeqStillAdvancesWatermark_9915(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test-events.sock")

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
	es.Start(ctx)
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
	if err := writeFrame(conn, EventTypeSessionOpen, 1, good); err != nil {
		t.Fatalf("write seq 1: %v", err)
	}
	if got := <-dispatched; got != 1 {
		t.Fatalf("baseline dispatched seq = %d, want 1", got)
	}

	overCeiling := uint32(maxDiscardableOversizedFrameBytes + 1)
	if err := writeOversizedFrameHeader(conn, EventTypeSessionOpen, 2, overCeiling, nil); err != nil {
		t.Fatalf("write seq-2 oversized header: %v", err)
	}
	waitForDisconnected(t, es)

	if !resyncCalled.Load() {
		t.Fatal("CONTROL: oversized frame must still trigger the rate-limited resync")
	}
	if got := es.lastRecvSeq.Load(); got != 2 {
		t.Fatalf("lastRecvSeq = %d, want 2; a contiguous oversized frame must keep the loop-break (F-123)", got)
	}
	if got := es.lastAppliedSeq.Load(); got != 2 {
		t.Fatalf("lastAppliedSeq = %d, want 2 (F-123)", got)
	}
}

// F-125: pause state and the ack-batch backpressure signal must be observable
// in status. Reflection keeps the cell compiling on base (fields absent → RED)
// and pins behavior post-fix.
func TestEventStreamPauseAndAckBatchObservableInStatus_9915(t *testing.T) {
	st := reflect.TypeOf(EventStreamStatus{})
	_, hasPaused := st.FieldByName("Paused")
	_, hasBatch := st.FieldByName("EventsSinceAck")
	if !hasPaused || !hasBatch {
		t.Fatalf("EventStreamStatus missing Paused=%v EventsSinceAck=%v; "+
			"pause/backpressure state is written and never read (F-125)", hasPaused, hasBatch)
	}

	es := NewEventStream(filepath.Join(t.TempDir(), "x.sock"))
	if err := es.SendPause(); err == nil {
		t.Fatal("SendPause without a connection must error")
	}
	if paused := reflect.ValueOf(es.Status()).FieldByName("Paused").Bool(); paused {
		t.Fatal("a failed SendPause left Paused=true; the state must stay truthful (F-125)")
	}

	// Success half (connected helper): pause/resume round-trips truthfully.
	sdir := t.TempDir()
	ssock := filepath.Join(sdir, "test-events.sock")
	ces := NewEventStream(ssock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ces.Start(ctx)
	defer ces.Close()
	time.Sleep(50 * time.Millisecond)
	conn, err := net.Dial("unix", ssock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	waitForConnected(t, ces)
	if err := ces.SendPause(); err != nil {
		t.Fatalf("SendPause on a live stream: %v", err)
	}
	if paused := reflect.ValueOf(ces.Status()).FieldByName("Paused").Bool(); !paused {
		t.Fatal("SendPause succeeded but Status().Paused is false (F-125)")
	}
	if err := ces.SendResume(); err != nil {
		t.Fatalf("SendResume on a live stream: %v", err)
	}
	if paused := reflect.ValueOf(ces.Status()).FieldByName("Paused").Bool(); paused {
		t.Fatal("SendResume succeeded but Status().Paused is true (F-125)")
	}

	// EventsSinceAck behavior: applied frames advance it (unit-level,
	// deterministic on an unstarted stream with no ackLoop ticker).
	quiet := NewEventStream(filepath.Join(t.TempDir(), "q.sock"))
	quiet.markFrameApplied(11)
	quiet.markFrameApplied(12)
	if got := reflect.ValueOf(quiet.Status()).FieldByName("EventsSinceAck").Uint(); got != 2 {
		t.Fatalf("EventsSinceAck = %d, want 2 after 2 applied frames (F-125)", got)
	}

	// Reset half: the ACK flush zeroes it (connected stream, ackLoop tick).
	ces.markFrameApplied(1001)
	ces.markFrameApplied(1002)
	batchOf := func() uint64 {
		return reflect.ValueOf(ces.Status()).FieldByName("EventsSinceAck").Uint()
	}
	dl := time.Now().Add(2 * time.Second)
	for batchOf() != 0 && time.Now().Before(dl) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := batchOf(); got != 0 {
		t.Fatalf("EventsSinceAck = %d, want 0 after the ACK flush (F-125)", got)
	}
}
