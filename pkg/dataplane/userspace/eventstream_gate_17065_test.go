package userspace

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #17065: the event-stream gate must not pay a full DecodeRawEventRecord
// (392 B / 18 allocs per frame on the reporter's bench) when the record
// will be discarded. These cells pin needRecord selection at the
// dispatch boundary: raw-installed or no-consumer frames validate via
// logging.ValidRawEvent only; a decoded consumer (or a pending queue
// that will need the stored record) still gets a fully decoded record.

func gatePayload17065() []byte {
	return buildDataplaneEventV4Payload(
		6, 1111, 443,
		[4]byte{10, 0, 1, 5}, [4]byte{172, 16, 80, 200},
		[4]byte{172, 16, 80, 8},
		40000, 1, 2, 0, 77, 0,
	)
}

func TestEventStreamGateValidatesWithoutDecode17065(t *testing.T) {
	payload := gatePayload17065()
	if !logging.ValidRawEvent(payload) {
		t.Fatal("gate fixture payload is not ValidRawEvent")
	}
	// Validity gate allocs: the predicate the raw path now pays per frame.
	if got := testing.AllocsPerRun(100, func() {
		if !logging.ValidRawEvent(payload) {
			t.Fatal("ValidRawEvent flipped inside alloc run")
		}
	}); got != 0 {
		t.Fatalf("ValidRawEvent gate allocs = %v, want 0", got)
	}
	// Contrast: the discarded full decode the gate replaces allocates.
	if got := testing.AllocsPerRun(20, func() {
		if _, ok := decodeDataplaneEventPayload(payload); !ok {
			t.Fatal("decodeDataplaneEventPayload rejected gate fixture")
		}
	}); got == 0 {
		t.Fatal("decodeDataplaneEventPayload unexpectedly allocation-free; gate contrast lost")
	}
}

// TestDispatchRawSkipsRecord17065 drives dispatchOrQueueDataplaneFrame
// with the raw callback installed and a zero record (what the gate now
// passes): the raw callback must receive the payload, the decoded
// callback must not fire, and accounting must still run.
func TestDispatchRawSkipsRecord17065(t *testing.T) {
	es := NewEventStream("")
	payload := gatePayload17065()
	var rawSeq uint64
	var rawPayload []byte
	decodedFired := false
	ok := es.dispatchOrQueueDataplaneFrame(
		EventFrameTypePolicyDeny, 42, payload, logging.EventRecord{},
		func(seq uint64, p []byte) { rawSeq, rawPayload = seq, p },
		func(uint64, logging.EventRecord) { decodedFired = true },
	)
	if !ok {
		t.Fatal("dispatchOrQueueDataplaneFrame returned false for raw dispatch")
	}
	if decodedFired {
		t.Fatal("decoded callback fired on the raw path")
	}
	if rawSeq != 42 || len(rawPayload) != len(payload) {
		t.Fatalf("raw callback got seq %d payload %d bytes, want 42/%d", rawSeq, len(rawPayload), len(payload))
	}
	if got := es.PolicyDenyEvents.Load(); got != 1 {
		t.Fatalf("PolicyDenyEvents = %d, want 1 (accounting runs without a decoded record)", got)
	}
}

// TestDispatchQueuedFrameDecodesOnFlush17065: a frame queued while no
// callback is installed keeps its decoded record, and flushing after
// only the decoded callback is installed delivers that record — the
// pending-queue consumer the gate must not starve.
func TestDispatchQueuedFrameDecodesOnFlush17065(t *testing.T) {
	es := NewEventStream("")
	payload := gatePayload17065()
	rec, ok := decodeDataplaneEventPayload(payload)
	if !ok {
		t.Fatal("decodeDataplaneEventPayload rejected gate fixture")
	}
	if !es.dispatchOrQueueDataplaneFrame(EventFrameTypePolicyDeny, 7, payload, rec, nil, nil) {
		t.Fatal("queueing with no callbacks returned false")
	}
	var gotSeq uint64
	var gotRec logging.EventRecord
	es.SetOnDataplaneEvent(func(seq uint64, r logging.EventRecord) {
		gotSeq, gotRec = seq, r
	})
	// SetOnDataplaneEvent flushes pending frames synchronously.
	if gotSeq != 7 {
		t.Fatalf("flushed seq = %d, want 7", gotSeq)
	}
	if gotRec.Type != "POLICY_DENY" || gotRec.PolicyID != 77 {
		t.Fatalf("flushed record = %+v, want POLICY_DENY policy 77", gotRec)
	}
}

// TestReadLoopQueuedFrameDecodesOnFlush17065 is the GATE-LEVEL regression
// for the Rev18096 blocker: drive readLoop itself with NO callbacks
// installed, so the first policy-deny frame validates only and queues.
// Then install ONLY the decoded callback and assert the flushed record
// is the real decoded record, not the zero value the pre-fix gate stored.
func TestReadLoopQueuedFrameDecodesOnFlush17065(t *testing.T) {
	payload := gatePayload17065()
	want, ok := decodeDataplaneEventPayload(payload)
	if !ok {
		t.Fatal("decodeDataplaneEventPayload rejected gate fixture")
	}
	es := NewEventStream("")
	reader, writer := net.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	es.mu.Lock()
	es.conn = reader
	es.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); es.readLoop(ctx) }()
	defer func() { cancel(); _ = reader.Close(); _ = writer.Close(); <-done }()
	if err := writeFrame(writer, EventFrameTypePolicyDeny, 7, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !es.hasPendingCallbackFrames() {
		if time.Now().After(deadline) {
			t.Fatal("readLoop did not queue the no-callback frame")
		}
		time.Sleep(time.Millisecond)
	}
	var gotSeq uint64
	var gotRec logging.EventRecord
	es.SetOnDataplaneEvent(func(seq uint64, r logging.EventRecord) {
		gotSeq, gotRec = seq, r
	})
	if gotSeq != 7 {
		t.Fatalf("flushed seq = %d, want 7", gotSeq)
	}
	if !gotRec.Time.Equal(want.Time) {
		// Both decodes fall back to time.Now() (fixture timestamp 0), so
		// wall-clock equality is not expected; only type/policy pin Time.
		want.Time = gotRec.Time
	}
	if gotRec != want {
		t.Fatalf("flushed record = %+v, want real decoded record %+v", gotRec, want)
	}
	if gotRec.Type != "POLICY_DENY" || gotRec.PolicyID != 77 {
		t.Fatalf("flushed record = %+v, want POLICY_DENY policy 77", gotRec)
	}
}

// BenchmarkEventStreamGate17065 measures the per-frame gate the raw
// path pays after #17065 (validation only). It must report 0 allocs/op.
func BenchmarkEventStreamGate17065(b *testing.B) {
	payload := gatePayload17065()
	b.ReportAllocs()
	for b.Loop() {
		if !logging.ValidRawEvent(payload) {
			b.Fatal("gate fixture stopped validating")
		}
	}
}
