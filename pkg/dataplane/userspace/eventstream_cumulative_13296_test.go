package userspace

import "testing"

// TestEventStreamCountersSurviveHelperRestart13296 pins D5-02 (#13296):
// daemon-side EventStream counters are monotonic for the life of the daemon,
// not of one helper incarnation. Tearing a helper down must fold the stream's
// counters into the Manager base instead of discarding them, and the
// published status must keep reporting the cumulative totals (non-nil
// EventStream) while no helper is running.
func TestEventStreamCountersSurviveHelperRestart13296(t *testing.T) {
	m := &Manager{}

	es1 := NewEventStream("")
	es1.paused.Store(true)
	es1.ackBatch.Store(13)
	es1.FramesRead.Store(42)
	es1.FramesWritten.Store(7)
	es1.TelemetryGapResyncs.Store(6)
	es1.PendingOverflowDisconnects.Store(9)
	es1.PeerCredRejections.Store(2)
	es1.SeqGaps.Store(2)
	es1.PolicyDenyEvents.Store(17)
	es1.ScreenDropEvents.Store(5)
	es1.UnknownFrameDrops.Store(1)
	m.eventStream = es1

	m.resetAfterHelperGoneLocked()
	if m.eventStream != nil {
		t.Fatal("premise broken: resetAfterHelperGoneLocked left eventStream set")
	}

	// Status published while the helper is down keeps the pre-crash totals.
	st := ProcessStatus{}
	m.recordHelperStatusLocked(&st)
	if st.EventStream == nil {
		t.Fatal("EventStream nil while helper down: xpf_userspace_event_stream_* series vanish during the crash window")
	}
	if st.EventStream.FramesRead != 42 || st.EventStream.PolicyDenyEvents != 17 ||
		st.EventStream.DecodeErrors != 3 || st.EventStream.SeqGaps != 2 {
		t.Fatalf("counters lost on helper teardown: got %+v, want folded FramesRead=42 PolicyDenyEvents=17 DecodeErrors=3 SeqGaps=2", *st.EventStream)
	}
	if st.EventStream.TelemetryGapResyncs != 6 ||
		st.EventStream.PendingOverflowDisconnects != 9 ||
		st.EventStream.PeerCredRejections != 2 {
		t.Fatalf("new monotonic counters lost on teardown: telemetry=%d pending_overflow=%d peer_cred=%d",
			st.EventStream.TelemetryGapResyncs,
			st.EventStream.PendingOverflowDisconnects,
			st.EventStream.PeerCredRejections)
	}
	if st.EventStream.Paused || st.EventStream.EventsSinceAck != 0 {
		t.Fatalf("transient stream state leaked across teardown: Paused=%v EventsSinceAck=%d",
			st.EventStream.Paused, st.EventStream.EventsSinceAck)
	}

	// Replacement helper stream: cumulative = base + new incarnation.
	es2 := NewEventStream("")
	es2.paused.Store(true)
	es2.ackBatch.Store(4)
	es2.FramesRead.Store(10)
	es2.PolicyDenyEvents.Store(1)
	es2.TelemetryGapResyncs.Store(1)
	m.eventStream = es2

	st2 := ProcessStatus{}
	m.recordHelperStatusLocked(&st2)
	if st2.EventStream == nil {
		t.Fatal("EventStream nil with live stream")
	}
	if st2.EventStream.FramesRead != 52 {
		t.Fatalf("FramesRead = %d, want 52 (42 folded base + 10 new)", st2.EventStream.FramesRead)
	}
	if st2.EventStream.PolicyDenyEvents != 18 {
		t.Fatalf("PolicyDenyEvents = %d, want 18 (17 folded base + 1 new)", st2.EventStream.PolicyDenyEvents)
	}
	if st2.EventStream.DecodeErrors != 3 {
		t.Fatalf("DecodeErrors = %d, want 3 (folded base only)", st2.EventStream.DecodeErrors)
	}
	if st2.EventStream.TelemetryGapResyncs != 7 ||
		st2.EventStream.PendingOverflowDisconnects != 9 ||
		st2.EventStream.PeerCredRejections != 2 {
		t.Fatalf("new counters did not accumulate across helper restart: %+v", *st2.EventStream)
	}
	if !st2.EventStream.Paused || st2.EventStream.EventsSinceAck != 4 {
		t.Fatalf("live transient state lost: Paused=%v EventsSinceAck=%d",
			st2.EventStream.Paused, st2.EventStream.EventsSinceAck)
	}

	// A second teardown (intentional stop path) folds again, without
	// double-counting the already-folded first incarnation.
	m.resetAfterHelperGoneLocked()
	st3 := ProcessStatus{}
	m.recordHelperStatusLocked(&st3)
	if st3.EventStream == nil || st3.EventStream.FramesRead != 52 || st3.EventStream.PolicyDenyEvents != 18 {
		t.Fatalf("second fold wrong: %+v, want FramesRead=52 PolicyDenyEvents=18", st3.EventStream)
	}
	if st3.EventStream.Paused || st3.EventStream.EventsSinceAck != 0 {
		t.Fatalf("retired stream transient state leaked: %+v", *st3.EventStream)
	}
	// Folding a torn-down stream again is a no-op (idempotent).
	m.resetAfterHelperGoneLocked()
	st4 := ProcessStatus{}
	m.recordHelperStatusLocked(&st4)
	if st4.EventStream == nil || st4.EventStream.FramesRead != 52 {
		t.Fatalf("repeated fold double-counted: %+v, want FramesRead=52", st4.EventStream)
	}
}
