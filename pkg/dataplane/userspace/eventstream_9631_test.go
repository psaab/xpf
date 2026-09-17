package userspace

import (
	"testing"
)

// TestPendingQueueFillsWhenCallbackNeverReady9631 pins the #9631 storm
// mechanism at the EventStream layer: a session callback that stays false
// (what handleEventStreamDelta did for every delta while the HA sync peer
// was down) queues one pending frame per delta, and the 4097th delta fails
// the 4096 cap — the caller then backs off 100ms and closes the stream to
// force a replay, which replays, refills and closes again for the whole
// outage. This cell stays green before and after the fix; it documents why
// the daemon must not answer false for a whole outage.
func TestPendingQueueFillsWhenCallbackNeverReady9631(t *testing.T) {
	es := NewEventStream("")
	es.SetOnEvent(func(eventType uint8, seq uint64, delta SessionDeltaInfo) bool {
		return false // simulate peer-down not-ready on every delta
	})
	for seq := uint64(1); seq <= pendingCallbackFramesLimit; seq++ {
		if !es.dispatchOrQueueSessionFrame(EventTypeSessionOpen, seq, SessionDeltaInfo{}) {
			t.Fatalf("seq %d/%d: expected queueing below the cap", seq, pendingCallbackFramesLimit)
		}
	}
	es.pendingMu.Lock()
	queued := len(es.pendingCallbackFrames)
	es.pendingMu.Unlock()
	if queued != pendingCallbackFramesLimit {
		t.Fatalf("queued frames = %d, want %d", queued, pendingCallbackFramesLimit)
	}
	if es.dispatchOrQueueSessionFrame(EventTypeSessionOpen, pendingCallbackFramesLimit+1, SessionDeltaInfo{}) {
		t.Fatal("4097th delta with a never-ready callback must fail the queue cap (close-to-replay)")
	}
}

// TestAlwaysReadyCallbackNeverEnqueues9631 pins the #9631 composition at the
// EventStream layer: a callback that always answers handled (what the daemon
// does for peer-down deltas after the fix) never enqueues a pending frame, so
// the 4096 cap is unreachable and no close-to-replay fires however many
// deltas arrive. Green before and after; it proves true ⇒ no queue growth.
func TestAlwaysReadyCallbackNeverEnqueues9631(t *testing.T) {
	es := NewEventStream("")
	es.SetOnEvent(func(eventType uint8, seq uint64, delta SessionDeltaInfo) bool {
		return true // handled: the #9631 peer-down answer for deltas
	})
	const frames = 5000
	for seq := range frames {
		if !es.dispatchOrQueueSessionFrame(EventTypeSessionOpen, uint64(seq+1), SessionDeltaInfo{}) {
			t.Fatalf("seq %d/%d: a handled delta must never fail the queue", seq+1, frames)
		}
	}
	es.pendingMu.Lock()
	queued := len(es.pendingCallbackFrames)
	es.pendingMu.Unlock()
	if queued != 0 {
		t.Fatalf("queued frames = %d, want 0 (handled deltas bypass the queue)", queued)
	}
	if got := es.lastAppliedSeq.Load(); got != frames {
		t.Fatalf("lastAppliedSeq = %d, want %d (every handled frame advances the watermark)", got, frames)
	}
}
