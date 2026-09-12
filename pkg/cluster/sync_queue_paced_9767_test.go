package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9767: a paced enqueue waits for room in a full send queue, where the lossy
// producers drop, and gives up with the same drop accounting when its wait
// passes or the peer disconnects.

func connectedFullQueue9767(t *testing.T) *SessionSync {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
	s.SetConnectedForTesting(true)
	if n := s.FillSendQueueForTesting(); n != cap(s.sendCh) {
		t.Fatalf("setup: filled %d of %d send-queue slots", n, cap(s.sendCh))
	}
	return s
}

func TestPacedQueueWaitsForRoomInsteadOfDropping_9767(t *testing.T) {
	s := connectedFullQueue9767(t)
	go func() {
		for i := 0; i < 2; i++ {
			time.Sleep(50 * time.Millisecond)
			<-s.sendCh
		}
	}()

	if !s.QueueSessionV4Paced(dataplane.SessionKey{}, dataplane.SessionValue{}, 5*time.Second) {
		t.Fatal("#9767: a v4 install into a full queue that the writer drains within the wait was dropped")
	}
	if !s.QueueSessionV6Paced(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, 5*time.Second) {
		t.Fatal("#9767: a v6 install into a full queue that the writer drains within the wait was dropped")
	}
	if got := s.stats.SessionsSent.Load(); got != 2 {
		t.Errorf("SessionsSent = %d, want 2", got)
	}
	if got := s.stats.Errors.Load(); got != 0 {
		t.Errorf("installs that waited and were queued counted %d send errors", got)
	}
	if s.syncBackfillNeeded.Load() {
		t.Error("installs that waited and were queued armed the sweep backfill, which is the drop signal")
	}
}

func TestPacedQueueGivesUpWithTheDropAccountingAfterItsWait_9767(t *testing.T) {
	s := connectedFullQueue9767(t)
	const wait = 40 * time.Millisecond
	start := time.Now()
	if s.QueueSessionV4Paced(dataplane.SessionKey{}, dataplane.SessionValue{}, wait) {
		t.Fatal("an install into a queue that nothing drains reported success")
	}
	if waited := time.Since(start); waited < wait {
		t.Errorf("gave up after %v, before its %v wait", waited, wait)
	}
	if got := s.stats.Errors.Load(); got != 1 {
		t.Errorf("send errors = %d, want 1, as a lossy producer's drop counts", got)
	}
	if !s.syncBackfillNeeded.Load() {
		t.Error("the dropped install did not arm the sweep backfill")
	}
}

func TestPacedQueueStopsWaitingWhenThePeerDisconnects_9767(t *testing.T) {
	never := NewSessionSync(":0", "10.0.0.2:4785", nil)
	start := time.Now()
	if never.QueueSessionV4Paced(dataplane.SessionKey{}, dataplane.SessionValue{}, 5*time.Second) {
		t.Fatal("an install to a peer that was never connected reported success")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("waited %v on a peer that was never connected", waited)
	}

	s := connectedFullQueue9767(t)
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.SetConnectedForTesting(false)
	}()
	start = time.Now()
	if s.QueueSessionV6Paced(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, 5*time.Second) {
		t.Fatal("an install whose peer disconnected during the wait reported success")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("kept waiting %v after the peer disconnected", waited)
	}
}
