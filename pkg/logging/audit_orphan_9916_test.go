package logging

import (
	"testing"
	"time"
)

// #9916 F-132: a send landing after the worker's final drain must not orphan.
//
// enqueue checks stopped then does a non-blocking send; the worker drains until a
// momentarily-empty default and exits. A send landing after that final drain sits
// in the channel forever: caller saw success, no drop counted, never written.
// The fix serializes check+send against retire (mu) and re-drains in stop(); this
// cell lands a barrier directly in the drain-to-exit window via the afterDrainFn
// seam (mirroring #5062) and asserts it is acknowledged (written or ack-closed),
// not orphaned.
func TestAsyncWriterNoOrphan9916(t *testing.T) {
	a := newAsyncAuditWriter(func(auditItem) {})

	entered := make(chan struct{})
	release := make(chan struct{})
	var once bool
	a.afterDrainFn = func() {
		if once {
			return
		}
		once = true
		close(entered)
		<-release
	}

	stopped := make(chan struct{})
	go func() {
		a.stop()
		close(stopped)
	}()

	// Wait until the worker is paused in the final drain (observed empty, before return).
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("worker never reached the final-drain seam; fixture did not pause")
	}

	// Land a barrier directly in the window (bypasses enqueue/mu, like syncForTest's
	// direct channel send — the mu-bypassing path the re-drain exists for).
	ack := make(chan struct{})
	select {
	case a.items <- auditItem{ack: ack}:
	case <-time.After(5 * time.Second):
		t.Fatalf("could not land the barrier in the window; channel unexpectedly full")
	}

	// Release the worker and join stop().
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatalf("stop() never returned; worker stuck")
	}

	// The barrier must have been acknowledged (handled), not orphaned in a dead channel.
	select {
	case <-ack:
	case <-time.After(2 * time.Second):
		t.Fatalf("barrier orphaned: sent in the drain-to-exit window, never handled, no drop counted (#9916 F-132)")
	}
}
