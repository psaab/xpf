package logging

import (
	"sync/atomic"
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

// #9916 F-132 (serialization half, parent-review follow-up): the barrier cell
// above injects directly into the channel and never calls enqueue, so removing
// the enqueue/retire serialization would still pass it. This cell drives the
// REAL orphan race through enqueue: the producer passes the stopped check and
// pauses (beforeSendFn, holding mu); stop() runs (blocking on mu until the pause
// releases); the producer resumes and its send lands before the worker's drain.
// The accepted line must be handled EXACTLY ONCE — on unfixed code (no mu) stop
// completes during the pause and the resumed send orphans into the dead channel.
func TestAsyncWriterEnqueueSerializedAgainstStop9916(t *testing.T) {
	var handled atomic.Int64
	a := newAsyncAuditWriter(func(auditItem) { handled.Add(1) })

	entered := make(chan struct{})
	release := make(chan struct{})
	var once bool
	a.beforeSendFn = func() {
		if once {
			return
		}
		once = true
		close(entered)
		<-release
	}

	type result struct{ ok bool }
	enqueued := make(chan result, 1)
	go func() {
		enqueued <- result{ok: a.enqueue(auditItem{line: "9916-serialization-probe"})}
	}()

	// Wait until the producer has passed the stopped check and paused mid-enqueue.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("producer never reached the pre-send seam; fixture did not pause")
	}

	// Mechanism pin: the paused producer must HOLD mu across the check-to-send
	// window (TryLock fails). This is what makes stop block below instead of
	// racing past — distinguishing blocking from slow without a sleep (#6827
	// precedent). If the serialization is removed, TryLock succeeds here and
	// this cell goes RED before any timing is involved.
	if a.mu.TryLock() {
		a.mu.Unlock()
		t.Fatalf("paused producer does not hold the retire lock — enqueue/retire not serialized (#9916 F-132)")
	}

	// Retire while the producer is paused. Fixed: stop blocks on mu behind the
	// paused send (proven held above). Unfixed (no mu): stop would complete here
	// and the resumed send would orphan.
	stopped := make(chan struct{})
	go func() {
		a.stop()
		close(stopped)
	}()

	// Resume the producer, then join both. Release-before-join is what keeps
	// this deadlock-free: stop cannot complete until the paused send resumes.
	close(release)
	var res result
	select {
	case res = <-enqueued:
	case <-time.After(5 * time.Second):
		t.Fatalf("paused enqueue never completed")
	}
	if !res.ok {
		t.Fatalf("enqueue returned false; the send passed the pre-stop check and must be accepted")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatalf("stop() never returned")
	}

	// Exactly once: neither orphaned (0) nor double-handled by worker + re-drain (2).
	if got := handled.Load(); got != 1 {
		t.Fatalf("accepted line handled %d times, want exactly 1 (#9916 F-132 serialization)", got)
	}
	if got := a.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d, want 0 — an accepted line must not count as dropped", got)
	}
}
