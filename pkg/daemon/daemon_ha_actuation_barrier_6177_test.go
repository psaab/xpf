package daemon

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file covers the failover fence barrier's OWN arm/disarm/wait/timeout
// bookkeeping (#6177). The sibling daemon_ha_actuation_6371_test.go drives the
// barrier through handleClusterEvent and pins the VERDICT the demotion
// delivers; nothing pinned the barrier's lifecycle itself — the timeout leg,
// the disarm leg, the map cleanup, and the request-identity rules that keep one
// transfer-out cycle from disturbing another.
//
// The barrier is a self-contained mutex+map on Daemon, so these drive it
// directly: a bare Daemon reaches every branch and cannot pass for an unrelated
// reason.

// newBarrierDaemon builds the minimum Daemon the barrier API needs.
func newBarrierDaemon(timeout time.Duration) *Daemon {
	return &Daemon{
		failoverActuateWait:    make(map[failoverActuationKey]*failoverActuation),
		failoverActuateTimeout: timeout,
	}
}

// armedBarriers reports how many barriers are still held. Every arm must be
// released by exactly one wait or disarm, so a test that finishes with a
// non-zero count has leaked a channel no one will ever close or read.
func armedBarriers(d *Daemon) int {
	d.failoverActuateMu.Lock()
	defer d.failoverActuateMu.Unlock()
	return len(d.failoverActuateWait)
}

// errFenceRejected stands in for the dataplane refusing the demotion write —
// the verdict signalFailoverActuationFailed carries.
var errFenceRejected = errors.New("rg_active clear rejected")

// TestFailoverActuationBarrier_TimeoutReportsFailureAndDropsBarrier covers the
// leg the #6371 tests do not reach: a demotion event that never arrives. The
// wait must expire with a NON-nil verdict (a nil would ack the transfer as
// applied and let the peer promote against a node that never demoted), and it
// must leave nothing behind — a stranded barrier would be closed later by a
// demotion event with no reader.
//
// Fail-on-revert: return nil from the `case <-timer.C` branch of
// waitFailoverActuated and the first assertion reds; drop the
// disarmFailoverActuation call in that branch and the leak assertion reds.
func TestFailoverActuationBarrier_TimeoutReportsFailureAndDropsBarrier(t *testing.T) {
	d := newBarrierDaemon(40 * time.Millisecond)
	d.armFailoverActuation(1, 7)

	start := time.Now()
	err := d.waitFailoverActuated(1, 7)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("waitFailoverActuated returned nil for a demotion that never actuated: " +
			"the applied-ack would tell the peer to promote against a node that never demoted")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("verdict = %v, want the bounded-wait timeout", err)
	}
	// Positive control: the wait really parked on the barrier. An instant
	// return would mean the barrier was never armed and the assertion above
	// passed for the wrong reason.
	if elapsed < 40*time.Millisecond {
		t.Fatalf("wait returned after %v, want at least the %v timeout", elapsed, 40*time.Millisecond)
	}
	if n := armedBarriers(d); n != 0 {
		t.Fatalf("armed barriers after an expired wait = %d, want 0: the expiry must drop "+
			"the stranded barrier so a late demotion event has nothing to close", n)
	}
	// A late demotion event for the RG must be a harmless no-op, not a close
	// of an already-abandoned channel.
	d.signalFailoverActuated(1)
	if n := armedBarriers(d); n != 0 {
		t.Fatalf("armed barriers after a late actuation = %d, want 0", n)
	}
}

// TestFailoverActuationBarrier_ExpiredRequestKeepsNewerRequestArmed is the
// #6177 item-2 regression. An expired wait disarms — and before the barrier map
// was keyed by request, that disarm deleted the RG's slot outright. A newer
// transfer-out for the same RG that had already armed lost its barrier, so its
// wait found nothing, returned nil, and the node acked APPLIED for a demotion
// it had not performed: the two-owner window #5640 exists to prevent.
//
// Fail-on-revert: key failoverActuateWait by rgID alone (or drop reqID from the
// key), and the newer request's barrier is deleted by the older one's expiry —
// the wait below returns nil and this reds on a clean assertion.
func TestFailoverActuationBarrier_ExpiredRequestKeepsNewerRequestArmed(t *testing.T) {
	d := newBarrierDaemon(40 * time.Millisecond)

	d.armFailoverActuation(1, 1) // older cycle, its demotion event never lands
	expired := make(chan error, 1)
	go func() { expired <- d.waitFailoverActuated(1, 1) }()

	d.armFailoverActuation(1, 2) // newer cycle for the same RG

	select {
	case err := <-expired:
		if err == nil {
			t.Fatal("the older request's wait must expire with a failure verdict")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the older request's wait never expired")
	}

	// The newer request must still be armed: its demotion verdict has to reach
	// its waiter. Resolving with a FAILURE makes the difference observable —
	// a barrier the expiry wrongly deleted resolves to nothing and its wait
	// reports success.
	d.signalFailoverActuationFailed(1, errFenceRejected)
	err := d.waitFailoverActuated(1, 2)
	if err == nil {
		t.Fatal("the newer request's wait returned nil: an older request's expiry deleted " +
			"its barrier, so a REJECTED demotion would be acked as applied (#6177)")
	}
	if !errors.Is(err, errFenceRejected) {
		t.Fatalf("verdict = %v, want the demotion rejection", err)
	}
	if n := armedBarriers(d); n != 0 {
		t.Fatalf("armed barriers after both requests released = %d, want 0", n)
	}
}

// TestFailoverActuationBarrier_StaleHandleCannotDisarmARearmedRequest pins the
// other half of item 2: identity, not just the key. A duplicate transfer-out
// message re-uses the peer's request id, so two handler goroutines can hold
// handles for the SAME key. The one that finishes first must not evict the
// barrier the other one armed.
//
// Fail-on-revert: drop the `d.failoverActuateWait[key] == b` guard in
// disarmFailoverActuation and the stale handle deletes the live barrier — the
// wait below returns nil and this reds.
func TestFailoverActuationBarrier_StaleHandleCannotDisarmARearmedRequest(t *testing.T) {
	d := newBarrierDaemon(time.Second)

	stale := d.armFailoverActuation(1, 9)
	d.disarmFailoverActuation(1, 9, stale) // this request's ManualFailover failed
	if n := armedBarriers(d); n != 0 {
		t.Fatalf("armed barriers after a matching disarm = %d, want 0", n)
	}

	d.armFailoverActuation(1, 9)           // re-armed under the same request id
	d.disarmFailoverActuation(1, 9, stale) // the superseded handle must be inert
	if n := armedBarriers(d); n != 1 {
		t.Fatalf("armed barriers after a stale disarm = %d, want the live barrier to survive", n)
	}

	d.signalFailoverActuationFailed(1, errFenceRejected)
	err := d.waitFailoverActuated(1, 9)
	if err == nil {
		t.Fatal("wait returned nil: a superseded handle evicted the live barrier, so a " +
			"REJECTED demotion would be acked as applied (#6177)")
	}
	if !errors.Is(err, errFenceRejected) {
		t.Fatalf("verdict = %v, want the demotion rejection", err)
	}
}

// TestFailoverActuationBarrier_VerdictFansOutAcrossRequests pins the resolve
// side. The demotion event carries no request id — it reports that this node
// finished demoting the RG — so it must resolve EVERY request in flight for
// that RG. Resolving only one would leave the other waiting out its full
// timeout and downgrading a handoff that actually completed.
//
// Fail-on-revert: stop the resolve loop at the first match and the second wait
// below expires with a timeout instead of the demotion verdict.
func TestFailoverActuationBarrier_VerdictFansOutAcrossRequests(t *testing.T) {
	d := newBarrierDaemon(150 * time.Millisecond)
	d.armFailoverActuation(1, 1)
	d.armFailoverActuation(1, 2)
	d.armFailoverActuation(2, 1) // a different RG must be untouched

	d.signalFailoverActuationFailed(1, errFenceRejected)

	for _, reqID := range []uint64{1, 2} {
		err := d.waitFailoverActuated(1, reqID)
		if !errors.Is(err, errFenceRejected) {
			t.Fatalf("request %d verdict = %v, want the demotion rejection delivered to "+
				"every request in flight for the RG", reqID, err)
		}
	}
	// RG2's barrier is still armed — the RG1 event said nothing about it.
	if n := armedBarriers(d); n != 1 {
		t.Fatalf("armed barriers after RG1 resolved = %d, want 1 (RG2 untouched)", n)
	}
	d.disarmFailoverActuation(2, 1, nil) // a nil handle disarms nothing
	if n := armedBarriers(d); n != 1 {
		t.Fatalf("armed barriers after a nil-handle disarm = %d, want 1", n)
	}
}

// TestFailoverActuationBarrier_DisarmedRequestReportsNoFence pins the
// ManualFailover-error contract: the demotion was never enqueued, so no event
// will ever fire. The disarm must leave the wait free to return IMMEDIATELY
// rather than burning the full timeout — the handler is not on the ack path
// here, but a leaked barrier would be closed later by an unrelated event.
//
// #9259 changed the VALUE and deliberately kept the TIMING assertion verbatim.
// This cell's subject is immediacy — its own comment says the handler is not on
// the ack path here — so `want nil` was incidental to what it pins, while
// returning nil on the ack path is #9036's final link. The wait now reports
// ErrFailoverNeverArmed, still immediately.
func TestFailoverActuationBarrier_DisarmedRequestReportsNoFence(t *testing.T) {
	d := newBarrierDaemon(2 * time.Second)
	b := d.armFailoverActuation(3, 11)
	d.disarmFailoverActuation(3, 11, b)

	start := time.Now()
	err := d.waitFailoverActuated(3, 11)
	if !errors.Is(err, ErrFailoverNeverArmed) {
		t.Fatalf("wait on a disarmed request = %v, want ErrFailoverNeverArmed (#9259)", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("wait on a disarmed request took %v, want an immediate return", elapsed)
	}
	if n := armedBarriers(d); n != 0 {
		t.Fatalf("armed barriers after disarm = %d, want 0", n)
	}
}

// TestFailoverActuationBarrier_BatchTakesTheFirstFailure pins the batch wait:
// one request id, one barrier per RG, and a single RG whose demotion did not
// actuate must fail the whole batch ack — a partially fenced batch handed to
// the peer as applied is a two-owner window on the RGs that did not demote.
func TestFailoverActuationBarrier_BatchTakesTheFirstFailure(t *testing.T) {
	d := newBarrierDaemon(150 * time.Millisecond)
	for _, rgID := range []int{1, 2} {
		d.armFailoverActuation(rgID, 5)
	}
	d.signalFailoverActuated(1)
	d.signalFailoverActuationFailed(2, errFenceRejected)

	err := d.waitFailoverActuatedBatch([]int{1, 2}, 5)
	if !errors.Is(err, errFenceRejected) {
		t.Fatalf("batch verdict = %v, want the failing member's rejection", err)
	}

	// All-actuated control: the batch must still ack applied, or every planned
	// batch failover would stall.
	for _, rgID := range []int{1, 2} {
		d.armFailoverActuation(rgID, 6)
		d.signalFailoverActuated(rgID)
	}
	if err := d.waitFailoverActuatedBatch([]int{1, 2}, 6); err != nil {
		t.Fatalf("batch verdict = %v, want nil when every member actuated", err)
	}
}

// TestFailoverActuationBarrier_BatchFailureConsumesSiblingBarriers is the
// #13221 regression: when the FIRST RG in a batch fails, the batch wait must
// still release every sibling barrier (resolved ones consumed, unresolved
// ones disarmed) instead of leaking them in failoverActuateWait for the
// daemon's lifetime. The pre-fix early return only failed when the LAST
// member failed, which is why the sibling test above never saw the leak.
//
// Fail-on-revert: restore the early return in waitFailoverActuatedBatch and
// the resolved-sibling leak assertion fails; the second case also pins that
// unresolved siblings are disarmed without waiting through their timeout.
func TestFailoverActuationBarrier_BatchFailureConsumesSiblingBarriers(t *testing.T) {
	// Case 1: sibling already resolved successfully before the batch wait.
	d := newBarrierDaemon(150 * time.Millisecond)
	for _, rgID := range []int{1, 2} {
		d.armFailoverActuation(rgID, 42)
	}
	d.signalFailoverActuationFailed(1, errFenceRejected)
	d.signalFailoverActuated(2)
	if err := d.waitFailoverActuatedBatch([]int{1, 2}, 42); !errors.Is(err, errFenceRejected) {
		t.Fatalf("batch verdict = %v, want the first member's rejection", err)
	}
	if n := armedBarriers(d); n != 0 {
		t.Fatalf("armed barriers after failed batch (resolved sibling) = %d, want 0", n)
	}

	// Case 2: sibling never resolves; it must be disarmed, not waited on for
	// its full timeout and not leaked.
	d = newBarrierDaemon(150 * time.Millisecond)
	for _, rgID := range []int{1, 2, 3} {
		d.armFailoverActuation(rgID, 43)
	}
	d.signalFailoverActuationFailed(1, errFenceRejected)
	d.signalFailoverActuated(3)
	start := time.Now()
	if err := d.waitFailoverActuatedBatch([]int{1, 2, 3}, 43); !errors.Is(err, errFenceRejected) {
		t.Fatalf("batch verdict = %v, want the first member's rejection", err)
	}
	if elapsed := time.Since(start); elapsed >= 150*time.Millisecond {
		t.Fatalf("failed batch took %v; siblings must be released without waiting out their timeout", elapsed)
	}
	if n := armedBarriers(d); n != 0 {
		t.Fatalf("armed barriers after failed batch (unresolved sibling) = %d, want 0", n)
	}
}

// TestFailoverActuationBarrier_ResolveIsIdempotentUnderConcurrency drives the
// double-close path the demotion handler can reach when two events for one RG
// land back to back, and lets -race see the arm/resolve/wait interleaving. A
// second resolve must be a no-op: a double close panics and takes the daemon
// down mid-failover.
func TestFailoverActuationBarrier_ResolveIsIdempotentUnderConcurrency(t *testing.T) {
	d := newBarrierDaemon(2 * time.Second)
	d.armFailoverActuation(4, 21)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				d.signalFailoverActuated(4)
				return
			}
			d.signalFailoverActuationFailed(4, errFenceRejected)
		}(i)
	}
	wg.Wait()

	// Whichever verdict won, exactly one was published and the wait consumes it.
	if err := d.waitFailoverActuated(4, 21); err != nil && !errors.Is(err, errFenceRejected) {
		t.Fatalf("verdict = %v, want either the success or the rejection", err)
	}
	if n := armedBarriers(d); n != 0 {
		t.Fatalf("armed barriers after the wait consumed the verdict = %d, want 0", n)
	}
}

// #9259 route 2: the verdict was already CONSUMED by an earlier waiter.
//
// The first waiter deletes the entry after reading it, deliberately, so a later
// wait cannot re-read a stale verdict (#6177). Before #9259 a second wait then
// found an empty slot and returned nil — and nil is what sync_failover.go turns
// into failoverAckApplied. So a duplicate or retried ack promoted the peer off
// a barrier that had already been spent.
//
// The two routes are distinguished on purpose: "never armed" and "already
// consumed" send an operator to different places — a stale/duplicate request
// versus a retry racing its own first attempt.
func TestFailoverActuationBarrier_ConsumedVerdictIsNotReusable9259(t *testing.T) {
	d := newBarrierDaemon(2 * time.Second)
	d.armFailoverActuation(4, 21)
	d.resolveFailoverActuation(4, nil)

	// First waiter: takes the real verdict. This is the control — if it did
	// not succeed, the second wait below would prove nothing about consumption.
	if err := d.waitFailoverActuated(4, 21); err != nil {
		t.Fatalf("first wait = %v, want the actuated verdict (nil); without a "+
			"successful first wait this cell measures nothing", err)
	}

	// Second waiter for the SAME request.
	err := d.waitFailoverActuated(4, 21)
	if err == nil {
		t.Fatal("#9259: a second wait for an already-consumed verdict returned nil. " +
			"sync_failover.go sends failoverAckApplied exactly when this returns nil, " +
			"so a duplicate or retried failover ack promotes the peer off a barrier " +
			"that was already spent — #5640's invariant again.")
	}
	if !errors.Is(err, ErrFailoverVerdictConsumed) {
		t.Errorf("#9259: verdict = %v, want ErrFailoverVerdictConsumed. Reporting it "+
			"as never-armed would be safe but wrong: it sends the operator looking "+
			"for a stale request id when the real event is a retry.", err)
	}
}

// The consumed ledger is BOUNDED, and an eviction must degrade the DIAGNOSTIC
// rather than the safety property: an evicted key reports as never-armed, which
// is still an error and still downgrades the ack. Pinned because a bounded
// structure silently changing an operator-facing reason is exactly what gets
// discovered during an outage.
func TestFailoverConsumedLedgerIsBoundedAndFailsSafe9259(t *testing.T) {
	d := newBarrierDaemon(2 * time.Second)
	// Consume one verdict, then push it out of the ledger.
	first := failoverActuationKey{rgID: 9, reqID: 1}
	d.armFailoverActuation(first.rgID, first.reqID)
	d.resolveFailoverActuation(first.rgID, nil)
	if err := d.waitFailoverActuated(first.rgID, first.reqID); err != nil {
		t.Fatalf("fixture: first wait = %v, want nil", err)
	}
	if !errors.Is(d.waitFailoverActuated(first.rgID, first.reqID), ErrFailoverVerdictConsumed) {
		t.Fatal("fixture: the key was not recorded as consumed, so the eviction " +
			"below would prove nothing")
	}

	d.failoverActuateMu.Lock()
	for i := 0; i < failoverConsumedCap+1; i++ {
		d.noteFailoverVerdictConsumedLocked(failoverActuationKey{rgID: 99, reqID: uint64(i + 1000)})
	}
	d.failoverActuateMu.Unlock()

	if n := len(d.failoverActuateConsumed); n > failoverConsumedCap {
		t.Errorf("#9259: the consumed ledger holds %d entries, cap is %d — it is "+
			"unbounded and grows with every failover for the life of the process",
			n, failoverConsumedCap)
	}
	// The evicted key must still FAIL, just with the other reason.
	err := d.waitFailoverActuated(first.rgID, first.reqID)
	if err == nil {
		t.Fatal("#9259: an evicted consumed key returned nil. Eviction must cost " +
			"the diagnostic, never the safety property.")
	}
	if !errors.Is(err, ErrFailoverNeverArmed) {
		t.Errorf("#9259: evicted key = %v, want the conservative ErrFailoverNeverArmed", err)
	}
}
