package cluster

import (
	"context"
	"sync"
	"testing"
	"time"
)

// #19135: the forced resync, the aged-ack re-drive and the barrier-fence
// re-prime share #19115's ONE retry backoff (one failure count, one deadline).
// Each rechecks it under bulkSendMu and keeps its obligation armed when held
// back, and nextSweepDelay schedules the deadline. The fixtures are #19115's
// (sync_cold_prime_redrive_prompt_19115_test.go).

// failBulk19135 runs one authoritative bulk that fails, which closes the
// backoff for its first 1 s step (measured from the failure's end).
func failBulk19135(t *testing.T, ss *SessionSync, snap *flakySnapshot19115) {
	t.Helper()
	snap.failures.Store(1)
	if err := ss.doBulkSync(); err == nil {
		t.Fatal("FIXTURE: want the injected bulk failure")
	}
	if ss.bulkRetryBackoffOpen() {
		t.Fatal("FIXTURE: the failure must close the retry backoff")
	}
}

// ackedPrimary19135 is a primary on the fast sweep profile whose cold prime
// was sent and acked, so no debt is owed and the switch's later branches are
// reachable.
func ackedPrimary19135(t *testing.T, ctx context.Context, snap *flakySnapshot19115) *SessionSync {
	t.Helper()
	ss := primarySync19115(t, ctx, sweepProfiles19115[0], snap.read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	epoch, _, pending := ss.PendingBulkAck()
	if !pending {
		t.Fatal("FIXTURE: want the cold prime sent and pending")
	}
	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch))
	if ss.needColdPrime.Load() {
		t.Fatal("FIXTURE: the ack did not discharge the debt")
	}
	return ss
}

// TestForcedResyncWaitsForTheBackoffAndFiresAtItsDeadline19135 supersedes
// #19115's TestForcedResyncKeepsItsCadence19115 (#19135 reverses that scope
// decision). Checked on a 50 ms sweep:
//   - a forced resync armed inside the backoff is NOT exported before the
//     deadline;
//   - its arm stays set (the obligation is kept);
//   - it IS exported once the deadline passes.
func TestForcedResyncWaitsForTheBackoffAndFiresAtItsDeadline19135(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	ss := ackedPrimary19135(t, ctx, snap)
	failBulk19135(t, ss, snap)
	bulks, reads := ss.stats.BulkSyncs.Load(), snap.calls.Load()
	ss.forceResync.Store(true) // a delete-journal overflow
	ss.wakeSyncSweep()
	time.Sleep(600 * time.Millisecond) // a dozen 50 ms sweep ticks, all inside the 1 s backoff
	if got := snap.calls.Load(); got != reads {
		t.Fatalf("#19135: a forced resync inside the retry backoff exported %d time(s) on a 50 ms sweep; it must wait for the deadline",
			got-reads)
	}
	if !ss.forceResync.Load() {
		t.Fatal("#19135: a held-back forced resync dropped its arm (the obligation was lost)")
	}
	took, ok := waitForBulkSyncs19115(ss, bulks+1, 1500*time.Millisecond)
	if !ok {
		t.Fatal("#19135: the held-back forced resync was not sent after its 1 s deadline passed")
	}
	t.Logf("forced resync sent %v after the 600 ms check (deadline 1 s after the failure)", took.Round(time.Millisecond))
}

// TestHeldBackRetryIsScheduledExactlyAtItsDeadline19135 (Codex finding 18 on
// #19115 v4: gating without scheduling costs a profile interval). With a
// forced resync armed, or an aged-ack retry owed, and the backoff in the
// future, the sweep timer is armed at EXACTLY the deadline. With neither, it
// is the profile interval.
func TestHeldBackRetryIsScheduledExactlyAtItsDeadline19135(t *testing.T) {
	ss := bareSync19115((&flakySnapshot19115{}).read)
	now := int64(1_000_000_000_000)
	ss.nowMonoFn = func() int64 { return now }
	for range 4 { // into the tail: the fourth failure backs off 8 s
		ss.noteBulkRetryResult(errExportGenChanged19115)
	}
	want := time.Duration(ss.bulkRetryNotBeforeNs() - now)
	if want != 8*time.Second {
		t.Fatalf("FIXTURE: the fourth failure must back off 8 s, got %v", want)
	}
	if d := ss.nextSweepDelay(time.Minute); d != time.Minute {
		t.Fatalf("FIXTURE: with no retry owed the timer must be the profile interval, got %v", d)
	}
	ss.forceResync.Store(true)
	if d := ss.nextSweepDelay(time.Minute); d != want {
		t.Errorf("#19135: a held-back forced resync's sweep timer is %v, want EXACTLY its deadline %v", d, want)
	}
	ss.forceResync.Store(false)
	ss.bulkAckRetryOwed.Store(true)
	if d := ss.nextSweepDelay(time.Minute); d != want {
		t.Errorf("#19135: a held-back aged-ack retry's sweep timer is %v, want EXACTLY its deadline %v", d, want)
	}
}

// TestForcedRetryBehindAFailedPredecessorDoesNotExport19135 (Codex finding 1
// on #19115 v4):
//   - a forced resync admitted while a predecessor bulk still held
//     bulkSendMu, before that bulk's failure was recorded, must see the
//     failure's deadline once it gets the lock;
//   - so it does not export, and it re-arms.
func TestForcedRetryBehindAFailedPredecessorDoesNotExport19135(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	snap.failures.Store(1)
	ss := bareSync19115(snap.read)
	atResult := make(chan struct{})
	releaseResult := make(chan struct{})
	var once sync.Once
	ss.testBeforeBulkResult = func(err error) {
		if err != nil {
			once.Do(func() {
				close(atResult)
				<-releaseResult
			})
		}
	}
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	connected := make(chan struct{})
	go func() {
		defer close(connected)
		ss.handleNewConnection(ctx, 0, conn, true) // the predecessor: a failing cold prime
	}()
	select {
	case <-atResult:
	case <-time.After(5 * time.Second):
		close(releaseResult)
		t.Fatal("FIXTURE: the predecessor bulk never reached its result")
	}
	if !ss.bulkRetryBackoffOpen() {
		t.Fatal("FIXTURE: the predecessor's failure must not be recorded yet")
	}
	ss.forceResync.Store(true)
	swept := make(chan struct{})
	go func() {
		defer close(swept)
		ss.syncSweep() // the forced branch is chosen, then waits on bulkSendMu
	}()
	time.Sleep(200 * time.Millisecond)
	close(releaseResult)
	<-swept
	<-connected
	if got := snap.calls.Load(); got != 1 {
		t.Fatalf("#19135: a forced resync admitted behind a failed predecessor exported again (%d snapshot reads, want 1); it must recheck the backoff under bulkSendMu",
			got)
	}
	if !ss.forceResync.Load() {
		t.Fatal("#19135: the forced resync skipped by its under-lock recheck did not re-arm")
	}
}

// TestAgedAckRetryWaitsForTheBackoff19135: an owed aged-ack re-drive is held
// to the backoff, keeps its obligation, and goes once the deadline passes.
func TestAgedAckRetryWaitsForTheBackoff19135(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	ss := ackedPrimary19135(t, ctx, snap)
	failBulk19135(t, ss, snap)
	bulks, reads := ss.stats.BulkSyncs.Load(), snap.calls.Load()
	ss.bulkAckRetryOwed.Store(true)
	ss.wakeSyncSweep()
	time.Sleep(600 * time.Millisecond)
	if got := snap.calls.Load(); got != reads {
		t.Fatalf("#19135: an aged-ack re-drive inside the retry backoff exported %d time(s); it must wait for the deadline", got-reads)
	}
	if !ss.bulkAckRetryOwed.Load() {
		t.Fatal("#19135: a held-back aged-ack re-drive dropped its obligation")
	}
	if _, ok := waitForBulkSyncs19115(ss, bulks+1, 1500*time.Millisecond); !ok {
		t.Fatal("#19135: the held-back aged-ack re-drive was not sent after its deadline passed")
	}
}

// TestBarrierReprimeWaitsForTheBackoff19135:
//   - refused barriers (0.5 s apart in production) after a failed bulk start
//     no re-prime export before the deadline;
//   - the fence stays armed;
//   - the first refusal after the deadline re-primes.
func TestBarrierReprimeWaitsForTheBackoff19135(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	ss := bareSync19115(snap.read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	failBulk19135(t, ss, snap)
	ss.fence.epoch.Store(ss.fence.cleared.Load() + 1)
	ss.fence.pendingBulk.Store(0)
	if !ss.barrierFenced() || ss.fenceDischargeAwaited() {
		t.Fatal("FIXTURE: want the barrier fenced with no discharge-capable bulk pending")
	}
	reads := snap.calls.Load()
	for range 5 {
		ss.scheduleBarrierFenceReprime("19135-cell")
		time.Sleep(100 * time.Millisecond)
	}
	if got := snap.calls.Load(); got != reads {
		t.Fatalf("#19135: refused barriers inside the retry backoff started %d re-prime export(s); they must wait for the deadline", got-reads)
	}
	if !ss.barrierFenced() {
		t.Fatal("FIXTURE: the fence must stay armed")
	}
	time.Sleep(700 * time.Millisecond) // past the 1 s deadline
	ss.scheduleBarrierFenceReprime("19135-cell")
	deadline := time.Now().Add(3 * time.Second)
	for snap.calls.Load() == reads || ss.fence.reprimeInFlight.Load() {
		if time.Now().After(deadline) {
			t.Fatal("#19135: the first refused barrier after the deadline did not re-prime")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBackoffResetsAndExemptions19135 checks the reset rules and the
// exemptions:
//   - a successful bulk resets the episode, so a NEW forced arm goes at once;
//   - a forced resync consumed at connect is an edge, not a retry, and
//     exports even while the backoff is closed;
//   - a fenced failure neither advances nor resets the backoff.
func TestBackoffResetsAndExemptions19135(t *testing.T) {
	t.Run("success resets", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		snap := &flakySnapshot19115{}
		ss := ackedPrimary19135(t, ctx, snap)
		failBulk19135(t, ss, snap)
		if err := ss.doBulkSync(); err != nil {
			t.Fatalf("FIXTURE: want the next bulk to succeed: %v", err)
		}
		if !ss.bulkRetryBackoffOpen() {
			t.Fatal("#19135/#19115: a successful bulk must reset the retry backoff")
		}
		bulks := ss.stats.BulkSyncs.Load()
		ss.forceResync.Store(true)
		ss.wakeSyncSweep()
		if _, ok := waitForBulkSyncs19115(ss, bulks+1, 400*time.Millisecond); !ok {
			t.Fatal("#19135: after a success, a new forced resync was held back; the episode must reset")
		}
	})
	t.Run("connect-time forced resync is exempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		snap := &flakySnapshot19115{}
		ss := bareSync19115(snap.read)
		if err := ss.doBulkSync(); err == nil {
			t.Fatal("FIXTURE: with no connection the bulk must fail")
		}
		if ss.bulkRetryBackoffOpen() {
			t.Fatal("FIXTURE: the failure must close the backoff")
		}
		reads := snap.calls.Load()
		ss.forceResync.Store(true)
		conn := newBulkCaptureConn()
		t.Cleanup(func() { conn.Close() })
		ss.handleNewConnection(ctx, 0, conn, true)
		if got := snap.calls.Load(); got != reads+1 {
			t.Fatalf("#19135: a forced resync consumed at connect must export even while the backoff is closed (%d reads, want %d)",
				got, reads+1)
		}
	})
	t.Run("a fence neither advances nor resets", func(t *testing.T) {
		ss := bareSync19115((&flakySnapshot19115{}).read)
		now := int64(1_000_000_000_000)
		ss.nowMonoFn = func() int64 { return now }
		ss.noteBulkRetryResult(errExportGenChanged19115)
		before := ss.bulkRetryNotBeforeNs()
		ss.noteBulkRetryResult(errBulkFencedForPeer)
		if got := ss.bulkRetryNotBeforeNs(); got != before {
			t.Fatalf("#19135/#19115: a fenced bulk moved the backoff deadline (%d -> %d)", before, got)
		}
	})
}
