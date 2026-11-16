package cluster

import (
	"context"
	"sync"
	"sync/atomic"
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
	// The forced case must be CHOSEN (its CAS consumed the arm) while the
	// backoff is still open, before the predecessor's failure is recorded.
	// Otherwise the outer gate would skip it and this cell would not reach
	// the under-lock recheck it is about (#19135 review, Codex P2-3).
	if !waitUntil19135(5*time.Second, func() bool { return !ss.forceResync.Load() }) {
		close(releaseResult)
		t.Fatal("FIXTURE: the sweep never consumed the forced arm")
	}
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
		// The connection install arms a new debt (armColdPrimeLocked), which
		// RESETS the episode. So the failure that closes the backoff must land
		// after that reset and before admission, or the cell would test an
		// open backoff and pass a wrongly gated admission (#19135 review,
		// Codex P2-2).
		closedAtAdmission := false
		ss.testBeforeConnectColdPrime = func() {
			ss.noteBulkRetryResult(errExportGenChanged19115)
			closedAtAdmission = !ss.bulkRetryBackoffOpen()
		}
		reads := snap.calls.Load()
		ss.forceResync.Store(true)
		conn := newBulkCaptureConn()
		t.Cleanup(func() { conn.Close() })
		ss.handleNewConnection(ctx, 0, conn, true)
		if !closedAtAdmission {
			t.Fatal("FIXTURE: the backoff must be closed at connect-time admission")
		}
		if got := snap.calls.Load(); got != reads+1 {
			t.Fatalf("#19135: a forced resync consumed at connect must export even while the backoff is closed (%d reads, want %d)",
				got, reads+1)
		}
	})
	t.Run("a peer's bulk request is exempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		snap := &flakySnapshot19115{}
		ss, conn := connectedAndDischarged19135(t, ctx, snap)
		ss.noteBulkRetryResult(errExportGenChanged19115)
		if ss.bulkRetryBackoffOpen() {
			t.Fatal("FIXTURE: the backoff must be closed")
		}
		reads := snap.calls.Load()
		ss.handleMessage(conn, syncMsgBulkRequest, nil)
		if !waitUntil19135(2*time.Second, func() bool { return snap.calls.Load() > reads }) {
			t.Fatal("#19135: a peer's bulk request must export even while the backoff is closed")
		}
	})
	t.Run("the daemon prime is exempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		snap := &flakySnapshot19115{}
		ss, _ := connectedAndDischarged19135(t, ctx, snap)
		ss.noteBulkRetryResult(errExportGenChanged19115)
		if ss.bulkRetryBackoffOpen() {
			t.Fatal("FIXTURE: the backoff must be closed")
		}
		reads := snap.calls.Load()
		sent, err := ss.DoPrimeBulkSync()
		if err != nil || !sent || snap.calls.Load() != reads+1 {
			t.Fatalf("#19135: the daemon prime must export even while the backoff is closed (sent=%v err=%v reads %d->%d)",
				sent, err, reads, snap.calls.Load())
		}
	})
	t.Run("a fence neither advances nor resets", func(t *testing.T) {
		// Both capability fences, and the NEXT failure's step: a fence that
		// changed the failure count without moving the deadline would show
		// only there (#19135 review, Codex P2-3).
		for _, fence := range []error{errBulkFencedForPeer, errBulkFencedForIpsecPeer} {
			ss := bareSync19115((&flakySnapshot19115{}).read)
			now := int64(1_000_000_000_000)
			ss.nowMonoFn = func() int64 { return now }
			ss.noteBulkRetryResult(errExportGenChanged19115)
			before := ss.bulkRetryNotBeforeNs()
			ss.noteBulkRetryResult(fence)
			if got := ss.bulkRetryNotBeforeNs(); got != before {
				t.Fatalf("#19135/#19115: %v moved the backoff deadline (%d -> %d)", fence, before, got)
			}
			ss.noteBulkRetryResult(errExportGenChanged19115)
			if got, want := ss.bulkRetryNotBeforeNs(), now+int64(coldPrimeRetrySchedule[1]); got != want {
				t.Fatalf("#19135/#19115: after %v, the next failure's deadline is %d, want the episode's SECOND step %d (%v): the fence changed the failure count",
					fence, got, want, coldPrimeRetrySchedule[1])
			}
		}
	})
}

// waitUntil19135 polls cond every millisecond until it holds or bound passes.
func waitUntil19135(bound time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(bound)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// connectedAndDischarged19135 is a primary connected to a peer whose
// connect-time cold prime was acked, so no debt is owed. The sweep is NOT
// running: each cell drives syncSweep or the scheduler itself.
func connectedAndDischarged19135(t *testing.T, ctx context.Context, snap *flakySnapshot19115) (*SessionSync, *bulkCaptureConn) {
	t.Helper()
	ss := bareSync19115(snap.read)
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
	return ss, conn
}

// parkFailingPredecessor19135 starts a failing authoritative bulk that holds
// bulkSendMu and parks at its result, BEFORE its failure reaches the backoff.
// release lets it record the failure and return; done closes when it has.
func parkFailingPredecessor19135(t *testing.T, ss *SessionSync, snap *flakySnapshot19115) (release func(), done <-chan struct{}) {
	t.Helper()
	atResult := make(chan struct{})
	releaseResult := make(chan struct{})
	var once, releaseOnce sync.Once
	ss.testBeforeBulkResult = func(err error) {
		if err != nil {
			once.Do(func() {
				close(atResult)
				<-releaseResult
			})
		}
	}
	snap.failures.Store(1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = ss.doBulkSyncAdmitted(nil)
	}()
	release = func() { releaseOnce.Do(func() { close(releaseResult) }) }
	select {
	case <-atResult:
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("FIXTURE: the predecessor bulk never reached its result")
	}
	if !ss.bulkRetryBackoffOpen() {
		release()
		t.Fatal("FIXTURE: the predecessor's failure must not be recorded yet")
	}
	return release, finished
}

// TestAgedRetryBehindAFailedPredecessorDoesNotExport19135 (#19135 review,
// Codex P2-3): an aged-ack re-drive CHOSEN while the backoff was open, which
// then waits on bulkSendMu behind a predecessor that fails, must see that
// failure under the lock:
//   - no export;
//   - the obligation kept;
//   - the in-flight guard released.
//
// The outer sweep gate cannot stop it here; only redriveAgedBulk's
// under-lock recheck can.
func TestAgedRetryBehindAFailedPredecessorDoesNotExport19135(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	ss, _ := connectedAndDischarged19135(t, ctx, snap)
	release, predecessorDone := parkFailingPredecessor19135(t, ss, snap)
	reads := snap.calls.Load()
	ss.bulkAckRetryOwed.Store(true)
	swept := make(chan struct{})
	go func() {
		defer close(swept)
		ss.syncSweep()
	}()
	if !waitUntil19135(5*time.Second, func() bool { return ss.bulkRedriveInFlight.Load() }) {
		release()
		t.Fatal("FIXTURE: the sweep never chose the aged re-drive")
	}
	release()
	<-swept
	<-predecessorDone
	if got := snap.calls.Load(); got != reads {
		t.Fatalf("#19135: an aged re-drive admitted behind a failed predecessor exported %d time(s); it must recheck the backoff under bulkSendMu",
			got-reads)
	}
	if !ss.bulkAckRetryOwed.Load() {
		t.Fatal("#19135: the aged re-drive skipped by its under-lock recheck dropped its obligation")
	}
	if ss.bulkRedriveInFlight.Load() {
		t.Fatal("#19135: the aged re-drive skipped by its under-lock recheck kept bulkRedriveInFlight")
	}
}

// TestBarrierReprimeBehindAFailedPredecessorDoesNotExport19135 (#19135
// review, Codex P2-3): a barrier re-prime admitted past its outer gates while
// the backoff was open, which then waits on bulkSendMu behind a predecessor
// that fails, must see that failure in its under-lock predicate:
//   - no export;
//   - the fence still armed;
//   - reprimeInFlight released.
func TestBarrierReprimeBehindAFailedPredecessorDoesNotExport19135(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	ss, _ := connectedAndDischarged19135(t, ctx, snap)
	release, predecessorDone := parkFailingPredecessor19135(t, ss, snap)
	ss.fence.epoch.Store(ss.fence.cleared.Load() + 1)
	ss.fence.pendingBulk.Store(0)
	if !ss.barrierFenced() || ss.fenceDischargeAwaited() {
		release()
		t.Fatal("FIXTURE: want the barrier fenced with no discharge-capable bulk pending")
	}
	reads := snap.calls.Load()
	ss.scheduleBarrierFenceReprime("19135-cell")
	if !ss.fence.reprimeInFlight.Load() {
		release()
		t.Fatal("FIXTURE: the re-prime must pass its outer gates while the backoff is open")
	}
	release()
	<-predecessorDone
	if !waitUntil19135(3*time.Second, func() bool { return !ss.fence.reprimeInFlight.Load() }) {
		t.Fatal("#19135: the re-prime never released reprimeInFlight")
	}
	if got := snap.calls.Load(); got != reads {
		t.Fatalf("#19135: a barrier re-prime admitted behind a failed predecessor exported %d time(s); it must recheck the backoff under bulkSendMu",
			got-reads)
	}
	if !ss.barrierFenced() {
		t.Fatal("FIXTURE: the fence must stay armed")
	}
}

// TestOverdueHeldBackRetryIsPolledNotDeferred19135 (#19135 review, Codex
// P2-1):
//   - a held-back forced retry whose deadline passes while the sweep runs
//     (the enumeration crossed it after the gate skipped) must be re-checked
//     at coldPrimeRetryPollDelay, not after another profile interval;
//   - EXACTLY min(base, coldPrimeRetryPollDelay), never zero or negative;
//   - while the sweep could not run it (paused, either capability fence,
//     disconnected), the profile interval stands: no poll.
func TestOverdueHeldBackRetryIsPolledNotDeferred19135(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	ss, _ := connectedAndDischarged19135(t, ctx, snap)
	var now atomic.Int64
	now.Store(1_000_000_000_000)
	ss.nowMonoFn = now.Load
	ss.noteBulkRetryResult(errExportGenChanged19115)
	ss.forceResync.Store(true)
	const profile = 60 * time.Second
	base := ss.capSweepIntervalForLiveness(profile)
	if got := ss.nextSweepDelay(profile); got != coldPrimeRetrySchedule[0] {
		t.Fatalf("FIXTURE: a future deadline must be scheduled exactly (%v, want %v)", got, coldPrimeRetrySchedule[0])
	}
	now.Add(int64(coldPrimeRetrySchedule[0] + 500*time.Millisecond)) // the enumeration crossed it
	if !ss.bulkRetryRunnableNow() {
		t.Fatal("FIXTURE: a connected, unpaused, unfenced primary must be able to run the retry")
	}
	// EXACTLY the cap: a zero or negative delay would spin the loop, and a
	// longer one defers the retry (#19135 re-check, Codex P3).
	if got, want := ss.nextSweepDelay(profile), min(base, coldPrimeRetryPollDelay); got != want {
		t.Fatalf("#19135: an OVERDUE held-back forced retry was scheduled %v out (profile %v); want exactly %v (min(base, coldPrimeRetryPollDelay))",
			got, profile, want)
	}
	// Not runnable: this branch adds nothing, so the profile interval stands.
	notRunnable := func(state string, enter, leave func()) {
		t.Helper()
		enter()
		defer leave()
		if ss.bulkRetryRunnableNow() {
			t.Fatalf("FIXTURE: %s must make the retry not runnable", state)
		}
		if got := ss.nextSweepDelay(profile); got != base {
			t.Fatalf("#19135: while %s an overdue retry was scheduled at %v; the profile interval %v must stand", state, got, base)
		}
	}
	notRunnable("paused", func() { ss.incrementalPauseDepth.Add(1) }, func() { ss.incrementalPauseDepth.Add(-1) })
	notRunnable("fenced for an install-table-incapable peer",
		func() { ss.peerIncarnationState().bulkFencedForPeer.Store(true) },
		func() { ss.peerIncarnationState().bulkFencedForPeer.Store(false) })
	notRunnable("fenced for an IPsec-incapable peer",
		func() { ss.peerIncarnationState().bulkFencedForIpsecPeer.Store(true) },
		func() { ss.peerIncarnationState().bulkFencedForIpsecPeer.Store(false) })
	notRunnable("disconnected", func() { ss.stats.Connected.Store(false) }, func() { ss.stats.Connected.Store(true) })
}
