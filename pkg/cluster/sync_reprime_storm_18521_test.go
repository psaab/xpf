package cluster

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #18521 (C) and (D), the second live shape (loss cluster, test-ha-crash
// phase 1). fw0's xpfd restarted; on reconnect fw1's ordered stream moved and
// armed the #9508 barrier fence. Every manual-failover admission retry (every
// 0.5s) was refused by the fence and kicked a NEW full re-prime, while fw0 —
// installing at ~50 sessions/s — was still working through the earlier ones
// and withheld its BulkAck because the zone map moved mid-bulk. The fence can
// only be discharged by an ack for the bulk currently pending, so it never was.

// fencedSender18521 is a connected sender with an armed fence whose bulks are
// simulated by BulkSyncOverride recording exactly the pending state
// bulkSyncWindow records before BulkEnd (record-then-send). The real bulk then
// returns early (no session store), touching nothing.
func fencedSender18521(t *testing.T) (*SessionSync, *atomic.Uint64) {
	t.Helper()
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.stats.Connected.Store(true)
	ss.fence.epoch.Store(2)
	ss.fence.cleared.Store(1)
	var bulks atomic.Uint64
	ss.BulkSyncOverride = func() error {
		n := bulks.Add(1)
		ss.pendingBulkAckEpoch.Store(n)
		ss.fence.pendingBulk.Store(ss.fence.epoch.Load() + 1)
		ss.pendingBulkAckSince.Store(MonotonicNanos())
		return nil
	}
	if !ss.barrierFenced() {
		t.Fatal("fixture: fence must be armed")
	}
	return ss, &bulks
}

// refuse runs one admission attempt: a fenced barrier, then lets any re-prime
// it scheduled finish writing — the state the 0.5s admission cadence sees.
func refuse18521(t *testing.T, ss *SessionSync) {
	t.Helper()
	if err := ss.WaitForPeerBarrier(time.Second); err == nil {
		t.Fatal("a fenced barrier was admitted")
	}
	ss.wg.Wait()
}

// RED before the fix: ten refused barriers start ten full bulks, each
// superseding the pending epoch the previous one's ack would have matched.
func TestRefusedBarriersStartOneReprimePerFenceEpoch18521(t *testing.T) {
	ss, bulks := fencedSender18521(t)
	for i := 0; i < 10; i++ {
		refuse18521(t, ss)
	}
	if got := bulks.Load(); got != 1 {
		t.Fatalf("ten refused barriers started %d full re-primes; want 1 while the first one's "+
			"ack is pending — each extra bulk replaces the pending epoch, so the peer's ack for "+
			"the earlier one is dropped and the fence can never discharge (#18521)", got)
	}
	// The ack for that one re-prime discharges the fence.
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], ss.pendingBulkAckEpoch.Load())
	if !ss.handleMessage(nil, syncMsgBulkAck, payload[:]) {
		t.Fatal("the BulkAck for the pending re-prime was not accepted")
	}
	if ss.barrierFenced() {
		t.Fatal("the acked re-prime did not discharge the fence")
	}
}

// The suppression is only for a bulk that can discharge the CURRENT epoch and
// whose ack is not yet presumed lost. Each row must still re-prime.
func TestReprimeStillRunsWhenThePendingBulkCannotDischarge18521(t *testing.T) {
	rows := []struct {
		name  string
		setup func(ss *SessionSync)
	}{
		{"no bulk pending", func(ss *SessionSync) {}},
		{"pending bulk captured before the stream moved", func(ss *SessionSync) {
			ss.pendingBulkAckEpoch.Store(41)
			ss.fence.pendingBulk.Store(ss.fence.epoch.Load()) // capture of epoch-1
			ss.pendingBulkAckSince.Store(MonotonicNanos())
		}},
		{"pending ack older than BulkAckPendingRetryAfter", func(ss *SessionSync) {
			ss.pendingBulkAckEpoch.Store(41)
			ss.fence.pendingBulk.Store(ss.fence.epoch.Load() + 1)
			ss.pendingBulkAckSince.Store(MonotonicNanos() - int64(BulkAckPendingRetryAfter+time.Second))
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			ss, bulks := fencedSender18521(t)
			row.setup(ss)
			refuse18521(t, ss)
			if got := bulks.Load(); got != 1 {
				t.Fatalf("re-primes = %d, want 1: nothing pending can discharge this fence", got)
			}
		})
	}
}

// (D) receiver cells. A completed bulk window whose BulkAck is withheld must
// ask the peer for a replacement; otherwise the sender's barrier fence waits
// out its 35s retry. RED before the fix for every withholding branch.

func rerequestReceiver18521(t *testing.T) *SessionSync {
	t.Helper()
	rx, _ := receiver9655(t, false, map[uint16]int{1: 1, 5: 5})
	rx.stats.Connected.Store(true)
	rx.testZoneMapSettle = 10 * time.Millisecond
	rx.testBulkRerequestBackoff = 20 * time.Millisecond
	return rx
}

// drainRerequests waits for the re-request machinery to go idle, then counts
// queued BulkRequest frames.
func drainRerequests18521(t *testing.T, rx *SessionSync) int {
	t.Helper()
	if !waitFor18521(t, 5*time.Second, func() bool { return !rx.bulkRerequestInFlight.Load() }) {
		t.Fatal("the re-request never left its wait")
	}
	rx.wg.Wait()
	requests := 0
	for len(rx.sendCh) > 0 {
		msg := <-rx.sendCh
		if len(msg) >= syncHeaderSize && msg[4] == syncMsgBulkRequest {
			requests++
		}
	}
	return requests
}

func TestWithheldBulkAckRequestsAReplacement18521(t *testing.T) {
	rows := []struct {
		name   string
		during func(rx *SessionSync)
	}{
		{"zone map changed mid-bulk (reconcile skipped)", func(rx *SessionSync) {
			rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
		}},
		{"transient helper install failure", func(rx *SessionSync) {
			rx.bulkMu.Lock()
			rx.bulkInstallFailedV4[staleUnmapped9655] = struct{}{}
			rx.bulkMu.Unlock()
		}},
		{"aborted receive window", func(rx *SessionSync) {
			rx.bulkMu.Lock()
			rx.bulkRecvInvalid = true
			rx.bulkMu.Unlock()
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			rx := rerequestReceiver18521(t)
			rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
			row.during(rx)
			rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
			if rx.BulkEverCompleted() {
				t.Fatal("fixture: the withheld bulk must not complete")
			}
			if n := drainRerequests18521(t, rx); n != 1 {
				t.Fatalf("a withheld BulkAck queued %d bulk re-requests, want exactly 1: without "+
					"it the sender's fence waits out its 35s retry (#18521)", n)
			}
			if got := rx.Stats().BulkRerequestsSent; got != 1 {
				t.Fatalf("BulkRerequestsSent = %d, want 1", got)
			}
		})
	}
}

// Two withheld bulks back to back produce ONE request (single-flight), for
// the latest of them. RED with the single-flight CAS removed (two requests),
// and with the latest-serial tracking removed (zero: the first request sees
// its bulk superseded and drops while the second lost the race). The
// request's decision is held on testBulkRerequestGate until both bulks are
// in, so the order is forced, not won against a backoff (review of #18525
// round 2).
func TestBackToBackWithheldBulksRequestOnce18521(t *testing.T) {
	rx := rerequestReceiver18521(t)
	gate := make(chan struct{})
	rx.testBulkRerequestGate = gate
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(2, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 5})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(2, nil))
	close(gate)
	if n := drainRerequests18521(t, rx); n != 1 {
		t.Fatalf("two back-to-back withheld bulks queued %d requests, want exactly 1", n)
	}
}

// A newer bulk accepted while the request waits is the replacement; asking
// again would only replace its pending epoch on the sender. RED with the
// serial check removed.
func TestRerequestDroppedWhenANewerBulkWasAccepted18521(t *testing.T) {
	rx := rerequestReceiver18521(t)
	gate := make(chan struct{})
	rx.testBulkRerequestGate = gate
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	// The sender's own retry starts a fresh bulk; it is still streaming.
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(2, nil))
	close(gate)
	if n := drainRerequests18521(t, rx); n != 0 {
		t.Fatalf("queued %d re-requests although a newer bulk was already accepted", n)
	}
}

// A receiver that lost the connection while waiting asks for nothing: the
// reconnect re-primes.
func TestSkippedReconcileRerequestDropsWhenDisconnected18521(t *testing.T) {
	rx := rerequestReceiver18521(t)
	rx.stats.Connected.Store(false)
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	if n := drainRerequests18521(t, rx); n != 0 {
		t.Fatalf("a disconnected receiver queued %d requests", n)
	}
}

// The settle wait is capped: a map that never stops moving still gets its
// request once zoneMapSettleMax passes.
func TestSkippedReconcileRerequestIsCappedUnderChurn18521(t *testing.T) {
	rx := rerequestReceiver18521(t)
	rx.testZoneMapSettle = time.Hour
	rx.testZoneMapSettleMax = 50 * time.Millisecond
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	if !waitFor18521(t, 5*time.Second, func() bool { return len(rx.sendCh) > 0 }) {
		t.Fatal("a settle wait that never settles must still request after its cap")
	}
	rx.wg.Wait()
}

// Backoff: 1s doubling per consecutive withheld bulk, capped at 30s; a
// reconciled bulk resets the streak.
func TestBulkRerequestBackoff18521(t *testing.T) {
	for streak, want := range map[uint64]time.Duration{
		1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 5: 16 * time.Second,
		6: bulkRerequestMax, 100: bulkRerequestMax,
	} {
		if got := bulkRerequestDelay(streak); got != want {
			t.Errorf("bulkRerequestDelay(%d) = %v, want %v", streak, got, want)
		}
	}
	rx := rerequestReceiver18521(t)
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	drainRerequests18521(t, rx)
	if rx.bulkRerequestStreak.Load() == 0 {
		t.Fatal("fixture: a withheld bulk must advance the streak")
	}
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(2, nil))
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(2, nil))
	if !rx.BulkEverCompleted() {
		t.Fatal("fixture: the second bulk must reconcile")
	}
	if got := rx.bulkRerequestStreak.Load(); got != 0 {
		t.Fatalf("a reconciled bulk left the backoff streak at %d", got)
	}
}

// Finding 2 of the review: the pending-bulk stamp is monotonic, so a
// wall-clock step cannot make an old ack look young (or a young one old).
// Driven through a real bulk, with the monotonic clock advanced by the seam.
// RED with the stamp back on time.Now().UnixNano().
func TestPendingBulkAckAgeIsMonotonic18521(t *testing.T) {
	sender, _ := newBulk6031Primary(t)
	receiver, _ := newBulk6031Standby(t)
	base := MonotonicNanos()
	now := base
	sender.nowMonoFn = func() int64 { return now }
	sender.BulkSnapshotSource = func() (BulkSnapshot, error) { return BulkSnapshot{}, nil }
	pumpBulk(t, sender, receiver)
	if _, age, ok := sender.PendingBulkAck(); !ok || age != 0 {
		t.Fatalf("fixture: want a pending bulk aged 0, got ok=%v age=%v", ok, age)
	}
	now = base + int64(BulkAckPendingRetryAfter+time.Second)
	if _, age, _ := sender.PendingBulkAck(); age != BulkAckPendingRetryAfter+time.Second {
		t.Fatalf("pending bulk age = %v, want %v from the monotonic clock", age, BulkAckPendingRetryAfter+time.Second)
	}
}

// Review of #18525 round 2 (finding 5, wire seat): every request makes the
// sender walk its WHOLE table, and the transient-install branch — expected
// while the helper is still coming up — asked at 1s, 2s, 4s, 8s, 16s: about
// five full bulks in the first 31s, against one per 35s before #18521. The
// wait now starts at bulkRerequestTransientFloor for that branch, and for
// every branch is never shorter than the withheld bulk's own receive
// duration. RED with the transient branch on the 1s start, and with the
// duration floor dropped.
func TestBulkRerequestWaitFloors18525(t *testing.T) {
	for _, c := range []struct {
		base     time.Duration
		streak   uint64
		duration time.Duration
		want     time.Duration
	}{
		{bulkRerequestTransientFloor, 1, 0, 10 * time.Second},
		{bulkRerequestTransientFloor, 2, 0, 20 * time.Second},
		{bulkRerequestTransientFloor, 3, 0, bulkRerequestMax},
		{bulkRerequestBackoff, 1, 0, time.Second},
		{bulkRerequestBackoff, 1, 7 * time.Second, 7 * time.Second},
		{bulkRerequestBackoff, 6, 90 * time.Second, 90 * time.Second},
	} {
		if got := bulkRerequestWait(c.base, c.streak, c.duration); got != c.want {
			t.Errorf("bulkRerequestWait(%v, %d, %v) = %v, want %v", c.base, c.streak, c.duration, got, c.want)
		}
	}

	rows := []struct {
		name   string
		during func(rx *SessionSync)
		bulk   time.Duration
		want   time.Duration
	}{
		{"transient helper install failure, fast bulk", func(rx *SessionSync) {
			rx.bulkMu.Lock()
			rx.bulkInstallFailedV4[staleUnmapped9655] = struct{}{}
			rx.bulkMu.Unlock()
		}, time.Second, bulkRerequestTransientFloor},
		{"zone map changed mid-bulk, 7s bulk", func(rx *SessionSync) {
			rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
		}, 7 * time.Second, 7 * time.Second},
		{"zone map changed mid-bulk, fast bulk", func(rx *SessionSync) {
			rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
		}, 0, bulkRerequestBackoff},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			rx := rerequestReceiver18521(t)
			now := time.Unix(1_800_000_000, 0)
			rx.testBulkRecvNow = func() time.Time { return now }
			var waits []time.Duration
			rx.testOnBulkRerequestScheduled = func(_ string, wait time.Duration) { waits = append(waits, wait) }
			rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
			row.during(rx)
			now = now.Add(row.bulk)
			rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
			drainRerequests18521(t, rx)
			if len(waits) != 1 || waits[0] != row.want {
				t.Fatalf("scheduled waits %v, want [%v]", waits, row.want)
			}
		})
	}
}

// Review of #18525 round 3 (finding 9, wire seat): a bulk withheld for
// transient install failures WHILE an earlier bulk's re-request was in flight
// was requested on the earlier bulk's 1s schedule — skipping its 10s floor —
// and the request's log line named the earlier cause. The in-flight request
// now decides on the newest withheld bulk's own record. Runs the production
// schedule scaled (1s -> 10ms, so the transient floor is 100ms); the sent
// hook's wait is a lower bound the code enforces, so load can only lengthen
// it. RED with the first bulk's schedule and reason.
func TestRerequestUsesTheNewestWithheldBulksSchedule18525(t *testing.T) {
	rx := rerequestReceiver18521(t)
	rx.testBulkRerequestBackoff = 0
	rx.testBulkRerequestUnit = 10 * time.Millisecond
	gate := make(chan struct{})
	rx.testBulkRerequestGate = gate
	type sent struct {
		reason string
		waited time.Duration
	}
	var mu sync.Mutex
	var sends []sent
	rx.testOnBulkRerequestSent = func(reason string, waited time.Duration) {
		mu.Lock()
		sends = append(sends, sent{reason, waited})
		mu.Unlock()
	}
	// Bulk 1: reconcile skipped (zone map moved) — the 1s schedule.
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	// Bulk 2, while bulk 1's request waits: transient install failures.
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(2, nil))
	rx.bulkMu.Lock()
	rx.bulkInstallFailedV4[staleUnmapped9655] = struct{}{}
	rx.bulkMu.Unlock()
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(2, nil))
	close(gate)
	if n := drainRerequests18521(t, rx); n != 1 {
		t.Fatalf("queued %d requests for two overlapping withheld bulks, want 1", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sends) != 1 {
		t.Fatalf("sent hook saw %d requests", len(sends))
	}
	floor := bulkRerequestTransientFloor / time.Second * rx.testBulkRerequestUnit
	if sends[0].reason != "transient helper install failures" || sends[0].waited < floor {
		t.Fatalf("the request for the transient-withheld bulk went out %v after it (floor %v) "+
			"naming %q: it ran on the earlier bulk's schedule (review of #18525 round 3)",
			sends[0].waited, floor, sends[0].reason)
	}
}
