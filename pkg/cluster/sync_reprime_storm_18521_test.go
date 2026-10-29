package cluster

import (
	"encoding/binary"
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
		ss.pendingBulkAckSince.Store(time.Now().UnixNano())
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
			ss.pendingBulkAckSince.Store(time.Now().UnixNano())
		}},
		{"pending ack older than BulkAckPendingRetryAfter", func(ss *SessionSync) {
			ss.pendingBulkAckEpoch.Store(41)
			ss.fence.pendingBulk.Store(ss.fence.epoch.Load() + 1)
			ss.pendingBulkAckSince.Store(time.Now().Add(-BulkAckPendingRetryAfter - time.Second).UnixNano())
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

// (D) receiver: a bulk whose reconcile was skipped because the zone map moved
// mid-bulk withholds its BulkAck (#9655/#11070, unchanged). It must ask the
// peer for a replacement once the map settles. RED before the fix: nothing is
// ever queued, and the sender's only retry is its 35s ack bound.
func TestSkippedReconcileRequestsAFreshBulk18521(t *testing.T) {
	rx, _ := receiver9655(t, false, map[uint16]int{1: 1, 5: 5})
	rx.stats.Connected.Store(true)
	rx.testZoneMapSettle = 20 * time.Millisecond

	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	if rx.BulkEverCompleted() {
		t.Fatal("#11070 contract: the skipped bulk must still not complete")
	}
	// A second skipped BulkEnd while the first re-request is still settling
	// must not queue a second request.
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(2, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 5})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(2, nil))

	if !waitFor18521(t, 5*time.Second, func() bool { return !rx.bulkRerequestInFlight.Load() }) {
		t.Fatal("the re-request never left its settle wait")
	}
	rx.wg.Wait()
	var requests int
	for len(rx.sendCh) > 0 {
		msg := <-rx.sendCh
		if len(msg) >= syncHeaderSize && msg[4] == syncMsgBulkRequest {
			requests++
		}
	}
	if requests == 0 {
		t.Fatal("a reconcile skipped for a zone-map change withheld its BulkAck and asked for no " +
			"replacement bulk: the sender's barrier fence waits on that ack, so every manual " +
			"failover is refused until the sender's 35s retry (#18521)")
	}
	if requests > 2 {
		t.Fatalf("queued %d bulk requests for two skipped bulks", requests)
	}
}

// A receiver that lost the connection while settling asks for nothing: the
// reconnect re-primes.
func TestSkippedReconcileRerequestDropsWhenDisconnected18521(t *testing.T) {
	rx, _ := receiver9655(t, false, map[uint16]int{1: 1, 5: 5})
	rx.testZoneMapSettle = 20 * time.Millisecond
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1})
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	if !waitFor18521(t, 5*time.Second, func() bool { return !rx.bulkRerequestInFlight.Load() }) {
		t.Fatal("the re-request never left its settle wait")
	}
	rx.wg.Wait()
	if n := len(rx.sendCh); n != 0 {
		t.Fatalf("a disconnected receiver queued %d frames", n)
	}
}

// The settle wait is capped: a map that never stops moving still gets its
// request once zoneMapSettleMax passes.
func TestSkippedReconcileRerequestIsCappedUnderChurn18521(t *testing.T) {
	rx, _ := receiver9655(t, false, map[uint16]int{1: 1, 5: 5})
	rx.stats.Connected.Store(true)
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
