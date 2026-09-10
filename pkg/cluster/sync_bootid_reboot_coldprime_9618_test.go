package cluster

import "testing"

// #9618: a peer reboot classified by the BulkStart BOOT ID (the order #9174
// V014 did not cover) must owe the replacement a cold prime.

var (
	incA9618 = bootIncarnation{0xa0, 0xa1}
	incB9618 = bootIncarnation{0xb0, 0xb1}
)

// primedPair9618 is an established, primed and acked HA pair on fabric 0.
func primedPair9618(t *testing.T) *SessionSync {
	t.Helper()
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn
	c0 := pipeConn(t)
	ss.installConn(0, c0)
	ss.handleMessage(c0, syncMsgBulkStart, bulkStartPayload(1, &incA9618))
	ss.handleMessage(c0, syncMsgBulkEnd, bulkStartPayload(1, &incA9618))
	ss.needColdPrime.Store(false)
	ss.outboundBulkAcked.Store(true)
	return ss
}

func TestBootIDRebootArmsColdPrime_9618(t *testing.T) {
	ss := primedPair9618(t)
	incBefore := ss.peerIncarnation

	// The replacement dials the EMPTY alternate slot before any heartbeat
	// raised the epoch, so installConn has nothing to classify on.
	c1 := pipeConn(t)
	d := ss.installConn(1, c1)
	if ss.needColdPrime.Load() || d.shouldColdPrime {
		t.Fatalf("attribution: the empty-slot install already armed the cold prime "+
			"(needColdPrime=%v shouldColdPrime=%v), so this cell would not isolate the boot-id path",
			ss.needColdPrime.Load(), d.shouldColdPrime)
	}

	ss.handleMessage(c1, syncMsgBulkStart, bulkStartPayload(1, &incB9618))

	ss.mu.Lock()
	corpseLive := ss.conn0 != nil
	inc := ss.peerIncarnation
	ss.mu.Unlock()
	if corpseLive || inc == incBefore {
		t.Fatalf("attribution: the boot-id switch did not run (conn0 live=%v, incarnation %d -> %d)",
			corpseLive, incBefore, inc)
	}
	if !ss.needColdPrime.Load() {
		t.Errorf("#9618: BulkStart carried a NEW boot id, the incarnation advanced and the corpse on " +
			"fabric 0 was evicted, but needColdPrime is false. The prior incarnation's acked bulk " +
			"suppresses the ordinary resend, so the survivor never sends its table to the rebooted " +
			"(empty) peer and the next failover to it blackholes every established flow (#5480)")
	}
	if !ss.outboundBulkAcked.Load() {
		t.Fatalf("attribution: outboundBulkAcked was cleared, so a resend would be owed without the " +
			"latch and this cell would not bind it")
	}
}

// Negative control: zero -> X is the FIRST incarnated prime, not a reboot
// (#6910's distinction). It must not arm.
func TestFirstIncarnatedPrimeDoesNotArmColdPrime_9618(t *testing.T) {
	ss := newAckTestSync(t)
	c0 := pipeConn(t)
	ss.installConn(0, c0)
	ss.needColdPrime.Store(false)
	incBefore := ss.peerIncarnation
	ss.handleMessage(c0, syncMsgBulkStart, bulkStartPayload(1, &incA9618))
	if ss.needColdPrime.Load() {
		t.Errorf("#9618 control: the first incarnated prime armed a cold prime; only X -> Y is a reboot")
	}
	if ss.peerIncarnation != incBefore {
		t.Errorf("#9618 control: the first incarnated prime advanced the incarnation %d -> %d",
			incBefore, ss.peerIncarnation)
	}
}

// Negative control: the SAME boot bringing up its second fabric and priming on
// it is routine, not a reboot. It must not arm, and must not evict fabric 0.
func TestSameBootSecondFabricBulkStartDoesNotArmColdPrime_9618(t *testing.T) {
	ss := primedPair9618(t)
	c1 := pipeConn(t)
	ss.installConn(1, c1)
	ss.handleMessage(c1, syncMsgBulkStart, bulkStartPayload(2, &incA9618))
	ss.mu.Lock()
	c0Live := ss.conn0 != nil
	ss.mu.Unlock()
	if ss.needColdPrime.Load() {
		t.Errorf("#9618 control: a same-boot BulkStart on the second fabric armed a cold prime")
	}
	if !c0Live {
		t.Errorf("#9618 control: a same-boot BulkStart on the second fabric evicted fabric 0")
	}
}

// The latch alone is not the fix: the owed prime must reach the replacement.
// After the boot-id switch, the evicted corpse's receive loop ends in a STALE
// disconnect, which must not discharge the debt, and the sweep's owed
// cold-prime re-drive must then send exactly one authoritative bulk on the
// replacement's connection and clear the latch.
func TestBootIDRebootColdPrimeIsDrivenToTheReplacement_9618(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.SetRuntime(&mockSweepDP{})
	c0, c1 := newBulkCaptureConn(), newBulkCaptureConn()
	t.Cleanup(func() { c0.Close(); c1.Close() })

	ss.installConn(0, c0)
	ss.handleMessage(c0, syncMsgBulkStart, bulkStartPayload(1, &incA9618))
	ss.handleMessage(c0, syncMsgBulkEnd, bulkStartPayload(1, &incA9618))
	ss.needColdPrime.Store(false)
	ss.outboundBulkAcked.Store(true)
	bulksBefore := ss.stats.BulkSyncs.Load()

	ss.installConn(1, c1)
	if ss.needColdPrime.Load() {
		t.Fatalf("attribution: the empty-slot install armed the cold prime, so this cell would not isolate the boot-id path")
	}
	ss.handleMessage(c1, syncMsgBulkStart, bulkStartPayload(1, &incB9618))
	if !ss.needColdPrime.Load() {
		t.Fatalf("#9618: the boot-id switch did not arm the cold prime")
	}

	ss.handleDisconnect(c0)
	if !ss.needColdPrime.Load() {
		t.Fatalf("#9618: the evicted corpse's stale disconnect discharged the owed cold prime")
	}
	if !ss.IsConnected() {
		t.Fatalf("attribution: the replacement on fabric 1 must still be connected")
	}

	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = monotonicSeconds()
	for i := 0; i < 3 && ss.needColdPrime.Load(); i++ {
		ss.syncSweep()
	}
	if ss.needColdPrime.Load() {
		t.Errorf("#9618: the sweep never discharged the owed cold prime; the replacement stays empty")
	}
	if got := ss.stats.BulkSyncs.Load() - bulksBefore; got != 1 {
		t.Errorf("#9618: want exactly one authoritative bulk for the reboot, got %d", got)
	}
	if starts, ends := countBulkMarkers(t, c1.bytes()); starts == 0 || ends == 0 {
		t.Errorf("#9618: no bulk window reached the REPLACEMENT's connection (starts=%d ends=%d)", starts, ends)
	}
	if starts, _ := countBulkMarkers(t, c0.bytes()); starts != 0 {
		t.Errorf("attribution: a bulk was sent to the evicted corpse (starts=%d)", starts)
	}
}
