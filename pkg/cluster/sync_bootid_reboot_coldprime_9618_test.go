package cluster

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9618: a peer reboot classified by the BulkStart BOOT ID (the order #9174
// V014 did not cover) must owe the replacement a cold prime.

var (
	incA9618 = bootIncarnation{0xa0, 0xa1}
	incB9618 = bootIncarnation{0xb0, 0xb1}
)

// drainedPipe9618 is a net.Pipe whose far end is read and discarded, so frames
// the SessionSync writes (a BulkAck, a capabilities exchange) never block on a
// peer that does not read.
func drainedPipe9618(t *testing.T) net.Conn {
	t.Helper()
	local, peer := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	t.Cleanup(func() { local.Close(); peer.Close() })
	return local
}

// primedPair9618 is an established, primed and acked HA pair on fabric 0.
func primedPair9618(t *testing.T) *SessionSync {
	t.Helper()
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn
	c0 := drainedPipe9618(t)
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
	c1 := drainedPipe9618(t)
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

// The corpse can leave the registry on its OWN — its receive loop ends — after
// the replacement installed on the empty slot but before the replacement's
// BulkStart. Nothing classified the reboot at install time, the partial
// disconnect owes nothing, and the boot-id switch that finally sees it has no
// corpse left to evict. It must still arm: gating the arm on an eviction loses
// exactly the reboot this issue is about.
func TestBootIDRebootArmsAfterTheCorpseAlreadyLeft_9618(t *testing.T) {
	ss := primedPair9618(t)
	c1 := drainedPipe9618(t)
	ss.installConn(1, c1)
	if ss.needColdPrime.Load() {
		t.Fatalf("attribution: the empty-slot install armed the cold prime")
	}
	ss.mu.Lock()
	corpse := ss.conn0
	ss.mu.Unlock()
	ss.handleDisconnect(corpse)
	if ss.needColdPrime.Load() {
		t.Fatalf("attribution: the corpse's partial disconnect armed the cold prime, so this cell would not isolate the switch")
	}
	incBefore := ss.peerIncarnation
	ss.handleMessage(c1, syncMsgBulkStart, bulkStartPayload(1, &incB9618))
	if ss.peerIncarnation == incBefore {
		t.Fatalf("attribution: the boot-id switch did not run (incarnation stayed %d)", incBefore)
	}
	if !ss.needColdPrime.Load() {
		t.Errorf("#9618: the boot-id switch retired the incarnation with no corpse left to evict and owed nothing; " +
			"the replacement's table stays empty")
	}
}

// Negative control: zero -> X is the FIRST incarnated prime, not a reboot
// (#6910's distinction). It must not arm.
func TestFirstIncarnatedPrimeDoesNotArmColdPrime_9618(t *testing.T) {
	ss := newAckTestSync(t)
	c0 := drainedPipe9618(t)
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
	c1 := drainedPipe9618(t)
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
// cold-prime re-drive must then send exactly one authoritative bulk, carrying
// the established session, on the replacement's connection and clear the latch.
func TestBootIDRebootColdPrimeIsDrivenToTheReplacement_9618(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	established := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 7, 1}, DstIP: [4]byte{10, 0, 8, 1}, Protocol: 6, SrcPort: 1200, DstPort: 80}
	ss.SetRuntime(&mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{established: {IngressZone: 2}},
		sessionCounter: 1,
	})
	ss.IsPrimaryFn = func() bool { return true }
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

	ss.lastSweepTime = monotonicSeconds()
	for i := 0; i < 3; i++ {
		ss.syncSweep()
	}
	if got := ss.stats.BulkSyncs.Load() - bulksBefore; got != 1 {
		t.Errorf("#9618: want exactly one authoritative bulk for the reboot, got %d", got)
	}
	// #9626: writing the bulk discharges nothing. The replacement's BulkAck does.
	if !ss.needColdPrime.Load() {
		t.Errorf("#9626: the owed cold prime was discharged before the replacement acknowledged the bulk")
	}
	epoch, _, ok := ss.PendingBulkAck()
	if !ok {
		t.Fatalf("#9618: the sweep's bulk left no pending ack to discharge the debt with")
	}
	ss.handleMessage(c1, syncMsgBulkAck, epochPayload9626(epoch))
	if ss.needColdPrime.Load() {
		t.Errorf("#9618: the replacement's BulkAck did not discharge the owed cold prime; the next reboot signal would find it still armed")
	}
	if starts, ends := countBulkMarkers(t, c1.bytes()); starts == 0 || ends == 0 {
		t.Errorf("#9618: no bulk window reached the REPLACEMENT's connection (starts=%d ends=%d)", starts, ends)
	}
	if n := countFrames9618(t, c1.bytes(), syncMsgSessionV4); n == 0 {
		t.Errorf("#9618: the re-sent window reached the replacement but carried no session; the established flow is still missing there")
	}
	if starts, _ := countBulkMarkers(t, c0.bytes()); starts != 0 {
		t.Errorf("attribution: a bulk was sent to the evicted corpse (starts=%d)", starts)
	}
}

func countFrames9618(t *testing.T, buf []byte, typ uint8) int {
	t.Helper()
	n := 0
	for len(buf) > 0 {
		if len(buf) < syncHeaderSize {
			t.Fatalf("truncated frame header: %d bytes left", len(buf))
		}
		ft := buf[4]
		pl := binary.LittleEndian.Uint32(buf[8:12])
		buf = buf[syncHeaderSize:]
		if uint32(len(buf)) < pl {
			t.Fatalf("truncated payload: want %d, have %d", pl, len(buf))
		}
		buf = buf[pl:]
		if ft == typ {
			n++
		}
	}
	return n
}
