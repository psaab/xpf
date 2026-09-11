package cluster

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

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
	ss.OnPeerConnected = func() {}
	c1 := pipeConn(t)
	ss.installConn(1, c1)
	before := ss.peerConnectedDispatches.Load()
	ss.handleMessage(c1, syncMsgBulkStart, bulkStartPayload(2, &incA9618))
	if n := ss.peerConnectedDispatches.Load() - before; n != 0 {
		t.Errorf("#9618 control: a same-boot BulkStart on the second fabric dispatched OnPeerConnected %d times", n)
	}
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
	established := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 7, 1}, DstIP: [4]byte{10, 0, 8, 1}, Protocol: 6, SrcPort: 1200, DstPort: 80}
	ss.SetRuntime(&mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{established: {IngressZone: 2}},
		sessionCounter: 1,
	})
	ss.IsPrimaryFn = func() bool { return true }
	peerConnected := make(chan struct{}, 4)
	ss.OnPeerConnected = func() { peerConnected <- struct{}{} }
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
	for len(peerConnected) > 0 {
		<-peerConnected // installs before the reboot is classified
	}
	ss.handleMessage(c1, syncMsgBulkStart, bulkStartPayload(1, &incB9618))
	if !ss.needColdPrime.Load() {
		t.Fatalf("#9618: the boot-id switch did not arm the cold prime")
	}
	select {
	case <-peerConnected:
	case <-time.After(2 * time.Second):
		t.Errorf("#9618: the boot-id switch retired the incarnation but never dispatched OnPeerConnected; " +
			"the epoch-first order of the same reboot does, and without it the new peer process gets no " +
			"DHCP-lease or IPsec-SA sync nudge and no config reconcile")
	}

	ss.handleDisconnect(c0)
	if !ss.needColdPrime.Load() {
		t.Fatalf("#9618: the evicted corpse's stale disconnect discharged the owed cold prime")
	}
	if !ss.IsConnected() {
		t.Fatalf("attribution: the replacement on fabric 1 must still be connected")
	}

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

// One reboot, BOTH classifiers: the heartbeat epoch is seen first (installConn
// retires the corpse and owes the prime; handleNewConnection sends it and
// dispatches OnPeerConnected), then the replacement's BulkStart carries the new
// boot id. That second classification evicts nothing and must neither dispatch
// the non-idempotent callback again nor re-arm a prime already sent.
func TestEpochFirstThenBootIDDispatchesAndArmsOnce_9618(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.SetRuntime(&mockSweepDP{})
	ss.IsPrimaryFn = func() bool { return true }
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn
	ss.OnPeerConnected = func() {}
	ctx, cancel := context.WithCancel(context.Background())
	c0, c1 := newBulkCaptureConn(), newBulkCaptureConn()
	t.Cleanup(func() { cancel(); c0.Close(); c1.Close() })

	ss.handleNewConnection(ctx, 0, c0, true)
	ss.handleMessage(c0, syncMsgBulkStart, bulkStartPayload(1, &incA9618))
	ss.handleMessage(c0, syncMsgBulkEnd, bulkStartPayload(1, &incA9618))

	src.epoch = 101 // the peer rebooted, and its heartbeat is seen first
	ss.handleNewConnection(ctx, 1, c1, true)
	ss.mu.Lock()
	corpseLive := ss.conn0 != nil
	ss.mu.Unlock()
	if corpseLive {
		t.Fatalf("attribution: the epoch-first install did not evict the corpse")
	}
	if ss.needColdPrime.Load() {
		t.Fatalf("attribution: the install-time cold prime did not complete, so a re-arm would be unobservable")
	}
	dispatched := ss.peerConnectedDispatches.Load()
	if dispatched < 2 {
		t.Fatalf("attribution: want both installs to have dispatched OnPeerConnected, got %d", dispatched)
	}

	ss.handleMessage(c1, syncMsgBulkStart, bulkStartPayload(1, &incB9618))
	if n := ss.peerConnectedDispatches.Load() - dispatched; n != 0 {
		t.Errorf("#9618: the boot-id classification of a reboot the epoch already handled dispatched "+
			"OnPeerConnected again (%d extra). The callback is not idempotent: it bumps the daemon's sync "+
			"connection epoch and can re-arm the readiness timer", n)
	}
	if ss.needColdPrime.Load() {
		t.Errorf("#9618: the boot-id classification re-armed a cold prime the epoch-first install already sent")
	}
}
