package cluster

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func replayBulkFrames12166(t *testing.T, receiver *SessionSync, conn net.Conn, buf []byte) (starts int) {
	t.Helper()
	for len(buf) > 0 {
		if len(buf) < syncHeaderSize || string(buf[:4]) != "BPSY" {
			t.Fatal("bulk retry emitted an invalid frame")
		}
		typ := buf[4]
		n := int(binary.LittleEndian.Uint32(buf[8:12]))
		buf = buf[syncHeaderSize:]
		if n < 0 || n > len(buf) {
			t.Fatalf("bulk retry frame length %d exceeds remaining %d", n, len(buf))
		}
		payload := buf[:n]
		buf = buf[n:]
		if typ == syncMsgBulkStart {
			starts++
		}
		receiver.handleMessage(conn, typ, payload)
	}
	return starts
}

func bulkAckEpochs12166(conn *frameCaptureConn) []uint64 {
	var epochs []uint64
	for _, frame := range conn.frames {
		if len(frame) >= syncHeaderSize+8 && frame[4] == syncMsgBulkAck {
			epochs = append(epochs, binary.LittleEndian.Uint64(frame[syncHeaderSize:]))
		}
	}
	return epochs
}

func TestForcedResyncRetriesWithheldBulk12166(t *testing.T) {
	const zone = uint16(2)
	liveKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 1}, DstIP: [4]byte{10, 0, 4, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	flakyKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 3}, DstIP: [4]byte{10, 0, 4, 3}, Protocol: 6, SrcPort: 3000, DstPort: 80}
	ghostKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 2}, DstIP: [4]byte{10, 0, 4, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}

	primaryDP := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
		liveKey:  {IsReverse: 0, IngressZone: zone},
		flakyKey: {IsReverse: 0, IngressZone: zone},
	}, sessionCounter: 1}
	primary := NewSessionSync(":0", "10.0.0.2:4785", primaryDP)
	primary.IsPrimaryFn = func() bool { return true }
	standbyDP := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			liveKey:  {IsReverse: 0, IngressZone: zone},
			ghostKey: {IsReverse: 0, IngressZone: zone},
		},
		failSetV4: map[dataplane.SessionKey]error{flakyKey: errors.New(
			"mirror synced v4 session to userspace helper: session helper unreachable: read session response: i/o timeout")},
		sessionCounter: 1,
	}
	standby := NewSessionSync(":0", "10.0.0.1:4785", standbyDP)
	standby.IsPrimaryFn = func() bool { return false }
	standby.IsPrimaryForRGFn = func(int) bool { return false }
	standby.SetZoneRGMap(map[uint16]int{zone: 2})

	primaryConn := newBulkCaptureConn()
	primary.mu.Lock()
	primary.conn0 = primaryConn
	primary.mu.Unlock()
	primary.stats.Connected.Store(true)
	mkDelete := func(n int) []byte { return encodeDeleteV4(deleteKeyN(n), 0, false) }
	primary.deleteJournal.cap = 2
	primary.deleteJournal.entries = [][]byte{mkDelete(1), mkDelete(2), mkDelete(3)}
	primary.rejournalTail([][]byte{mkDelete(4), mkDelete(5), mkDelete(6)})
	if !primary.forceResync.Load() || primary.needColdPrime.Load() {
		t.Fatalf("fixture must arm only forced resync: force=%v cold-prime=%v",
			primary.forceResync.Load(), primary.needColdPrime.Load())
	}

	standbyLocal, standbyPeer := net.Pipe()
	defer standbyLocal.Close()
	defer standbyPeer.Close()
	standbyConn := &frameCaptureConn{Conn: standbyLocal}
	primary.syncSweep()
	first := primaryConn.bytes()
	if got := replayBulkFrames12166(t, standby, standbyConn, first); got != 1 {
		t.Fatalf("initial forced resync starts=%d, want 1", got)
	}
	if got := bulkAckEpochs12166(standbyConn); len(got) != 0 {
		t.Fatalf("transient install failure unexpectedly acked initial bulk: %v", got)
	}
	if !standby.TransferReadiness().BulkReceiveInProgress || standby.TransferReadiness().ReadyForManualFailover() {
		t.Fatal("withheld initial bulk did not retain the standby readiness gate")
	}
	if _, exists := standbyDP.v4sessions[ghostKey]; !exists {
		t.Fatal("incomplete initial snapshot reconciled away the ghost session")
	}

	delete(standbyDP.failSetV4, flakyKey)
	primary.pendingBulkAckSince.Store(MonotonicNanos() - int64(BulkAckPendingRetryAfter+time.Minute))
	for range 5 {
		primary.syncSweep()
	}
	allFrames := primaryConn.bytes()
	retryFrames := allFrames[len(first):]
	if got := replayBulkFrames12166(t, standby, standbyConn, retryFrames); got != 1 {
		t.Fatalf("aged forced-resync debt emitted %d retry bulks, want exactly 1", got)
	}
	acks := bulkAckEpochs12166(standbyConn)
	if len(acks) != 1 {
		t.Fatalf("recovered authoritative bulk acks=%v, want one ack", acks)
	}
	primary.handleMessage(primaryConn, syncMsgBulkAck, epochPayload9626(acks[0]))
	if _, exists := standbyDP.v4sessions[ghostKey]; exists {
		t.Fatal("successful retry did not reconcile the stale ghost session")
	}
	if got := standby.TransferReadiness(); got.BulkReceiveInProgress || !got.ReadyForManualFailover() {
		t.Fatalf("standby did not recover readiness after retry: %+v", got)
	}
	if got := primary.TransferReadiness(); !got.ReadyForManualFailover() {
		t.Fatalf("primary retained stale outbound-bulk readiness debt after ack: %+v", got)
	}
	if _, _, pending := primary.PendingBulkAck(); pending {
		t.Fatal("matching retry BulkAck did not clear the primary pending bulk")
	}

	for i := range 1000 {
		key := dataplane.SessionKey{SrcIP: [4]byte{10, 9, byte(i >> 8), byte(i)}, DstIP: [4]byte{10, 8, 0, 1}, Protocol: 6, SrcPort: uint16(1000 + i), DstPort: 443}
		standby.handleMessage(standbyConn, syncMsgSessionV4,
			encodeSessionV4Payload(key, dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: zone}))
	}
	standby.bulkMu.Lock()
	accumulated := len(standby.bulkRecvV4)
	standby.bulkMu.Unlock()
	if accumulated != 0 || standby.stats.BulkSyncEndTime.Load() == 0 {
		t.Fatalf("recovered bulk still accumulated incremental churn: bulkRecvV4=%d BulkSyncEndTime=%d",
			accumulated, standby.stats.BulkSyncEndTime.Load())
	}
}

func TestBulkRetrySourceFailureRetainsReadiness12166(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }
	conn := newBulkCaptureConn()
	ss.mu.Lock()
	ss.conn0 = conn
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)
	if err := ss.BulkSync(); err != nil {
		t.Fatalf("initial authoritative bulk: %v", err)
	}
	ss.pendingBulkAckSince.Store(MonotonicNanos() - int64(BulkAckPendingRetryAfter+time.Minute))
	ss.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{}, errors.New("snapshot unavailable")
	}

	ss.syncSweep()
	readiness := ss.TransferReadiness()
	if !readiness.BulkAckRetryOwed || readiness.ReadyForManualFailover() {
		t.Fatalf("failed source retry opened manual-failover readiness: %+v", readiness)
	}
	if got := readiness.Reason(); got != "outbound authoritative bulk retry is owed" {
		t.Fatalf("readiness reason=%q, want retry-debt explanation", got)
	}
	if got := ss.stats.BulkSyncs.Load(); got != 1 {
		t.Fatalf("source failure emitted another completed bulk: %d", got)
	}
}
