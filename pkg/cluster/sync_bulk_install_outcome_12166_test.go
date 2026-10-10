package cluster

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #12166: a transient helper transport failure is not a semantic import
// refusal. A bulk containing such a failure must keep the receive window and
// HA hold open, withhold BulkAck, and let the sender's bounded bulk-prime retry
// re-request the authoritative table. A later successful bulk completes; a
// semantic refusal remains the intentional-ACK path.
func TestBulkAckWaitsForTransientSessionInstall12166(t *testing.T) {
	transientA := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1001, DstPort: 80}
	transientB := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 3}, DstIP: [4]byte{10, 0, 0, 4}, SrcPort: 1002, DstPort: 80}
	refused := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 5}, DstIP: [4]byte{10, 0, 0, 6}, SrcPort: 1003, DstPort: 80}
	healthy := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{10, 0, 0, 7}, DstIP: [4]byte{10, 0, 0, 8}, SrcPort: 1004, DstPort: 80}
	transientV6 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1005, DstPort: 80}
	transientV6.SrcIP[15], transientV6.DstIP[15] = 1, 2
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		failSetV4: map[dataplane.SessionKey]error{
			transientA: errors.New("session table write failed"),
			transientB: errors.New("session table write failed"),
			refused:    dataplane.ErrSyncedImportRefused,
		},
		failSetV6: map[dataplane.SessionKeyV6]error{
			transientV6: errors.New("session table write failed"),
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneOwnership(ZoneRGMap{}, nil, nil)
	released := make(chan struct{}, 2)
	ss.OnBulkSyncReceived = func() { released <- struct{}{} }

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &frameCaptureConn{Conn: local}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	val6 := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2}
	writeBulk := func(epoch uint64) {
		ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(epoch, nil))
		for _, key := range []dataplane.SessionKey{transientA, transientB, refused, healthy} {
			ss.handleMessage(conn, syncMsgSessionV4, encodeSessionV4Payload(key, val))
		}
		ss.handleMessage(conn, syncMsgSessionV6, encodeSessionV6Payload(transientV6, val6))
		ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(epoch, nil))
	}

	writeBulk(1)
	// Give an erroneous asynchronous hold-release callback a bounded chance to
	// run; all other completion observables are synchronous in handleMessage.
	select {
	case <-released:
		t.Fatal("transient install failures released the HA sync hold")
	case <-time.After(50 * time.Millisecond):
	}
	if got := len(conn.frames); got != 0 {
		t.Fatalf("transient install failures produced %d ack frames; want BulkAck withheld", got)
	}
	if ss.BulkEverCompleted() || ss.stats.BulkSyncEndTime.Load() != 0 {
		t.Fatalf("incomplete bulk marked completed (ever=%v end=%d)", ss.BulkEverCompleted(), ss.stats.BulkSyncEndTime.Load())
	}
	if got := ss.TransferReadiness(); !got.BulkReceiveInProgress || got.ReadyForManualFailover() {
		t.Fatalf("incomplete bulk must remain a manual-failover readiness blocker, readiness=%+v", got)
	}
	if _, ok := dp.v4sessions[transientA]; ok {
		t.Fatal("fixture expected transient A's failed helper install to remain absent")
	}
	if _, ok := dp.v4sessions[transientB]; ok {
		t.Fatal("fixture expected transient B's failed helper install to remain absent")
	}
	if _, ok := dp.v6sessions[transientV6]; ok {
		t.Fatal("fixture expected transient IPv6 install to remain absent")
	}
	if _, ok := dp.v4sessions[healthy]; !ok {
		t.Fatal("fixture's later successful helper install did not land")
	}
	if ss.sessionMirrorWarnedV4.Load() {
		t.Fatal("fixture requires the later success to clear the mirror warning, isolating bulk outcome tracking")
	}
	if got := ss.stats.ImportsRefusedByHelper.Load(); got != 1 {
		t.Fatalf("semantic refusal count = %d, want 1", got)
	}

	// The bounded resend arrives as a fresh authoritative bulk. Its transient
	// installs now succeed, and the receiver can reconcile, ack, and release.
	delete(dp.failSetV4, transientA)
	delete(dp.failSetV4, transientB)
	delete(dp.failSetV6, transientV6)
	writeBulk(2)
	if len(conn.frames) != 1 {
		t.Fatalf("recovered bulk emitted %d frames, want one BulkAck", len(conn.frames))
	}
	ack := conn.frames[0]
	if len(ack) != syncHeaderSize+8 || ack[4] != syncMsgBulkAck || binary.LittleEndian.Uint64(ack[syncHeaderSize:]) != 2 {
		t.Fatalf("recovered bulk ack = %v, want BulkAck for epoch 2", ack)
	}
	if !ss.BulkEverCompleted() || ss.stats.BulkSyncEndTime.Load() == 0 {
		t.Fatal("recovered authoritative bulk did not complete")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("recovered authoritative bulk did not release the HA sync hold")
	}
	for _, key := range []dataplane.SessionKey{transientA, transientB, healthy} {
		if _, ok := dp.v4sessions[key]; !ok {
			t.Errorf("recovered bulk did not install %v", key)
		}
	}
	if _, ok := dp.v6sessions[transientV6]; !ok {
		t.Error("recovered bulk did not install the transient IPv6 session")
	}
	if _, ok := dp.v4sessions[refused]; ok {
		t.Error("semantic refusal unexpectedly installed a row")
	}
}
