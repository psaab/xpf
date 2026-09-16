package cluster

// #9752 round 4 item 1: the fence covers EVERY transmission path, not just
// the four public queue functions. The sweep resends through its own
// stamp→encode→queueMessage loop; the bulk through stamp→encode→direct
// socket writes. Both judge the same fence now: sweep skips, bulk aborts
// (no BulkEnd — an incomplete authoritative window must never complete).
//
// Production shapes throughout: real syncSweep, real doBulkSync over a
// net.Pipe into a real receiver apply, real capability frames.

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func sweepFenceFixture9752(t *testing.T, sessionID uint64) (*SessionSync, *mockSweepDP, dataplane.SessionKey) {
	t.Helper()
	base := monotonicSeconds()
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 47912, DstPort: 5203}
	dp := &mockSweepDP{
		// As the BPF mirror holds it: sync-only fields always 0.
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {State: dataplane.SessStateEstablished, Created: base - 5, SessionID: sessionID, RTFlowSessionID: sessionID},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base - 10
	// Announce the stamp once (delta path), so the sweep's mirror-sourced
	// resend restores it from the send memo — then drain the announcement.
	ss.QueueSessionV4(key, dataplane.SessionValue{SessionID: sessionID, RTFlowSessionID: sessionID,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811})
	for len(ss.sendCh) > 0 {
		<-ss.sendCh
	}
	return ss, dp, key
}

func TestSweepSkipsStampedForAnIncapablePeer9752(t *testing.T) {
	ss, _, _ := sweepFenceFixture9752(t, 77)
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly))
	ss.syncSweep()
	if got := len(ss.sendCh); got != 0 {
		t.Fatalf("sweep queued %d frames to an incapable peer; the resend path bypasses the fence", got)
	}
	if got := ss.stats.InstallsSuppressedNoPeerInstallTable.Load(); got == 0 {
		t.Error("sweep skip did not count; silent withholding is invisible debt")
	}
}

func TestSweepSendsStampedToACapablePeer9752(t *testing.T) {
	ss, _, key := sweepFenceFixture9752(t, 77)
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
	ss.syncSweep()
	key2, val2 := drainSessionV4(t, ss)
	if key2 != key {
		t.Fatal("sweep frame does not name the swept session")
	}
	if val2.InstallTableDomain != 525590 || val2.InstallTableCheck != 3318534811 {
		t.Fatalf("capable peer's sweep resend lost the stamp: (%d,%d)",
			val2.InstallTableDomain, val2.InstallTableCheck)
	}
}

// pumpBulkFenced9752 runs a sender bulk into a receiver like pumpBulk, but
// expects refusal: it reads until the sender returns, feeds every frame,
// and reports the sender error plus whether a BulkEnd completed.
func pumpBulkFenced9752(t *testing.T, senderSS, receiverSS *SessionSync) (sendErr error, bulkEnd bool) {
	t.Helper()
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	senderSS.mu.Lock()
	senderSS.conn0 = local
	senderSS.mu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- senderSS.doBulkSync() }()
	for {
		// The sender aborts without closing the pipe: stop as soon as it
		// reports instead of waiting out a read deadline.
		select {
		case sendErr := <-errCh:
			return sendErr, bulkEnd
		default:
		}
		if err := peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		mt, payload, err := readSyncFrame(peer)
		if err != nil {
			continue // timeout: re-check the sender before the next read
		}
		receiverSS.handleMessage(nil, mt, payload)
		if mt == syncMsgBulkEnd {
			bulkEnd = true
		}
	}
}

func TestBulkAbortsForAnIncapablePeer9752(t *testing.T) {
	senderSS, _ := newBulk6031Primary(t)
	receiverSS, receiverDP := newBulk6031Standby(t)
	// Table truth holds a STAMPED live session (userspace production shape).
	stampedLive := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 47912, DstPort: 5203}
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: stampedLive, Value: dataplane.SessionValue{
				State: dataplane.SessStateEstablished, IngressZone: 5,
				SessionID: 77, RTFlowSessionID: 77,
				InstallTableDomain: 525590, InstallTableCheck: 3318534811,
			}},
		}}, nil
	}
	senderSS.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly))

	sendErr, bulkEnd := pumpBulkFenced9752(t, senderSS, receiverSS)
	if !errors.Is(sendErr, errBulkFencedForPeer) {
		t.Fatalf("doBulkSync error = %v, want the fence sentinel", sendErr)
	}
	if bulkEnd {
		t.Fatal("a fenced bulk completed its window; the receiver reconciled against an incomplete snapshot")
	}
	if !senderSS.bulkFencedForPeer.Load() {
		t.Error("fence abort did not latch; every redrive would burn a full walk")
	}
	// No reconcile ran: the standby's stale session survives (it is NOT
	// deleted by an incomplete window), and the VRRP hold never released
	// (no BulkEnd → no OnBulkSyncReceived — asserted via bulkInProgress).
	if _, ok := receiverDP.v4sessions[staleOnStandby]; !ok {
		t.Error("an aborted window reconciled anyway; the stale session is gone")
	}
	receiverSS.bulkMu.Lock()
	inProgress := receiverSS.bulkInProgress
	receiverSS.bulkMu.Unlock()
	if !inProgress {
		t.Error("receiver closed the window without BulkEnd; a later BulkEnd could complete a holed snapshot")
	}
	// Second attempt skips quietly without walking (latch).
	if err := senderSS.doBulkSync(); !errors.Is(err, errBulkFencedForPeer) {
		t.Fatalf("latched bulk error = %v, want the fence sentinel", err)
	}
}

func TestBulkCompletesForACapablePeer9752(t *testing.T) {
	senderSS, _ := newBulk6031Primary(t)
	receiverSS, receiverDP := newBulk6031Standby(t)
	stampedLive := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 47912, DstPort: 5203}
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: stampedLive, Value: dataplane.SessionValue{
				State: dataplane.SessStateEstablished, IngressZone: 5,
				SessionID: 77, RTFlowSessionID: 77,
				InstallTableDomain: 525590, InstallTableCheck: 3318534811,
			}},
		}}, nil
	}
	senderSS.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
	pumpBulk(t, senderSS, receiverSS)
	if senderSS.bulkFencedForPeer.Load() {
		t.Error("capable bulk latched the fence")
	}
	if _, ok := receiverDP.v4sessions[stampedLive]; !ok {
		t.Error("capable peer did not install the bulked session")
	}
	if _, ok := receiverDP.v4sessions[staleOnStandby]; ok {
		t.Error("capable bulk did not reconcile the stale session")
	}
}

func capableFrame9752(t *testing.T) []byte {
	t.Helper()
	return capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity)
}

func incapableFrame9752(t *testing.T) []byte {
	t.Helper()
	return capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly)
}

// TestSweepWithholdsUnannouncedOnPBRActiveNode9752 pins round 5 item 1: a
// mirror (0,0) this node never announced is suspect on a PBR-active node
// (in-race delta, foreign row, or post-cap) — the sweep withholds it from
// incapable peers instead of passing it as genuine-default.
func TestSweepWithholdsUnannouncedOnPBRActiveNode9752(t *testing.T) {
	base := monotonicSeconds()
	pbrKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{8, 8, 8, 8},
		Protocol: 6, SrcPort: 47912, DstPort: 443}
	plainKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 103}, DstIP: [4]byte{8, 8, 4, 4},
		Protocol: 6, SrcPort: 47913, DstPort: 443}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			pbrKey:   {State: dataplane.SessStateEstablished, Created: base - 5, SessionID: 77, RTFlowSessionID: 77},
			plainKey: {State: dataplane.SessStateEstablished, Created: base - 5, SessionID: 78, RTFlowSessionID: 78},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base - 10
	// Announce ONLY the PBR session (delta path): the plain row stays
	// memo-miss, and the node is PBR-active.
	ss.QueueSessionV4(pbrKey, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811})
	for len(ss.sendCh) > 0 {
		<-ss.sendCh
	}
	if !ss.pbrAnnouncedForFence.Load() {
		t.Fatal("FIXTURE: announcing a stamp must set the PBR-active latch")
	}
	ss.handleMessage(nil, syncMsgPeerCapabilities, incapableFrame9752(t))
	ss.syncSweep()
	if got := len(ss.sendCh); got != 0 {
		t.Fatalf("sweep queued %d frames to an incapable peer on a PBR-active node; "+
			"unannounced mirror (0,0)s must be withheld, not passed as genuine", got)
	}
}

// TestSweepSendsUnannouncedOnInactiveNode9752 is the control: a node that
// never announced a stamp (kernel dataplanes always land here) sends
// mirror (0,0)s normally — legacy behavior preserved.
func TestSweepSendsUnannouncedOnInactiveNode9752(t *testing.T) {
	base := monotonicSeconds()
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 103}, DstIP: [4]byte{8, 8, 4, 4},
		Protocol: 6, SrcPort: 47913, DstPort: 443}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {State: dataplane.SessStateEstablished, Created: base - 5, SessionID: 78, RTFlowSessionID: 78},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base - 10
	ss.handleMessage(nil, syncMsgPeerCapabilities, incapableFrame9752(t))
	ss.syncSweep()
	if got := len(ss.sendCh); got != 1 {
		t.Fatalf("sendCh holds %d, want 1: inactive nodes must sweep normally", got)
	}
}

// TestBulkStoreWalkAbortsOnUnannouncedPBRActive9752: a store-mirror bulk
// (lossy rows, no helper truth) aborts on an unannounced row when the node
// is PBR-active — it must not frame the suspect (0,0) as genuine.
func TestBulkStoreWalkAbortsOnUnannouncedPBRActive9752(t *testing.T) {
	senderSS, _ := newBulk6031Primary(t)
	receiverSS, _ := newBulk6031Standby(t)
	pbrKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{8, 8, 8, 8},
		Protocol: 6, SrcPort: 47912, DstPort: 443}
	// Delta-announce the PBR session (records + sets the latch), but keep
	// it OUT of the walked store rows below: the walk holds only an
	// unannounced mirror row.
	senderSS.QueueSessionV4(pbrKey, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811})
	walk := &bulkWalk{source: "test-mirror", readsDuringWindow: true}
	plainKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 103}, DstIP: [4]byte{8, 8, 4, 4},
		Protocol: 6, SrcPort: 47913, DstPort: 443}
	walk.forEachV4 = func(yield func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
		yield(plainKey, dataplane.SessionValue{SessionID: 78, RTFlowSessionID: 78})
		return nil
	}
	walk.forEachV6 = func(yield func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
		return nil
	}
	senderSS.handleMessage(nil, syncMsgPeerCapabilities, incapableFrame9752(t))
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	senderSS.mu.Lock()
	senderSS.conn0 = local
	senderSS.mu.Unlock()
	errCh := make(chan error, 1)
	go func() { errCh <- senderSS.bulkSyncWindow(walk) }()
	sawEnd := false
	for {
		if err := peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		select {
		case err := <-errCh:
			if !errors.Is(err, errBulkFencedForPeer) {
				t.Fatalf("bulk error = %v, want the fence sentinel", err)
			}
			if sawEnd {
				t.Fatal("fenced bulk completed its window")
			}
			return
		default:
		}
		mt, payload, err := readSyncFrame(peer)
		if err != nil {
			continue
		}
		receiverSS.handleMessage(nil, mt, payload)
		if mt == syncMsgBulkEnd {
			sawEnd = true
		}
	}
}

// TestBulkHelperTruthUnstampedPasses9752: helper-truth (0,0)s are
// authoritative (the helper said default) — the miss rule never touches
// them, even on a PBR-active node to an incapable peer.
func TestBulkHelperTruthUnstampedPasses9752(t *testing.T) {
	senderSS, _ := newBulk6031Primary(t)
	receiverSS, _ := newBulk6031Standby(t)
	plainKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 103}, DstIP: [4]byte{8, 8, 4, 4},
		Protocol: 6, SrcPort: 47913, DstPort: 443}
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: plainKey, Value: dataplane.SessionValue{
				State: dataplane.SessStateEstablished, IngressZone: 5,
				SessionID: 78, RTFlowSessionID: 78,
			}},
		}}, nil
	}
	// PBR-active (sticky set), peer incapable: the authoritative (0,0) must
	// still flow and the window must complete.
	senderSS.pbrAnnouncedForFence.Store(true)
	senderSS.handleMessage(nil, syncMsgPeerCapabilities, incapableFrame9752(t))
	pumpBulk(t, senderSS, receiverSS)
	if senderSS.bulkFencedForPeer.Load() {
		t.Error("authoritative bulk latched the fence")
	}
}

// TestBulkRevalidatesLatchedFenceOnCapablePeer9752 pins round 5 item 4: a
// refuse→learn+clear→store-true interleave leaves latch-set + capable peer.
// The next bulk must revalidate and proceed — not skip quietly forever. The
// latch set after learning simulates exactly that interleave outcome
// (deterministic; a real-thread race would be flaky by nature).
func TestBulkRevalidatesLatchedFenceOnCapablePeer9752(t *testing.T) {
	senderSS, _ := newBulk6031Primary(t)
	receiverSS, receiverDP := newBulk6031Standby(t)
	stampedLive := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{8, 8, 8, 8},
		Protocol: 6, SrcPort: 47912, DstPort: 443}
	senderSS.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{V4: []dataplane.SessionEntryV4{
			{Key: stampedLive, Value: dataplane.SessionValue{
				State: dataplane.SessStateEstablished, IngressZone: 5,
				SessionID: 77, RTFlowSessionID: 77,
				InstallTableDomain: 525590, InstallTableCheck: 3318534811,
			}},
		}}, nil
	}
	senderSS.handleMessage(nil, syncMsgPeerCapabilities, capableFrame9752(t))
	// The raced outcome: latch stored AFTER the capable clear.
	senderSS.bulkFencedForPeer.Store(true)
	pumpBulk(t, senderSS, receiverSS)
	if senderSS.bulkFencedForPeer.Load() {
		t.Error("revalidation did not clear the stale latch")
	}
	if _, ok := receiverDP.v4sessions[stampedLive]; !ok {
		t.Error("revalidated bulk did not install the session")
	}
}
