package cluster

import (
	"testing"
)

// heartbeat_10315_test.go — #10315: a KEYED node must reject an UNSIGNED
// heartbeat even when the peer has never authenticated in THIS process.
//
// The defect: heartbeatAuthDecision granted a first-contact grace —
// keyConfigured + no trailer + peerAuthSeen==false → ACCEPT — where
// peerAuthSeen is sticky for the life of the PROCESS. Restart xpfd on a keyed
// node and, before the genuine peer's first signed frame lands, one forged
// unsigned datagram is admitted: it refreshes lastSeen (marks a dead peer
// alive), rebuilds peer RG state, and runs election — demoting a
// sole-surviving primary to secondary (total forwarding outage). No key
// knowledge needed; L2/control-link access suffices.
//
// Session-sync removed the identical grace as a security bug (#5078:
// syncAuthDecision no longer consults peerAuthSeen at all); the heartbeat kept
// it. The fix mirrors #5078: key the decision on key-CONFIGURED, not on
// process-lifetime peerAuthSeen. An unsigned frame on a keyed node is rejected
// before it can refresh liveness or feed election.
//
// These cells drive heartbeatReceiver.admitFrame — the SAME function readLoop
// calls for every datagram — so accept/reject, lastSeen, peerAlive and the
// election outcome are production's, not a copy's.

var unsigned10315Key = []byte("10315-keyed-cluster-psk")

// keyedSolePrimary10315 builds the victim: a keyed single-node primary (RG0,
// priority 200) whose peer has never authenticated in this process — the
// post-restart window the issue names.
func keyedSolePrimary10315(t *testing.T) (*Manager, *heartbeatReceiver) {
	t.Helper()
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200})))
	<-m.Events() // drain the initial single-node election (promotes to primary)
	m.mu.Lock()
	m.controlAuthKey = unsigned10315Key
	m.mu.Unlock()
	if !m.IsLocalPrimary(0) {
		t.Fatal("setup: the victim must start as the sole RG0 primary")
	}
	if m.HeartbeatPeerAuthSeen() {
		t.Fatal("setup: the peer must not have authenticated in this process")
	}
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	m.mu.Lock()
	m.hbReceiver = r
	m.mu.Unlock()
	return m, r
}

// unsignedPrimaryClaim10315 is the forged frame: node 1 claiming RG0 primary
// with a HIGHER priority than the victim, carried with NO auth trailer.
func unsignedPrimaryClaim10315() (*HeartbeatPacket, []byte) {
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 250, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	frame := MarshalHeartbeat(pkt)
	if _, _, present := heartbeatAuthTrailer(frame); present {
		panic("fixture: the attacker frame must carry no auth trailer")
	}
	return pkt, frame
}

func rg0State(m *Manager) NodeState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.groups[0].State
}

// TestKeyedNodeRejectsUnsignedHeartbeatBeforePeerAuth_10315 is the core: on a
// keyed node with no prior peer auth, an unsigned frame is rejected and
// refreshes NOTHING — lastSeen stays 0 and the peer stays not-alive.
//
// RED on the pre-fix code: the grace accepts the frame, lastSeen is stamped
// and PeerAlive flips true — a dead peer marked alive by a forgery.
func TestKeyedNodeRejectsUnsignedHeartbeatBeforePeerAuth_10315(t *testing.T) {
	m, r := keyedSolePrimary10315(t)
	pkt, frame := unsignedPrimaryClaim10315()

	if r.lastSeen.Load() != 0 {
		t.Fatal("setup: lastSeen must start at 0 (peer never seen)")
	}
	if accepted := r.admitFrame(frame, pkt); accepted {
		t.Fatal("#10315: a KEYED node admitted an UNSIGNED heartbeat before the " +
			"peer ever authenticated — the first-contact grace is open")
	}
	if got := r.lastSeen.Load(); got != 0 {
		t.Fatalf("#10315: a rejected unsigned frame refreshed peer liveness "+
			"(lastSeen 0 -> %d) — a dead peer is kept looking alive", got)
	}
	if m.PeerAlive() {
		t.Fatal("#10315: a rejected unsigned frame marked the peer alive")
	}
	if m.HeartbeatPeerAuthSeen() {
		t.Fatal("an unsigned frame must never arm the peer-authenticated flag")
	}
}

// TestUnsignedHeartbeatDoesNotDemoteSolePrimary_10315 is the outage cell: the
// same forged frame claims primary with higher priority, which — if admitted —
// resolves dual-primary by priority and demotes the survivor to secondary.
//
// RED on the pre-fix code: the victim ends SECONDARY with the peer "alive",
// i.e. a total forwarding outage from one unauthenticated datagram.
func TestUnsignedHeartbeatDoesNotDemoteSolePrimary_10315(t *testing.T) {
	m, r := keyedSolePrimary10315(t)
	pkt, frame := unsignedPrimaryClaim10315()

	if st := rg0State(m); st != StatePrimary {
		t.Fatalf("setup: victim RG0 state = %v, want primary", st)
	}
	r.admitFrame(frame, pkt)
	if st := rg0State(m); st != StatePrimary {
		t.Fatalf("#10315: an UNSIGNED heartbeat demoted the sole primary (RG0 "+
			"state = %v) — one forged datagram is a total forwarding outage", st)
	}
	// Drain any election event the (rejected) frame must NOT have produced.
	select {
	case ev := <-m.Events():
		t.Fatalf("#10315: a rejected frame drove election (event %+v)", ev)
	default:
	}
}

// TestKeyedSignedHeartbeatStillAccepted_10315 is the positive control: a
// correctly-signed frame on the same keyed node is accepted, refreshes
// liveness, and arms the peer-authenticated flag. It passes both pre- and
// post-fix; without it a fix that rejects EVERYTHING would satisfy the two
// cells above.
func TestKeyedSignedHeartbeatStillAccepted_10315(t *testing.T) {
	m, r := keyedSolePrimary10315(t)
	pkt, _ := unsignedPrimaryClaim10315()
	signed := MarshalHeartbeatAuth(pkt, unsigned10315Key, 0x10315, 1)
	if _, _, present := heartbeatAuthTrailer(signed); !present {
		t.Fatal("setup: the control frame must carry an auth trailer")
	}
	got, err := UnmarshalHeartbeat(signed)
	if err != nil {
		t.Fatalf("setup: unmarshal signed frame: %v", err)
	}
	if !r.admitFrame(signed, got) {
		t.Fatal("a correctly-signed heartbeat was rejected on a keyed node — " +
			"the fix must reject UNSIGNED frames, not all frames")
	}
	if r.lastSeen.Load() == 0 {
		t.Error("an accepted signed frame did not refresh lastSeen")
	}
	if !m.PeerAlive() {
		t.Error("an accepted signed frame did not mark the peer alive")
	}
	if !m.HeartbeatPeerAuthSeen() {
		t.Error("an accepted signed frame did not arm the peer-authenticated flag")
	}
}

// TestUnkeyedUnsignedHeartbeatStillAccepted_10315 is the interop control: a
// node with NO key configured cannot verify and must keep dual-accepting, or a
// key rollout / mixed-version cluster splits. It passes both pre- and post-fix.
func TestUnkeyedUnsignedHeartbeatStillAccepted_10315(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200})))
	<-m.Events()
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	m.mu.Lock()
	m.hbReceiver = r
	m.mu.Unlock()

	pkt, frame := unsignedPrimaryClaim10315()
	if !r.admitFrame(frame, pkt) {
		t.Fatal("an UNKEYED node rejected an unsigned heartbeat — unkeyed " +
			"dual-accept is the rolling-upgrade interop the fix must preserve")
	}
	if !m.PeerAlive() {
		t.Error("an accepted frame on an unkeyed node did not mark the peer alive")
	}
}
