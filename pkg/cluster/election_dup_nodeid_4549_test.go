package cluster

import (
	"testing"
)

// TestElection_DualActive_DuplicateNodeIDYields is the #4549 F11 fail-on-revert
// guard. Two chassis misconfigured with the SAME node-id and equal effective
// priority are an invalid cluster: the HA protocol carries no per-node identity
// besides the node-id, so election has no asymmetric discriminator to elect a
// single primary. Before the fix, the dual-active tie
// (localEff == peerEff && nodeID > peerNodeID) was FALSE when the node-ids were
// equal, so electRG returned electNoChange "Dual-active: winner stays" and BOTH
// symmetric nodes stayed PRIMARY — a permanent split-brain.
//
// The fix fails CLOSED: on a same-node-id tie the local node yields to
// SECONDARY, so both nodes demote and no dual-primary (duplicate VIP / ARP
// conflict) is manufactured. This test drives both nodes primary with the same
// node-id and asserts the local node does NOT stay primary. Reverting the fix
// (restore "winner stays") leaves the local node primary and fails this test.
func TestElection_DualActive_DuplicateNodeIDYields(t *testing.T) {
	// We are node 0; the peer is ALSO (misconfigured as) node 0.
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200})) // non-preempt
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "drain initial single-node election")

	// Force local to primary.
	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	// Peer heartbeat: SAME node-id (0), same priority → equal effective
	// priority, also primary → dual-active with a same-node-id tie.
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if m.IsLocalPrimary(0) {
		t.Fatal("duplicate node-id dual-active tie left local node PRIMARY " +
			"(both nodes stay primary = split-brain); must fail closed to secondary")
	}
	if m.PeerNodeID() != m.NodeID() {
		t.Fatalf("test setup: peerNodeID %d != nodeID %d", m.PeerNodeID(), m.NodeID())
	}
}

// TestElection_Preempt_DuplicateNodeIDYields covers the preempt tie path
// (rg.Preempt == true), which had the same defect: the same-node-id tie fell
// through to "no change", leaving a dual-primary cluster unresolved. The fix
// yields to SECONDARY. Reverting it leaves the local node primary → RED.
func TestElection_Preempt_DuplicateNodeIDYields(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200})) // preempt enabled
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "the next event")

	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    0, // duplicate node-id
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if m.IsLocalPrimary(0) {
		t.Fatal("duplicate node-id preempt tie left local node PRIMARY; " +
			"must fail closed to secondary")
	}
}
