package cluster

import (
	"testing"
	"time"
)

// #15734: the failback-stranding shape recorded by the #12495 gate.
//
//	node0 was primary; a plain `request chassis cluster failover
//	redundancy-group 2` on node0 (ManualFailover) moved RG2 to node1 via
//	the coordinated transfer, leaving node0 as the COMMITTED secondary
//	(transferCommitRolePinned=secondary) with ManualFailover spent.
//	The gate's failback then issued the same plain request on node1,
//	demoting node1 into secondary-hold. Node0's dual-resign guard saw
//	the peer transfer-out and cleared node0's hold — but node1's
//	commit pin promptly re-elected node1 primary, and node0 (having
//	re-armed ManualFailover when the gate's request reached it as the
//	peer-requested demotion... in the recorded run the hold showed as
//	Manual=yes on node0) sat in secondary-hold past the 300s deadline
//	because electRG only cleared a manual hold when the peer was
//	resigned or itself transferred out — never when the peer was the
//	committed primary.
//
// The fix: a manual hold does not outlive the peer's committed
// ownership. When the peer is PRIMARY and local is the committed
// secondary (pin), the hold clears after the existing 2s guard; the
// node stays secondary (peer-primary arms), so this is a hold release,
// not a promotion. FAIL-ON-REVERT: drop the peerCommittedPrimary term
// and the first test stays stranded (ManualFailover never clears).
func TestManualHoldClearsAgainstCommittedPrimaryPeer15734(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(2, false, map[int]int{0: 200, 1: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Local is the committed secondary with a manual hold re-armed
	// (the stranded node0 view: secondary-hold, Manual=yes).
	m.mu.Lock()
	rg := m.groups[2]
	rg.State = StateSecondaryHold
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now().Add(-3 * time.Second) // past the 2s guard
	rg.transferCommitRolePinned = true
	rg.transferCommitRole = StateSecondary
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	m.mu.RLock()
	held := m.groups[2].ManualFailover
	state := m.groups[2].State
	m.mu.RUnlock()
	if held {
		t.Fatal("manual hold survived against the committed-primary peer — the #15734 stranding: " +
			"electRG only released holds for resigned/transferred-out peers, so node0 sat in " +
			"secondary-hold Manual=yes past the 300s failback deadline")
	}
	if m.IsLocalPrimary(2) {
		t.Fatalf("hold release must not promote the committed secondary; state=%s", state)
	}
}

// Control: without the committed-secondary pin, a manual hold against a
// healthy primary peer must be PRESERVED (the ordinary post-failover
// shape — TestElection_ManualFailover_Preserved's contract). The release
// is scoped to the committed-transfer aftermath, not a general
// "peer is primary so drop the hold" rule, which would defeat every
// deliberate manual failover the moment the peer takes over.
func TestManualHoldPreservedWithoutCommitPin15734(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(2, false, map[int]int{0: 200, 1: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	if _, err := m.ManualFailover(2); err != nil {
		t.Fatalf("ManualFailover: %v", err)
	}
	drainEvents(m, 1)
	m.mu.Lock()
	m.groups[2].ManualFailoverAt = time.Now().Add(-3 * time.Second)
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	m.mu.RLock()
	held := m.groups[2].ManualFailover
	m.mu.RUnlock()
	if !held {
		t.Fatal("manual hold cleared without the committed-secondary pin — this would silently " +
			"undo every deliberate manual failover once the peer is primary")
	}
	if m.IsLocalPrimary(2) {
		t.Fatal("held node must stay non-primary")
	}
}

// The 2s guard still applies on the new arm: a hold armed moments ago
// (the peer's failback request just landed) must not clear instantly,
// or the resigned node could flap before the handoff settles.
func TestManualHoldCommittedPrimaryRespectsTimeGuard15734(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(2, false, map[int]int{0: 200, 1: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.mu.Lock()
	rg := m.groups[2]
	rg.State = StateSecondaryHold
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now() // just armed
	rg.transferCommitRolePinned = true
	rg.transferCommitRole = StateSecondary
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	m.mu.RLock()
	held := m.groups[2].ManualFailover
	m.mu.RUnlock()
	if !held {
		t.Fatal("fresh manual hold cleared inside the 2s guard on the committed-primary arm")
	}
}
