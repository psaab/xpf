// #6656: node0 reported PRIMARY for every RG while node1 carried the whole
// dataplane (1 vs 33 sessions, 4.7K vs 4.6M rx packets), with traffic flowing
// throughout.
//
// THE REPORTER'S HYPOTHESIS IS INAPPLICABLE, and saying so matters more than
// the fix. It proposed a VRRP virtual-MAC / VIP disagreement — but
// `private-rg-election` is the COMPILER DEFAULT (compiler_system.go: it is set
// true unconditionally and only `no-private-rg-election` opts out), and the
// loss userspace cluster's config does not opt out. Under it
// `vrrp.CollectRethInstances` returns nil, so there are no RETH VRRP instances
// at all: no VIP-owning state machine to disagree with, no sync hold, no
// preempt gate. An inapplicable hypothesis left standing sends the next
// investigator down the same path.
//
// WHAT DOES PRODUCE THAT SIGNATURE is transferOverrides outliving the
// peer incarnation it was granted against:
//
//   - `request chassis cluster failover redundancy-group N node 0` arms it,
//     rewriting THIS node's view of the peer to StateSecondaryHold.
//   - It has NO expiry, and applyTransferCommitOverridesOnPeerStateLocked
//     re-applies it to the rebuilt peer-group map on EVERY heartbeat.
//   - electRG then takes its "Peer transfer out" arm and self-elects this node
//     primary regardless of what the peer actually reports.
//   - FormatStatus renders the POST-override m.peerGroups, so the operator sees
//     a healthy primary — with an empty session table — and the peer shown as
//     secondary while the peer believes otherwise.
//
// handlePeerTimeout cleared ManualFailover ("the peer is dead, so the surviving
// node MUST be able to take over"), peerGroups, peerMonitors and both peer
// version fields — but not this. So the authority survived the peer that
// granted it, and cluster-setup.sh's reassert_primary_node0 arms it for EVERY
// RG on node0 after EVERY rolling deploy, swallowing errors. Two rolling
// deploys and a reboot preceded the incident.
//
// FAIL-ON-REVERT: delete the clearPeerTransferOutOverrideLocked loop from
// handlePeerTimeout and both tests below go RED.
package cluster

import (
	"testing"
)

// armTransferOutOverride puts the manager in the state a committed
// `request ... failover redundancy-group N node <self>` leaves behind.
func armTransferOutOverride(t *testing.T, m *Manager, rgID int, reqID uint64) {
	t.Helper()
	m.mu.Lock()
	m.applyPeerTransferOutOverrideLocked(rgID, reqID)
	m.mu.Unlock()
	m.mu.RLock()
	_, armed := m.transferOverrides[rgID]
	m.mu.RUnlock()
	if !armed {
		t.Fatalf("setup: override for RG%d not armed", rgID)
	}
}

func overrideArmed(m *Manager, rgID int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.transferOverrides[rgID]
	return ok
}

// TestPeerLossClearsTransferOutOverride6656 is the direct property.
//
// Every RG is armed, because the reported incident showed the divergence on
// RG0, RG1 and RG2 simultaneously — reassert_primary_node0 loops all of them —
// so a fix that cleared only the RG it happened to iterate first would not
// have addressed it.
func TestPeerLossClearsTransferOutOverride6656(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
		makeRG(1, false, map[int]int{0: 200, 1: 100}),
		makeRG(2, false, map[int]int{0: 200, 1: 100}),
	))
	drainEvents(m, 8)

	// The peer must be ALIVE first: handlePeerTimeout returns immediately if
	// it is already marked lost, so without this the test would pass against
	// unfixed code by never reaching the clear at all.
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	})
	if !m.PeerAlive() {
		t.Fatal("setup: peer must be alive before the timeout under test")
	}
	for rg := 0; rg < 3; rg++ {
		armTransferOutOverride(t, m, rg, uint64(1000+rg))
	}

	m.handlePeerTimeout()

	if m.PeerAlive() {
		t.Fatal("setup: handlePeerTimeout did not mark the peer lost, so the clear " +
			"under test was never reached")
	}
	for rg := 0; rg < 3; rg++ {
		if overrideArmed(m, rg) {
			t.Errorf("peer transfer-out override for RG%d survived peer loss. It has no "+
				"expiry and is re-applied to the rebuilt peer-group map on every "+
				"heartbeat, so from the reconnecting peer's FIRST heartbeat this node "+
				"forces it to secondary-hold and self-elects primary regardless of what "+
				"the peer reports (#6656)", rg)
		}
	}
}

// TestReconnectedPeerIsNotForcedSecondaryHoldAfterPeerLoss6656 binds the
// CONSEQUENCE rather than the field, and it is the test that actually
// describes the incident.
//
// Clearing a map is only interesting because of what the stale entry does to
// the next peer that connects. Here the peer comes back reporting itself
// PRIMARY — the rebooted / re-deployed peer that legitimately owns the RG —
// and this node must reflect that instead of overwriting it. A field-only
// assertion would still pass if the clear were moved somewhere the heartbeat
// path re-armed it.
func TestReconnectedPeerIsNotForcedSecondaryHoldAfterPeerLoss6656(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 200, 1: 100})))
	drainEvents(m, 4)

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)}},
	})
	armTransferOutOverride(t, m, 0, 4242)

	// Control: while the override is armed, the override IS applied — so the
	// assertion after the timeout is about the clear and not about the
	// override mechanism having quietly stopped working.
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)}},
	})
	if got := m.PeerGroupStates()[0].State; got != StateSecondaryHold {
		t.Fatalf("control: with the override armed, a peer advertising primary should be "+
			"forced to secondary-hold; got %v. The fixture is not exercising the "+
			"override at all, so the post-timeout assertion below would be vacuous", got)
	}

	m.handlePeerTimeout()

	// The peer returns — a reboot, a rolling deploy, a new process — and it
	// legitimately owns the RG.
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)}},
	})

	if got := m.PeerGroupStates()[0].State; got == StateSecondaryHold {
		t.Fatalf("a RECONNECTED peer advertising primary was still forced to "+
			"secondary-hold (%v). The transfer-out override outlived the peer "+
			"incarnation that granted it, so this node overwrites the new peer's "+
			"reported state on every heartbeat, self-elects primary, and shows the "+
			"operator a primary row with an empty session table while the peer "+
			"carries the traffic — the #6656 signature", got)
	}
	if got := m.PeerGroupStates()[0].State; got != StatePrimary {
		t.Errorf("reconnected peer state = %v, want %v (its own advertised state)", got, StatePrimary)
	}
}
