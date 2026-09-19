package cluster

import "testing"

// #10426: the preempt arm of electRG returned electNoChange with an EMPTY
// reason for a dual-active winner that was already primary, so runElection's
// reason-keyed reaffirm trigger never fired, no ClusterEvent{DualActiveWin:
// true} was emitted, and the daemon never ran scheduleDirectAnnounce —
// upstream kept the losing node's MAC until ARP/NDP expiry on direct-VIP
// (noRethVRRP) deployments under the recommended preempt: true.
//
// The winner cells below are fail-on-revert guards: reverting the preempt-arm
// reaffirm makes them RED. The loser / non-dual-active controls pin the
// unchanged behavior on either side of the fix.

// setupPreemptDualActiveWinner drives the manager to the preempt dual-active
// "winner stays" resolution: local is primary with higher priority, peer is
// also primary with lower priority, preempt on. Mirrors setupDualActiveWinner
// (non-preempt) in election_test.go.
func setupPreemptDualActiveWinner(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200})) // preempt, high priority
	m.UpdateConfig(cfg)
	<-m.Events() // drain the UpdateConfig event

	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()
	return m
}

func preemptDualActiveWinnerHeartbeat() *HeartbeatPacket {
	return &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
}

// TestElection_PreemptDualActive_WinnerEmitsReaffirm is the #10426
// fail-on-revert guard: a dual-active winner that stays primary under
// preempt: true must emit the DualActiveWin reaffirm event that drives the
// daemon's post-split-brain direct-VIP GARP/NA refresh.
func TestElection_PreemptDualActive_WinnerEmitsReaffirm(t *testing.T) {
	m := setupPreemptDualActiveWinner(t)

	m.handlePeerHeartbeat(preemptDualActiveWinnerHeartbeat())

	if !m.IsLocalPrimary(0) {
		t.Fatal("preempt dual-active winner must stay primary")
	}

	select {
	case ev := <-m.Events():
		if !ev.DualActiveWin {
			t.Errorf("expected DualActiveWin reaffirm event, got %+v", ev)
		}
		if ev.GroupID != 0 {
			t.Errorf("expected DualActiveWin event for RG 0, got %d", ev.GroupID)
		}
		if ev.OldState != StatePrimary || ev.NewState != StatePrimary {
			t.Errorf("dual-active reaffirm must report primary->primary, got %s->%s", ev.OldState, ev.NewState)
		}
	default:
		t.Fatal("preempt dual-active winner must emit DualActiveWin reaffirm " +
			"(drives direct-VIP GARP/NA refresh)")
	}
}

// TestElection_PreemptDualActive_TieWinnerEmitsReaffirm covers the second win
// path in the preempt arm: equal effective priority resolved by the node-ID
// tie-break in our favor. The lower-node-ID winner must also reaffirm.
func TestElection_PreemptDualActive_TieWinnerEmitsReaffirm(t *testing.T) {
	m := NewManager(0, 1) // lower node ID wins the tie
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if !m.IsLocalPrimary(0) {
		t.Fatal("preempt dual-active tie winner must stay primary")
	}

	select {
	case ev := <-m.Events():
		if !ev.DualActiveWin {
			t.Errorf("expected DualActiveWin reaffirm event, got %+v", ev)
		}
	default:
		t.Fatal("preempt dual-active tie winner must emit DualActiveWin reaffirm")
	}
}

// TestElection_PreemptDualActive_ElectRGReason pins the load-bearing coupling
// directly: the preempt arm must return the exact reaffirm reason string that
// runElection keys the DualActiveWin emission on.
func TestElection_PreemptDualActive_ElectRGReason(t *testing.T) {
	m := NewManager(0, 1)
	m.peerNodeID = 1
	rg := &RedundancyGroupState{
		GroupID: 0, State: StatePrimary, Preempt: true,
		LocalPriority: 200, Weight: 255,
	}
	peer := &PeerGroupState{
		GroupID: 0, Priority: 100, Weight: 255, State: StatePrimary,
	}

	result, reason := m.electRG(rg, peer)
	if result != electNoChange || reason != "Dual-active: winner stays" {
		t.Errorf("electRG preempt dual-active winner = (%v, %q), want (electNoChange, %q)",
			result, reason, "Dual-active: winner stays")
	}
}

// TestElection_PreemptDualActive_LoserYieldsWithoutReaffirm is the loser-side
// control: unchanged by the fix. The loser yields via a normal state-change
// event and must NOT emit a DualActiveWin reaffirm.
func TestElection_PreemptDualActive_LoserYieldsWithoutReaffirm(t *testing.T) {
	m := NewManager(1, 1) // higher node ID, lower priority: loses both ways
	cfg := makeConfig(makeRG(0, true, map[int]int{1: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if m.IsLocalPrimary(0) {
		t.Fatal("preempt dual-active loser must yield to secondary")
	}

	select {
	case ev := <-m.Events():
		if ev.DualActiveWin {
			t.Errorf("preempt dual-active loser must not emit DualActiveWin reaffirm, got %+v", ev)
		}
		if ev.OldState != StatePrimary || ev.NewState != StateSecondary {
			t.Errorf("loser must transition primary->secondary, got %s->%s", ev.OldState, ev.NewState)
		}
	default:
		t.Fatal("preempt dual-active loser must emit a state-change event")
	}

	select {
	case ev := <-m.Events():
		t.Errorf("no further events expected after loser yield, got %+v", ev)
	default:
	}
}

// TestElection_PreemptIncumbent_NoReaffirmWhenPeerNotPrimary is the
// non-dual-active control: unchanged by the fix. An incumbent primary whose
// peer is NOT primary is not a dual-active resolution and must stay silent.
func TestElection_PreemptIncumbent_NoReaffirmWhenPeerNotPrimary(t *testing.T) {
	m := setupPreemptDualActiveWinner(t)

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if !m.IsLocalPrimary(0) {
		t.Fatal("preempt incumbent must stay primary when peer is secondary")
	}

	select {
	case ev := <-m.Events():
		t.Errorf("incumbent with non-primary peer must emit no event, got %+v", ev)
	default:
	}
}
// TestElection_NonPreemptDualActive_WinnerControl is the preempt-disabled
// control for #10426. The existing non-preempt reaffirm path must continue to
// emit the same event for an already-primary dual-active winner.
func TestElection_NonPreemptDualActive_WinnerControl(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200})) // preempt disabled
	m.UpdateConfig(cfg)
	<-m.Events()

	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	m.handlePeerHeartbeat(preemptDualActiveWinnerHeartbeat())

	if !m.IsLocalPrimary(0) {
		t.Fatal("non-preempt dual-active winner must stay primary")
	}

	select {
	case ev := <-m.Events():
		if !ev.DualActiveWin {
			t.Errorf("expected non-preempt DualActiveWin reaffirm event, got %+v", ev)
		}
	default:
		t.Fatal("non-preempt dual-active winner must emit DualActiveWin reaffirm")
	}
}
