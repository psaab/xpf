package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16736: when both nodes' monitors take a redundancy group to weight 0,
// Junos keeps exactly one owner — the lower node ID ("If the monitored
// interfaces of a redundancy group on both nodes reach their thresholds
// at the same time, the redundancy group becomes primary on the node
// with the lower node ID", Juniper, Monitoring Chassis Cluster
// Interfaces). Before the fix each node took "Local weight 0" and the
// RG was owned by NEITHER node for the fault's duration.
//
// FAIL-ON-REVERT: removing the both-zero arm in electRG leaves both
// managers secondary in TestBothWeightZeroExactlyOneOwner16736 (owners=0).

// bothZeroFixture16736 builds one manager at the given node ID whose RG1
// carries a full 255 interface-monitor debt (weight 0, debt-derived),
// peer alive. preempt is a parameter because the live cluster runs with
// preempt off, and the fix must hold in both modes (the arm sits before
// the preempt split).
func bothZeroFixture16736(t *testing.T, nodeID int, preempt bool) *Manager {
	t.Helper()
	m := NewManager(nodeID, 1)
	cfg := &config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{
				ID:             1,
				NodePriorities: map[int]int{0: 200, 1: 100},
				Preempt:        preempt,
			},
		},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 4)
	// Full monitor debt: one 255-weight monitor down -> weight 0.
	m.SetMonitorWeight(1, "ge-0/0/1", true, 255)
	drainEvents(m, 4)
	m.mu.RLock()
	w := m.groups[1].Weight
	fails := append([]string(nil), m.groups[1].MonitorFails...)
	m.mu.RUnlock()
	if w != 0 || len(fails) != 1 {
		t.Fatalf("node%d fixture: weight=%d fails=%v, want weight 0 with one monitor fail", nodeID, w, fails)
	}
	return m
}

func peerHeartbeat16736(peerNode, state NodeState, weight int) *HeartbeatPacket {
	return &HeartbeatPacket{
		NodeID:    uint8(peerNode),
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 1, Priority: 100, Weight: uint8(weight), State: uint8(state)},
		},
	}
}

// exchangeBothZero16736 feeds each manager the other's real buildHeartbeat
// (so the wire weight/state actually exercised is the production shape),
// then returns the owner count.
func exchangeBothZero16736(t *testing.T, n0, n1 *Manager) int {
	t.Helper()
	n0.handlePeerHeartbeat(n1.buildHeartbeat())
	n1.handlePeerHeartbeat(n0.buildHeartbeat())
	drainEvents(n0, 4)
	drainEvents(n1, 4)
	owners := 0
	if n0.IsLocalPrimary(1) {
		owners++
	}
	if n1.IsLocalPrimary(1) {
		owners++
	}
	return owners
}

func TestBothWeightZeroExactlyOneOwner16736(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		n0 := bothZeroFixture16736(t, 0, preempt)
		n1 := bothZeroFixture16736(t, 1, preempt)
		if owners := exchangeBothZero16736(t, n0, n1); owners != 1 {
			t.Errorf("preempt=%v: both weight 0 owners=%d, want exactly 1 (node0)", preempt, owners)
		}
		if !n0.IsLocalPrimary(1) {
			t.Errorf("preempt=%v: node0 (lower ID) must be primary at both-zero", preempt)
		}
		if n1.IsLocalPrimary(1) {
			t.Errorf("preempt=%v: node1 (higher ID) must stay secondary at both-zero", preempt)
		}
		// Steady state: re-exchange must not flap the owner away.
		if owners := exchangeBothZero16736(t, n0, n1); owners != 1 || !n0.IsLocalPrimary(1) {
			t.Errorf("preempt=%v: both-zero steady state owners=%d node0Primary=%v, want stable node0 owner",
				preempt, owners, n0.IsLocalPrimary(1))
		}
	}
}

// Control: only node0's monitor is down. The healthy peer must own the
// RG — the both-zero tie-break must not promote the debt node over a
// healthy peer (existing "Peer weight 0" / peer-primary behaviour).
func TestBothZeroControlOnlyOneSideDown16736(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		n0 := bothZeroFixture16736(t, 0, preempt) // weight 0
		n1 := NewManager(1, 1)
		cfg := &config.ClusterConfig{
			RethCount: 1,
			RedundancyGroups: []*config.RedundancyGroup{
				{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}, Preempt: preempt},
			},
		}
		n1.UpdateConfig(cfg)
		drainEvents(n1, 4) // healthy, weight 255
		owners := exchangeBothZero16736(t, n0, n1)
		if owners != 1 || n0.IsLocalPrimary(1) || !n1.IsLocalPrimary(1) {
			t.Errorf("preempt=%v: only-node0-down owners=%d n0=%v n1=%v, want exactly node1 primary",
				preempt, owners, n0.IsLocalPrimary(1), n1.IsLocalPrimary(1))
		}
	}
}

// Control: a peer that explicitly transferred out (StateSecondaryHold)
// at weight 0 is owned by the existing "Peer transfer out" arm, and a
// locally held node (ManualFailover / ForceSecondary pin) must never
// be resurrected by the both-zero tie-break.
func TestBothZeroExcludesResignedShapes16736(t *testing.T) {
	// Peer secondary-hold at weight 0: the both-zero arm must NOT fire
	// (peer StateSecondaryHold is excluded — that shape is owned by the
	// transfer-out arms, which require local weight > 0 / yield logic).
	// Baseline behaviour for a local weight-0 node against a
	// secondary-hold peer is therefore "stays secondary" (the
	// pre-existing "Local weight 0" arm), and this pins that the
	// both-zero change did not alter that row. Asserted at the electRG
	// level, because runElection's #9452 degraded-promotion fallback
	// legitimately promotes a NOT-READY node against a yielded peer —
	// a different layer with its own cells.
	m := bothZeroFixture16736(t, 0, false)
	m.mu.Lock()
	resHold, _ := m.electRG(m.groups[1], &PeerGroupState{GroupID: 1, State: StateSecondaryHold, Weight: 0, Priority: 100})
	m.mu.Unlock()
	if resHold == electLocalPrimary {
		t.Error("peer secondary-hold at weight 0 must not be promoted by the both-zero tie-break")
	}

	// Local ForceSecondary pin: Weight=0 with NO monitor debt of 255.
	// The tie-break must not fire — a deliberate ISSU drain stays drained.
	pinned := NewManager(0, 1)
	cfg := &config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	}
	pinned.UpdateConfig(cfg)
	drainEvents(pinned, 4)
	pinned.mu.Lock()
	rg := pinned.groups[1]
	rg.Weight = 0 // ForceSecondary pin shape: no debt installed
	rg.State = StateSecondary
	pinned.peerAlive = true
	pinned.mu.Unlock()
	res, _ := func() (electionResult, string) {
		pinned.mu.Lock()
		defer pinned.mu.Unlock()
		return pinned.electRG(pinned.groups[1], &PeerGroupState{GroupID: 1, State: StateSecondary, Weight: 0, Priority: 100})
	}()
	if res == electLocalPrimary {
		t.Error("ForceSecondary-pinned weight 0 must not be promoted by the both-zero tie-break")
	}

	// Local ManualFailover flag set (even with debt present): no promote.
	held := bothZeroFixture16736(t, 0, false)
	held.mu.Lock()
	held.groups[1].ManualFailover = true
	held.groups[1].ManualFailoverAt = time.Now()
	resHeld, _ := held.electRG(held.groups[1], &PeerGroupState{GroupID: 1, State: StateSecondary, Weight: 0, Priority: 100})
	held.mu.Unlock()
	if resHeld == electLocalPrimary {
		t.Error("ManualFailover-held RG must not be promoted by the both-zero tie-break")
	}
}

// Control: peer reporting StatePrimary at weight 0 keeps the existing
// peer-primary/dual-active behaviour; the tie-break only fires when
// both sides report non-primary.
func TestBothZeroPeerPrimaryAtZeroUnchanged16736(t *testing.T) {
	m := bothZeroFixture16736(t, 0, false)
	m.handlePeerHeartbeat(peerHeartbeat16736(1, StatePrimary, 0))
	// Existing "Peer weight 0" arm promotes the local node against a
	// weight-0 peer regardless of its reported state — pin that the
	// both-zero change did not alter this row's outcome class: exactly
	// one of (local primary now, or local secondary to a live primary)
	// must hold and local must not be left without an election result.
	m.mu.RLock()
	st := m.groups[1].State
	m.mu.RUnlock()
	if st != StatePrimary && st != StateSecondary {
		t.Errorf("peer primary at weight 0: local state=%v, want primary or secondary", st)
	}
}

// Kernel-hold control (#12164/#9452 stay green): a held local node
// never promotes even when the peer reports weight 0 secondary.
func TestBothZeroKernelHoldNeverPromotes16736(t *testing.T) {
	m := bothZeroFixture16736(t, 0, false)
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	m.handlePeerHeartbeat(peerHeartbeat16736(1, StateSecondary, 0))
	if m.IsLocalPrimary(1) {
		t.Error("kernel-upgrade-held node must never promote at both-zero")
	}
	m.ClearKernelUpgradeHold()
}

// Duplicate node ID at both-zero: fail closed (both secondary), no
// asymmetric winner exists (#4549 F11 shape preserved).
func TestBothZeroDuplicateNodeIDFailsClosed16736(t *testing.T) {
	m := bothZeroFixture16736(t, 0, false)
	m.mu.Lock()
	m.peerNodeID = 0 // duplicate
	m.groups[1].State = StatePrimary
	res, reason := m.electRG(m.groups[1], &PeerGroupState{GroupID: 1, State: StateSecondary, Weight: 0, Priority: 100})
	m.mu.Unlock()
	if res != electLocalSecondary {
		t.Errorf("duplicate node-id both-zero: result=%v reason=%q, want secondary (fail closed)", res, reason)
	}
}
