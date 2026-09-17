package cluster

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestEffectivePriority(t *testing.T) {
	tests := []struct {
		base, weight, want int
	}{
		{200, 255, 200}, // full weight
		{200, 0, 0},     // zero weight
		{200, 128, 100}, // half weight (200*128/255 = 100)
		{100, 255, 100}, // full weight, lower priority
		{255, 255, 255}, // max everything
		{0, 255, 0},     // zero priority
		{200, -1, 0},    // negative weight → 0
	}
	for _, tt := range tests {
		got := EffectivePriority(tt.base, tt.weight)
		if got != tt.want {
			t.Errorf("EffectivePriority(%d, %d) = %d, want %d",
				tt.base, tt.weight, got, tt.want)
		}
	}
}

func TestElection_PeerLost_BecomesPrimary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events() // drain initial single-node election

	// Simulate peer arriving then disappearing.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 250, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	// Peer is primary with higher priority and preempt=false,
	// so we should be secondary if peer is primary.
	drainEvents(m, 1)

	// Now peer times out.
	m.handlePeerTimeout()

	// We should become primary (peer lost, weight > 0).
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary after peer timeout")
	}
}

func TestElection_PeerHigherPriority_Preempt(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 100})) // preempt enabled
	m.UpdateConfig(cfg)
	<-m.Events() // primary from single-node election

	// Peer has higher priority.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// With preempt, peer's higher priority should make us secondary.
	if m.IsLocalPrimary(0) {
		t.Error("should be secondary when peer has higher effective priority with preempt")
	}
}

func TestElection_LocalHigherPriority_Preempt(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 250})) // preempt, high priority
	m.UpdateConfig(cfg)
	<-m.Events()

	// Peer has lower priority and is currently primary.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// With preempt, our higher priority means we should be primary.
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary when local has higher priority with preempt")
	}
}

func TestElection_NonPreempt_IncumbentStays(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 250})) // no preempt
	m.UpdateConfig(cfg)
	<-m.Events()

	// We are primary. Peer arrives with higher priority but preempt=false.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 255, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Non-preempt: incumbent (us) stays primary.
	if !m.IsLocalPrimary(0) {
		t.Error("should stay primary with non-preempt (incumbent)")
	}
}

func TestElection_SplitBrain_LowerNodeWins(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Both nodes think they are primary (split-brain).
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Node 0 < Node 1, so node 0 (us) should stay primary.
	if !m.IsLocalPrimary(0) {
		t.Error("lower node ID should win split-brain")
	}
}

func TestElection_SplitBrain_HigherNodeLoses(t *testing.T) {
	m := NewManager(1, 1) // We are node 1 (higher)
	cfg := makeConfig(makeRG(0, true, map[int]int{1: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Peer (node 0, lower ID) also primary.
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// We (node 1) should yield to node 0 (lower ID).
	if m.IsLocalPrimary(0) {
		t.Error("higher node ID should yield in split-brain")
	}
}

// #1930 INC-2 r2 AGY Critical: a kernel-upgrade candidate boot sets an
// unconditional election hold. Even ISOLATED (no peer) — where a normal node
// auto-promotes to primary — the held node must stay SECONDARY until the
// promotion gate verifies the dataplane. This is the case the prior
// ForceSecondary fix missed (peerAlive=false at boot made it a no-op).
func TestElection_KernelUpgradeHold_IsolatedStaysSecondary(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate) // candidate boot, before the cluster starts electing
	if !m.KernelUpgradeHeld() {
		t.Fatal("SetKernelUpgradeHold must make KernelUpgradeHeld report true")
	}
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	// An ordinary isolated node would win the single-node election and be
	// primary. The hold must keep it secondary even with no peer in sight.
	if m.IsLocalPrimary(0) {
		t.Fatal("kernel-upgrade hold must keep an isolated candidate SECONDARY")
	}

	// A peer timeout re-runs election; the hold must still keep us secondary
	// (it is NOT auto-cleared the way ManualFailover is for an isolated node).
	m.handlePeerTimeout()
	if m.IsLocalPrimary(0) {
		t.Fatal("kernel-upgrade hold must survive a re-election (not auto-cleared)")
	}

	// Clearing the hold (promote success / rejoin) lets it take its role.
	m.ClearKernelUpgradeHold()
	if m.KernelUpgradeHeld() {
		t.Fatal("ClearKernelUpgradeHold must make KernelUpgradeHeld report false")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("after ClearKernelUpgradeHold the isolated node must become primary")
	}
}

// Defense in depth (r2 AGY Finding 1): if the hold is ever set AFTER a group is
// already primary, SetKernelUpgradeHold must DEMOTE it — not just block future
// promotions — so the hold is correct regardless of call ordering.
func TestElection_KernelUpgradeHold_DemotesAlreadyPrimary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	// Isolated node — wins the single-node election and is primary.
	if !m.IsLocalPrimary(0) {
		t.Fatal("precondition: isolated node should be primary before the hold")
	}
	drainEvents(m, 4)

	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	if m.IsLocalPrimary(0) {
		t.Fatal("SetKernelUpgradeHold must DEMOTE an already-primary group")
	}
	// And it must stay secondary across a re-election.
	m.handlePeerTimeout()
	if m.IsLocalPrimary(0) {
		t.Fatal("held node must stay secondary after re-election")
	}
}

// r2 Codex HIGH (never-both-down): the orchestrator's gRPC rejoin clears manual
// failover PER-RG via Manager.ResetFailover. That path MUST also drop the kernel
// hold synchronously, so the rejoined node is election-eligible the instant
// rejoin returns — otherwise the driver could drain the peer while this node is
// still held secondary (both secondary, no primary).
func TestResetFailover_ClearsKernelUpgradeHold(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	if m.IsLocalPrimary(0) {
		t.Fatal("precondition: held candidate must be secondary")
	}
	drainEvents(m, 4)

	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover: %v", err)
	}
	if m.KernelUpgradeHeld() {
		t.Fatal("ResetFailover (rejoin) must clear the kernel-upgrade hold synchronously")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("after rejoin the isolated node must reclaim primary (hold cleared)")
	}
}

func TestElection_LocalWeightZero_BecomesSecondary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 250}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Peer is secondary.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// We're primary. Now our weight drops to 0.
	m.SetMonitorWeight(0, "trust0", true, 255)

	// Should become secondary regardless of priority.
	if m.IsLocalPrimary(0) {
		t.Error("should be secondary with weight 0")
	}
}

func TestElection_PeerWeightZero_BecomesPrimary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Peer has higher priority but weight 0.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 250, Weight: 0, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Peer weight=0 means we should be primary.
	if !m.IsLocalPrimary(0) {
		t.Error("should be primary when peer has weight 0")
	}
}

func TestElection_ManualFailover_Preserved(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Manual failover.
	_, _ = m.ManualFailover(0)
	drainEvents(m, 1)

	// Peer heartbeat arrives.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Manual failover should keep us secondary even with higher priority.
	if m.IsLocalPrimary(0) {
		t.Error("manual failover should keep us secondary")
	}
}

func TestElection_PeerSecondaryHold_BecomesPrimary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if !m.IsLocalPrimary(0) {
		t.Error("should become primary when peer explicitly transfers out")
	}
}

func TestElection_DualResign_TimeGuard(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Manual failover — just set, should NOT clear even if peer is also in
	// transfer-out state.
	_, _ = m.ManualFailover(0)
	drainEvents(m, 1)

	// Peer also transferred out.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Within 2s time guard — should stay secondary.
	if m.IsLocalPrimary(0) {
		t.Error("should stay secondary within time guard (just transferred out)")
	}

	// Backdate the ManualFailoverAt to simulate >2s elapsed.
	m.mu.Lock()
	m.groups[0].ManualFailoverAt = time.Now().Add(-3 * time.Second)
	m.mu.Unlock()

	// Now re-trigger election via heartbeat.
	m.handlePeerHeartbeat(pkt)

	// After time guard, dual transfer-out should clear ManualFailover and
	// fall back to normal election.
	if !m.IsLocalPrimary(0) {
		t.Error("should become primary after time guard expires (dual transfer-out recovery)")
	}
}

func TestElection_DisabledState_Preserved(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Force disabled.
	m.mu.Lock()
	m.groups[0].State = StateDisabled
	m.mu.Unlock()

	// Peer heartbeat arrives.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Disabled state should be preserved.
	states := m.GroupStates()
	if states[0].State != StateDisabled {
		t.Errorf("state = %s, want disabled", states[0].State)
	}
}

func TestElection_MultipleRGs(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 200, 1: 100}),
		makeRG(1, true, map[int]int{0: 100, 1: 200}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	// Peer heartbeat with different priorities per RG.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// RG 0: we have higher priority (200 vs 100) → primary.
	if !m.IsLocalPrimary(0) {
		t.Error("RG 0: should be primary (higher priority)")
	}
	// RG 1: peer has higher priority (200 vs 100) with preempt → secondary.
	if m.IsLocalPrimary(1) {
		t.Error("RG 1: should be secondary (peer has higher priority)")
	}
}

func TestFormatInformation(t *testing.T) {
	m := NewManager(0, 1)
	cfg := &config.ClusterConfig{
		ClusterID:          1,
		NodeID:             0,
		HeartbeatInterval:  500,
		HeartbeatThreshold: 5,
		ControlInterface:   "fab0",
		RedundancyGroups: []*config.RedundancyGroup{
			makeRG(0, true, map[int]int{0: 200}),
		},
	}
	m.UpdateConfig(cfg)
	// Status formatting is a steady-state view; model the already-attached
	// dataplane so the new HA boot debt is cleared before asserting priority.
	m.SetMonitorWeight(0, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)

	out := m.FormatInformation()
	if !strings.Contains(out, "Cluster ID: 1") {
		t.Error("missing cluster ID")
	}
	if !strings.Contains(out, "Node ID: 0") {
		t.Error("missing node ID")
	}
	if !strings.Contains(out, "Heartbeat interval: 500 ms") {
		t.Error("missing heartbeat interval")
	}
	if !strings.Contains(out, "Heartbeat threshold: 5") {
		t.Error("missing heartbeat threshold")
	}
	if !strings.Contains(out, "Control interface: fab0") {
		t.Error("missing control interface")
	}
	if !strings.Contains(out, "Remote node: lost") {
		t.Error("missing remote node status")
	}
	if !strings.Contains(out, "Redundancy group 0:") {
		t.Error("missing RG 0 details")
	}
	if !strings.Contains(out, "Effective priority: 200") {
		t.Error("missing effective priority")
	}
	if !strings.Contains(out, "Redundancy mode:") {
		t.Error("missing redundancy mode")
	}
	if !strings.Contains(out, "Control link statistics:") {
		t.Error("missing control link statistics")
	}
}

func TestFormatInformation_WithPeer(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	// Add peer.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 150, Weight: 200, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	out := m.FormatInformation()
	if !strings.Contains(out, "healthy (node1)") {
		t.Error("peer should show as healthy")
	}
	if !strings.Contains(out, "Peer priority: 150") {
		t.Error("missing peer priority")
	}
}

func TestFormatStatus_WithPeer(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	// Add peer.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	out := m.FormatStatus()
	if !strings.Contains(out, "node0") {
		t.Error("missing local node")
	}
	if !strings.Contains(out, "node1") {
		t.Error("missing peer node")
	}
}

func TestElection_TiePriority_LowerNodeWins(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()

	// Both nodes have same effective priority, preempt enabled.
	// Both are secondary initially for election purposes.
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.mu.Unlock()

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Node 0 (us) should win tie with lower ID.
	if !m.IsLocalPrimary(0) {
		t.Error("lower node ID should win tie")
	}
}

func TestElection_BlocksPromotionWhenNotReady(t *testing.T) {
	m := NewManager(0, 1)
	m.takeoverHoldTime = 100 * time.Millisecond
	m.controlInterface = "hb0" // cluster mode — enables readiness gate

	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	// Force back to secondary for a clean test.
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.groups[0].Ready = false
	m.groups[0].ReadySince = time.Time{}
	m.mu.Unlock()

	// Peer is secondary — election would normally promote us.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Should NOT be primary — readiness gate blocks it.
	if m.IsLocalPrimary(0) {
		t.Error("should NOT be primary when RG is not ready")
	}
}

func TestElection_AllowsPromotionAfterHoldTimer(t *testing.T) {
	m := NewManager(0, 1)
	m.takeoverHoldTime = 50 * time.Millisecond
	m.controlInterface = "hb0" // cluster mode

	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	// Force back to secondary.
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	// Mark ready with a ReadySince in the past (>holdTime ago).
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-100 * time.Millisecond)
	m.mu.Unlock()

	// Peer is secondary — election should promote us since ready > holdTime.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	if !m.IsLocalPrimary(0) {
		t.Error("should be primary after readiness hold time expired")
	}
}

func TestElection_DoesNotDemoteExistingPrimary(t *testing.T) {
	m := NewManager(0, 1)
	m.takeoverHoldTime = 100 * time.Millisecond
	m.controlInterface = "hb0" // cluster mode

	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200})) // preempt=true for simpler setup
	// Pre-set ready state before UpdateConfig so election can promote.
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	// Force to primary (simulating an already-established primary).
	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.groups[0].Ready = false
	m.groups[0].ReadySince = time.Time{}
	m.mu.Unlock()

	if !m.IsLocalPrimary(0) {
		t.Fatal("should be primary (forced)")
	}

	// Peer arrives as secondary.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Already-primary node should NOT be demoted by readiness gate.
	if !m.IsLocalPrimary(0) {
		t.Error("already-primary node should NOT be demoted by readiness gate")
	}
}

func TestSetRGReady_TransitionsAndTimer(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	// Initial state: not ready.
	states := m.GroupStates()
	if states[0].Ready {
		t.Error("should start not ready")
	}
	if !states[0].ReadySince.IsZero() {
		t.Error("ReadySince should be zero when not ready")
	}

	// Transition to ready.
	m.SetRGReady(0, true, nil)
	states = m.GroupStates()
	if !states[0].Ready {
		t.Error("should be ready after SetRGReady(true)")
	}
	if states[0].ReadySince.IsZero() {
		t.Error("ReadySince should be set after ready transition")
	}

	// Transition back to not ready.
	m.SetRGReady(0, false, []string{"interface trust0 not found"})
	states = m.GroupStates()
	if states[0].Ready {
		t.Error("should be not ready after SetRGReady(false)")
	}
	if !states[0].ReadySince.IsZero() {
		t.Error("ReadySince should be cleared on not-ready transition")
	}
	if len(states[0].ReadinessReasons) != 1 || states[0].ReadinessReasons[0] != "interface trust0 not found" {
		t.Errorf("unexpected reasons: %v", states[0].ReadinessReasons)
	}
}

func TestNewManager_DefaultTakeoverHoldTimeIsImmediate(t *testing.T) {
	m := NewManager(0, 1)
	if m.takeoverHoldTime != 0 {
		t.Fatalf("takeoverHoldTime = %v, want 0", m.takeoverHoldTime)
	}

	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	m.SetRGReady(0, true, nil)

	m.mu.RLock()
	defer m.mu.RUnlock()
	if got := m.groups[0].holdTimer; got != nil {
		t.Fatal("holdTimer should stay nil when takeover hold defaults to immediate")
	}
}

func TestUpdateConfig_ZeroTakeoverHoldTimeResetsToImmediate(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))

	cfg.TakeoverHoldTime = 1500
	m.UpdateConfig(cfg)
	if got := m.takeoverHoldTime; got != 1500*time.Millisecond {
		t.Fatalf("takeoverHoldTime = %v, want 1500ms", got)
	}

	cfg.TakeoverHoldTime = 0
	m.UpdateConfig(cfg)
	if got := m.takeoverHoldTime; got != DefaultTakeoverHoldTime {
		t.Fatalf("takeoverHoldTime = %v, want default %v", got, DefaultTakeoverHoldTime)
	}
}

func TestIsReadyForTakeover(t *testing.T) {
	rg := &RedundancyGroupState{GroupID: 0}

	// Not ready at all.
	if rg.IsReadyForTakeover(100 * time.Millisecond) {
		t.Error("should not be ready when Ready=false")
	}

	// Ready but too recent.
	rg.Ready = true
	rg.ReadySince = time.Now()
	if rg.IsReadyForTakeover(1 * time.Second) {
		t.Error("should not be ready before hold time expires")
	}

	// Ready and hold time expired.
	rg.ReadySince = time.Now().Add(-2 * time.Second)
	if !rg.IsReadyForTakeover(1 * time.Second) {
		t.Error("should be ready after hold time expires")
	}

	// Zero hold time — ready immediately.
	rg.ReadySince = time.Now()
	if !rg.IsReadyForTakeover(0) {
		t.Error("should be ready with zero hold time")
	}
}

func TestElection_PeerLost_BypassesReadinessGate(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg.ControlInterface = "em0" // enables cluster mode readiness gate
	m.UpdateConfig(cfg)
	// No initial event: controlInterface + non-preempt + !peerEverSeen
	// blocks the initial single-node election (by design).

	// Simulate peer arriving — this sets peerEverSeen=true and makes
	// us secondary to the higher-priority peer.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 250, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	// Drain the secondary transition event.
	drainEvents(m, 1)

	// Confirm we're secondary.
	if m.IsLocalPrimary(0) {
		t.Fatal("should be secondary while peer is primary")
	}

	// Make the RG NOT ready (simulates sync disconnect setting Ready=false).
	m.mu.Lock()
	rg := m.groups[0]
	rg.Ready = false
	rg.ReadySince = time.Time{}
	m.mu.Unlock()

	// Peer timeout — despite readiness gate, we must take over.
	m.handlePeerTimeout()

	if !m.IsLocalPrimary(0) {
		t.Error("should be primary after peer timeout even when readiness gate is not met")
	}
}

func TestRGInterfaceReady(t *testing.T) {
	m := NewManager(0, 1) // node 0
	nlh := newMockNlHandle()
	nlh.setLink("ge-0-0-0", true)
	nlh.setLink("ge-7-0-0", true)

	groups := []*config.RedundancyGroup{
		{
			ID: 0,
			InterfaceMonitors: []*config.InterfaceMonitor{
				{Interface: "ge-0/0/0", Weight: 255}, // local (slot 0 → node 0)
				{Interface: "ge-7/0/0", Weight: 128}, // peer  (slot 7 → node 1)
			},
		},
	}
	mon := NewMonitor(m, groups)
	mon.nlHandle = nlh

	// All interfaces up — should be ready.
	ready, reasons := mon.RGInterfaceReady(0)
	if !ready {
		t.Errorf("should be ready, got reasons: %v", reasons)
	}

	// Remove peer's interface — should be skipped (ge-7/0/x belongs
	// to node 1, we are node 0).
	delete(nlh.links, "ge-7-0-0")
	ready, reasons = mon.RGInterfaceReady(0)
	if !ready {
		t.Errorf("missing peer interface should be skipped, got reasons: %v", reasons)
	}

	// Remove local interface — should fail readiness.
	delete(nlh.links, "ge-0-0-0")
	ready, reasons = mon.RGInterfaceReady(0)
	if ready {
		t.Error("missing local interface should fail readiness")
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "ge-0/0/0 missing") {
		t.Errorf("unexpected reasons: %v", reasons)
	}

	// Interface exists but is down.
	nlh.setLink("ge-0-0-0", false)
	ready, reasons = mon.RGInterfaceReady(0)
	if ready {
		t.Error("should NOT be ready with interface down")
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "ge-0/0/0 down") {
		t.Errorf("unexpected reasons: %v", reasons)
	}

	// RG not in config — should be ready (nothing to check).
	ready, reasons = mon.RGInterfaceReady(99)
	if !ready {
		t.Errorf("unknown RG should be ready, got reasons: %v", reasons)
	}
}

func TestElection_NonPreemptDualActive_LowerPriorityYields(t *testing.T) {
	// Both primary, different priorities, non-preempt.
	// Lower effective priority must yield.
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 100})) // non-preempt, low priority
	m.UpdateConfig(cfg)
	<-m.Events()

	// Force local to primary.
	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	// Peer is also primary with higher priority.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Lower priority (us) should yield.
	if m.IsLocalPrimary(0) {
		t.Error("lower priority should yield in non-preempt dual-active")
	}
}

func TestElection_NonPreemptDualActive_TieBreakNodeID(t *testing.T) {
	// Both primary, same priority, non-preempt.
	// Higher node ID must yield.
	m := NewManager(1, 1)                                    // We are node 1 (higher)
	cfg := makeConfig(makeRG(0, false, map[int]int{1: 200})) // non-preempt
	m.UpdateConfig(cfg)
	<-m.Events()

	// Force local to primary.
	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	// Peer (node 0) also primary with same priority.
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Higher node ID (us, node 1) should yield.
	if m.IsLocalPrimary(0) {
		t.Error("higher node ID should yield in non-preempt dual-active tie")
	}
}

func TestElection_NonPreemptDualActive_WinnerStays(t *testing.T) {
	// Both primary, we have higher priority, non-preempt.
	// Winner stays primary (electNoChange).
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200})) // non-preempt, high priority
	m.UpdateConfig(cfg)
	<-m.Events()

	// Force local to primary.
	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	// Peer also primary with lower priority.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// We win — stay primary.
	if !m.IsLocalPrimary(0) {
		t.Error("higher priority should stay primary in non-preempt dual-active")
	}
}

func TestElection_NonPreemptDualActive_PreemptSelfResolves(t *testing.T) {
	// Regression guard: preempt mode already handles dual-active via
	// priority comparison — ensure it still works.
	m := NewManager(1, 1)                                   // We are node 1 (higher)
	cfg := makeConfig(makeRG(0, true, map[int]int{1: 100})) // preempt enabled
	m.UpdateConfig(cfg)
	<-m.Events()

	// Force local to primary.
	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()

	// Peer (node 0) also primary with higher priority.
	pkt := &HeartbeatPacket{
		NodeID:    0,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)},
		},
	}
	m.handlePeerHeartbeat(pkt)

	// Preempt: peer has higher priority, we should yield.
	if m.IsLocalPrimary(0) {
		t.Error("preempt dual-active: lower priority should yield")
	}
}

// drainEvents drains up to n events from the channel.
func drainEvents(m *Manager, n int) {
	for i := 0; i < n; i++ {
		select {
		case <-m.Events():
		default:
			return
		}
	}
}

// setupDualActiveWinner drives the manager to the dual-active "winner stays"
// resolution: local is primary with higher priority, peer is also primary with
// lower priority, non-preempt. runElection (inside handlePeerHeartbeat) then
// takes the electNoChange "Dual-active: winner stays" branch that emits the
// DualActiveWin reaffirm event.
func setupDualActiveWinner(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200})) // non-preempt, high priority
	m.UpdateConfig(cfg)
	<-m.Events() // drain the UpdateConfig event

	m.mu.Lock()
	m.groups[0].State = StatePrimary
	m.mu.Unlock()
	return m
}

func dualActiveWinnerHeartbeat() *HeartbeatPacket {
	return &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}
}

// TestElection_DualActiveWinDrop_InvokesReconcileFallback is the #4867
// fail-on-revert guard. When eventCh is FULL at the dual-active "winner stays"
// resolution, the inline emission must NOT silently drop the reaffirm event:
// it must fire the generic reconcile fallback (onEventDrop) AND the dedicated
// reaffirm-drop callback (onDualActiveWinDrop) that re-drives the daemon's
// post-split-brain GARP/NA refresh. Reverting the fix (a bare `default:` that
// drops without invoking either callback) makes this test RED.
func TestElection_DualActiveWinDrop_InvokesReconcileFallback(t *testing.T) {
	m := setupDualActiveWinner(t)

	// Replace eventCh with an unbuffered channel with no receiver so the
	// inline dual-active select deterministically hits the full-channel
	// default arm.
	m.mu.Lock()
	m.eventCh = make(chan ClusterEvent)
	m.mu.Unlock()

	var eventDrops, reaffirmDrops int
	reaffirmRG := -1
	m.SetOnEventDrop(func() { eventDrops++ })
	m.SetOnDualActiveWinDrop(func(rgID int) {
		reaffirmDrops++
		reaffirmRG = rgID
	})

	m.handlePeerHeartbeat(dualActiveWinnerHeartbeat())

	// The winner stays primary regardless.
	if !m.IsLocalPrimary(0) {
		t.Fatal("dual-active winner must stay primary")
	}
	// The dedicated reaffirm-drop callback MUST fire so the GARP/NA refresh
	// is re-driven — this is the load-bearing assertion the revert breaks.
	if reaffirmDrops != 1 {
		t.Errorf("dropped dual-active reaffirm must invoke onDualActiveWinDrop exactly once, got %d", reaffirmDrops)
	}
	if reaffirmRG != 0 {
		t.Errorf("onDualActiveWinDrop must carry RG id 0, got %d", reaffirmRG)
	}
	// The generic reconcile fallback must also fire, matching sendEvent.
	if eventDrops != 1 {
		t.Errorf("dropped dual-active reaffirm must invoke onEventDrop (reconcile fallback), got %d", eventDrops)
	}
}

// TestElection_DualActiveWin_NormalPathDelivers proves the non-full path still
// delivers the DualActiveWin event through the channel and does NOT invoke the
// drop-fallback callbacks (the reconcile/re-announce path is drop-only).
func TestElection_DualActiveWin_NormalPathDelivers(t *testing.T) {
	m := setupDualActiveWinner(t)

	var eventDrops, reaffirmDrops int
	m.SetOnEventDrop(func() { eventDrops++ })
	m.SetOnDualActiveWinDrop(func(int) { reaffirmDrops++ })

	m.handlePeerHeartbeat(dualActiveWinnerHeartbeat())

	if !m.IsLocalPrimary(0) {
		t.Fatal("dual-active winner must stay primary")
	}

	select {
	case ev := <-m.Events():
		if !ev.DualActiveWin {
			t.Errorf("expected DualActiveWin event, got %+v", ev)
		}
		if ev.GroupID != 0 {
			t.Errorf("expected DualActiveWin event for RG 0, got %d", ev.GroupID)
		}
		if ev.OldState != StatePrimary || ev.NewState != StatePrimary {
			t.Errorf("dual-active reaffirm must report primary->primary, got %s->%s", ev.OldState, ev.NewState)
		}
	default:
		t.Fatal("DualActiveWin event was not delivered on the non-full path")
	}

	// The drop-only fallbacks must NOT fire when the channel had room.
	if eventDrops != 0 {
		t.Errorf("onEventDrop must not fire on the non-full path, got %d", eventDrops)
	}
	if reaffirmDrops != 0 {
		t.Errorf("onDualActiveWinDrop must not fire on the non-full path, got %d", reaffirmDrops)
	}
}
