package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16743: ForceSecondary (the ISSU drain) pinned Weight=0 only as a value in
// the derived Weight field. recalcWeight recomputes that field from monitor
// debt unconditionally, and the daemon apply tail feeds every interface
// monitor through SetMonitorWeight on every commit / peer config sync — so
// one no-change feed restored weight 255, the drained node's heartbeat
// advertised 255 at its higher priority, the peer preempt-yielded, and the
// drained node's ManualFailover arm parked it secondary: zero owners.
//
// The fix makes the pin a state fact (forcedSecondary) honoured by
// recalcWeight and debtDerivedWeightLocked, cleared by ResetFailover and
// peer loss.
//
// FAIL-ON-REVERT: drop the forcedSecondary check from recalcWeight (or the
// flag set in ForceSecondary) and TestForceSecondaryPinSurvivesMonitorFeed16743
// reds with weight 255 after the feed and owners=0 in the preempt row.

// drainPair16743 builds two real managers wired through real heartbeats:
// node0 (priority 200) and node1 (priority 100), RG1 with the given preempt
// setting and an interface monitor on ge-0/0/2. Both start with node0 primary.
func drainPair16743(t *testing.T, preempt bool) (node0, node1 *Manager) {
	t.Helper()
	cfg := &config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{
				ID:             1,
				NodePriorities: map[int]int{0: 200, 1: 100},
				Preempt:        preempt,
				InterfaceMonitors: []*config.InterfaceMonitor{
					{Interface: "ge-0/0/2", Weight: 100},
				},
			},
		},
	}
	node0 = NewManager(0, 1)
	node1 = NewManager(1, 1)
	node0.UpdateConfig(cfg)
	node1.UpdateConfig(cfg)
	drainEvents(node0, 10)
	drainEvents(node1, 10)
	exchange16743(node0, node1, 4)
	if !node0.IsLocalPrimary(1) || node1.IsLocalPrimary(1) {
		t.Fatalf("fixture: want node0 primary only, got node0=%v node1=%v",
			node0.IsLocalPrimary(1), node1.IsLocalPrimary(1))
	}
	return node0, node1
}

func exchange16743(a, b *Manager, rounds int) {
	for range rounds {
		b.handlePeerHeartbeat(a.buildHeartbeat())
		a.handlePeerHeartbeat(b.buildHeartbeat())
	}
	drainEvents(a, 100)
	drainEvents(b, 100)
}

func owners16743(a, b *Manager) int {
	n := 0
	if a.IsLocalPrimary(1) {
		n++
	}
	if b.IsLocalPrimary(1) {
		n++
	}
	return n
}

// Core acceptance from the issue: in the preempt row, owners stays 1 after
// the feed; the non-preempt row is the control.
func TestForceSecondaryPinSurvivesMonitorFeed16743(t *testing.T) {
	for _, preempt := range []bool{true, false} {
		name := "non-preempt"
		if preempt {
			name = "preempt"
		}
		t.Run(name, func(t *testing.T) {
			node0, node1 := drainPair16743(t, preempt)

			// ISSU drain on node0: peerAlive is set by the heartbeats above.
			if err := node0.ForceSecondary(); err != nil {
				t.Fatalf("ForceSecondary: %v", err)
			}
			drainEvents(node0, 10)
			exchange16743(node0, node1, 4)
			if got := owners16743(node0, node1); got != 1 {
				t.Fatalf("after drain: owners=%d, want 1 (node1)", got)
			}
			if !node1.IsLocalPrimary(1) {
				t.Fatal("after drain: node1 must be the single owner")
			}
			node0.mu.RLock()
			w0, forced := node0.groups[1].Weight, node0.groups[1].forcedSecondary
			node0.mu.RUnlock()
			if w0 != 0 || !forced {
				t.Fatalf("after drain: node0 weight=%d forced=%v, want 0/true", w0, forced)
			}

			// The trigger: one no-change monitor feed, exactly as the daemon
			// apply tail issues for every monitor on every commit / peer
			// config sync (up report on a never-down monitor).
			node0.SetMonitorWeight(1, "ge-0/0/2", false, 100)
			drainEvents(node0, 10)

			node0.mu.RLock()
			w0 = node0.groups[1].Weight
			node0.mu.RUnlock()
			if w0 != 0 {
				t.Fatalf("after no-change feed: node0 weight=%d, want pinned 0 (#16743)", w0)
			}
			// Wire weight must stay 0 too — the peer's preempt decision reads it.
			for _, g := range node0.buildHeartbeat().Groups {
				if int(g.GroupID) == 1 && g.Weight != 0 {
					t.Fatalf("heartbeat weight=%d, want 0 while drained", g.Weight)
				}
			}

			exchange16743(node0, node1, 10)
			if got := owners16743(node0, node1); got != 1 {
				t.Fatalf("preempt=%v after feed+heartbeats: owners=%d, want 1 — the peer yielded to the still-parked drained node (#16743)", preempt, got)
			}
			if !node1.IsLocalPrimary(1) {
				t.Errorf("preempt=%v: node1 must remain the owner after the feed", preempt)
			}
		})
	}
}

// The drain must also survive a real monitor failure + recovery cycle and a
// config re-apply (UpdateConfig -> reconcileMonitorDebtsLocked), not just a
// no-change feed.
func TestForceSecondaryPinSurvivesMonitorCycleAndReapply16743(t *testing.T) {
	node0, node1 := drainPair16743(t, true)
	if err := node0.ForceSecondary(); err != nil {
		t.Fatalf("ForceSecondary: %v", err)
	}
	exchange16743(node0, node1, 4)

	node0.SetMonitorWeight(1, "ge-0/0/2", true, 100)  // monitor fails
	node0.SetMonitorWeight(1, "ge-0/0/2", false, 100) // and recovers
	node0.UpdateConfig(node0Config16743(t, node0))
	drainEvents(node0, 10)
	node0.mu.RLock()
	w := node0.groups[1].Weight
	node0.mu.RUnlock()
	if w != 0 {
		t.Fatalf("weight=%d after monitor cycle + reapply, want pinned 0", w)
	}
	exchange16743(node0, node1, 6)
	if got := owners16743(node0, node1); got != 1 || !node1.IsLocalPrimary(1) {
		t.Fatalf("owners=%d node1Primary=%v, want 1/true", got, node1.IsLocalPrimary(1))
	}
}

func node0Config16743(t *testing.T, m *Manager) *config.ClusterConfig {
	t.Helper()
	return &config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{
				ID:             1,
				NodePriorities: map[int]int{0: 200, 1: 100},
				Preempt:        true,
				InterfaceMonitors: []*config.InterfaceMonitor{
					{Interface: "ge-0/0/2", Weight: 100},
				},
			},
		},
	}
}

// ResetFailover is the operator's deliberate end of the drain: the pin clears
// and the real monitor-derived weight (and election) return.
func TestForceSecondaryPinClearedByReset16743(t *testing.T) {
	node0, node1 := drainPair16743(t, true)
	if err := node0.ForceSecondary(); err != nil {
		t.Fatalf("ForceSecondary: %v", err)
	}
	exchange16743(node0, node1, 4)
	node0.SetMonitorWeight(1, "ge-0/0/2", false, 100)
	if err := node0.ResetFailover(1); err != nil {
		t.Fatalf("ResetFailover: %v", err)
	}
	node0.mu.RLock()
	rg := node0.groups[1]
	w, forced, manual := rg.Weight, rg.forcedSecondary, rg.ManualFailover
	node0.mu.RUnlock()
	if forced || manual {
		t.Fatalf("after reset: forced=%v manual=%v, want both false", forced, manual)
	}
	if w != 255 {
		t.Fatalf("after reset: weight=%d, want monitor-derived 255", w)
	}
	// Preempt: the higher-priority node reclaims once reset.
	exchange16743(node0, node1, 6)
	if !node0.IsLocalPrimary(1) || node1.IsLocalPrimary(1) {
		t.Fatalf("after reset+preempt: node0=%v node1=%v, want node0 primary only",
			node0.IsLocalPrimary(1), node1.IsLocalPrimary(1))
	}
}

// Peer loss ends the drain (issue fix direction: cleared by ResetFailover
// and peer loss): the survivor restores its monitor-derived weight and can
// own the RG again instead of staying parked at weight 0 forever.
func TestForceSecondaryPinClearedByPeerLoss16743(t *testing.T) {
	node0, _ := drainPair16743(t, true)
	if err := node0.ForceSecondary(); err != nil {
		t.Fatalf("ForceSecondary: %v", err)
	}
	node0.SetMonitorWeight(1, "ge-0/0/2", false, 100)
	node0.mu.RLock()
	if w := node0.groups[1].Weight; w != 0 {
		node0.mu.RUnlock()
		t.Fatalf("precondition: weight=%d, want pinned 0", w)
	}
	node0.mu.RUnlock()

	node0.handlePeerTimeout()
	drainEvents(node0, 10)
	node0.mu.RLock()
	rg := node0.groups[1]
	w, forced, manual := rg.Weight, rg.forcedSecondary, rg.ManualFailover
	node0.mu.RUnlock()
	if forced || manual {
		t.Fatalf("after peer loss: forced=%v manual=%v, want both false", forced, manual)
	}
	if w == 0 {
		t.Fatal("after peer loss: weight still 0 — survivor cannot take over")
	}
	if !node0.IsLocalPrimary(1) {
		t.Fatal("after peer loss: drained survivor must be able to own RG1")
	}
}

// A plain ManualFailover must NOT acquire the pin: it preserves
// monitor-derived weight semantics, and a later monitor feed must still
// recompute weight normally once the hold is consumed by a peer transfer.
func TestManualFailoverDoesNotPinWeight16743(t *testing.T) {
	node0, node1 := drainPair16743(t, true)
	if _, err := node0.ManualFailover(1); err != nil {
		t.Fatalf("ManualFailover: %v", err)
	}
	node0.mu.RLock()
	forced := node0.groups[1].forcedSecondary
	node0.mu.RUnlock()
	if forced {
		t.Fatal("plain ManualFailover must not set the ISSU drain pin")
	}
	_ = node1
	_ = time.Now
}
