package cluster

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16741: under preempt, the incumbent yielded to a rejoining
// higher-priority peer that was armed but still in the #7162/#14406 startup
// sync hold, so no node owned the RG until the hold released (up to 30s).
//
// The probes below are BLACK-BOX: two real managers exchange heartbeats
// through buildHeartbeat/handlePeerHeartbeat, exactly like the wire. The
// held rejoiner advertises its not-takeover-ready state only through the
// clamp buildHeartbeat installs. Tests that inject PeerGroupState by hand
// with a full weight would stay GREEN when the clamp is removed — the
// defect is precisely that nothing on the wire said "cannot take over".
//
// FAIL-ON-REVERT: reverting the clamp (advertise local weight regardless of
// readiness) reintroduces the #16741 window: the incumbent's preempt arm
// fires against the full-weight rejoiner and owners == 0. Reverting the
// takeoverReady guard alone keeps the control cells green but flips the
// pinned-secondary cells (committed requester must not be force-demoted by
// a gate-closed peer's demotion arms).

// preemptRejoinFixture16741 builds the two-node shape from the issue trace:
//
//	fw0 (node0, priority 200, preempt): the rejoiner. Primary before its
//	  reboot; now armed (dataplane ready) but still inside the startup
//	  sync hold, so its readiness gate is closed.
//	fw1 (node1, priority 100, preempt): the incumbent. Took over while fw0
//	  was gone and now owns RG1.
func preemptRejoinFixture16741(t *testing.T, preempt bool) (rejoiner, incumbent *Manager) {
	t.Helper()
	cfg := func() *config.ClusterConfig {
		c := makeConfig(makeRG(1, preempt, map[int]int{0: 200, 1: 100}))
		c.ControlInterface = "em0"
		return c
	}
	rejoiner = NewManager(0, 1)
	incumbent = NewManager(1, 1)
	t.Cleanup(rejoiner.Stop)
	t.Cleanup(incumbent.Stop)
	rejoiner.UpdateConfig(cfg())
	incumbent.UpdateConfig(cfg())
	// Both nodes prove their dataplane is armed (arm debt cleared), so
	// the rejoiner would carry full weight 255 — this is the "armed" row:
	// armed but still inside the sync hold.
	rejoiner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	incumbent.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	// #16741 models the startup hold as installed election debt: while
	// the hold is active the rejoiner advertises the arm-floor weight, so
	// the incumbent can see it cannot take over.
	rejoiner.SetMonitorWeight(1, startupSyncHoldMonitorIface, true, startupSyncHoldMonitorCost)

	// The incumbent owns the RG (it took over during the rejoiner's
	// outage). The rejoiner is ready in the interface/dataplane sense —
	// its gate is closed ONLY by the sync hold reason.
	incumbent.SetRGReady(1, true, nil)
	rejoiner.mu.Lock()
	rejoiner.groups[1].Ready = true
	rejoiner.groups[1].ReadySince = time.Now().Add(-time.Hour)
	rejoiner.groups[1].State = StateSecondary
	rejoiner.mu.Unlock()
	// ...then the sync hold closes its gate: not ready for takeover.
	rejoiner.SetRGReady(1, false, []string{"session sync startup hold: bulk sync not yet complete"})
	// After the rejoiner's rejoin, the incumbent is the established
	// owner (the crash-failover half of the shape); stamp the role
	// directly — UpdateConfig's isolated election may have resolved
	// the initial both-secondary differently per preempt setting.
	incumbent.mu.Lock()
	incumbent.groups[1].State = StatePrimary
	incumbent.groups[1].Ready = true
	incumbent.groups[1].ReadySince = time.Now().Add(-time.Hour)
	incumbent.mu.Unlock()
	rejoiner.mu.Lock()
	rejoiner.groups[1].State = StateSecondary
	rejoiner.mu.Unlock()
	if rejoiner.IsLocalPrimary(1) {
		t.Fatal("fixture: rejoiner must start secondary")
	}
	return rejoiner, incumbent
}

func exchange16741(rejoiner, incumbent *Manager) {
	for range 6 {
		incumbent.handlePeerHeartbeat(rejoiner.buildHeartbeat())
		rejoiner.handlePeerHeartbeat(incumbent.buildHeartbeat())
	}
}

// The acceptance row: a held-armed rejoiner must not leave the incumbent
// ownerless. One owner the entire time; ownership transfers only after
// the hold releases.
func TestPreemptIncumbentKeepsRGWhileRejoinerHeld16741(t *testing.T) {
	rejoiner, incumbent := preemptRejoinFixture16741(t, true)

	for round := range 10 {
		exchange16741(rejoiner, incumbent)
		owners := 0
		if incumbent.IsLocalPrimary(1) {
			owners++
		}
		if rejoiner.IsLocalPrimary(1) {
			owners++
		}
		if owners != 1 {
			t.Fatalf("round %d: owners=%d (incumbent=%v rejoiner=%v), want exactly 1 — "+
				"neither node may own RG1 while the rejoiner is in its startup sync hold",
				round, owners, incumbent.IsLocalPrimary(1), rejoiner.IsLocalPrimary(1))
		}
	}
	// In particular the incumbent must not have demoted at all.
	if !incumbent.IsLocalPrimary(1) {
		t.Fatal("incumbent demoted to a peer that cannot take over; RG has no owner " +
			"until the sync hold releases (#16741)")
	}
	if rejoiner.IsLocalPrimary(1) {
		t.Fatal("rejoiner promoted while its readiness gate was closed by the sync hold")
	}

	// The hold releases (bulk sync completes): the wire weight returns
	// with the real weight and ordinary preempt hands the RG over.
	rejoiner.SetMonitorWeight(1, startupSyncHoldMonitorIface, false, startupSyncHoldMonitorCost)
	rejoiner.SetRGReady(1, true, nil)
	exchange16741(rejoiner, incumbent)
	if !rejoiner.IsLocalPrimary(1) {
		t.Fatal("after the sync hold releases, the higher-priority rejoiner must take over (preempt)")
	}
	if incumbent.IsLocalPrimary(1) {
		t.Fatal("after takeover, the incumbent must be secondary")
	}
}

// The wire advertises the arm-floor weight while the rejoiner is held —
// and stops advertising it once the hold releases. This pins the debt
// install: a shell that only changes the receiver predicate must not pass.
func TestHeldRejoinerAdvertisesNotReady16741(t *testing.T) {
	rejoiner, incumbent := preemptRejoinFixture16741(t, true)

	pkt := rejoiner.buildHeartbeat()
	var held *HeartbeatGroup
	for i := range pkt.Groups {
		if pkt.Groups[i].GroupID == 1 {
			held = &pkt.Groups[i]
		}
	}
	if held == nil {
		t.Fatal("rejoiner heartbeat carries no RG1 entry")
	}
	if held.Weight != 1 {
		t.Fatalf("held rejoiner advertises wire weight %d, want 1 (the arm floor): the "+
			"incumbent reads full weight and yields into the ownerless window",
			held.Weight)
	}
	incumbent.handlePeerHeartbeat(rejoiner.buildHeartbeat())
	st := incumbent.PeerGroupStates()[1]
	if st.takeoverReady {
		t.Fatal("peer takeoverReady must be false while the rejoiner advertises the arm floor")
	}

	rejoiner.SetMonitorWeight(1, startupSyncHoldMonitorIface, false, startupSyncHoldMonitorCost)
	rejoiner.SetRGReady(1, true, nil)
	for _, g := range rejoiner.buildHeartbeat().Groups {
		if g.GroupID == 1 && g.Weight != 255 {
			t.Fatalf("after the hold releases the rejoiner advertises weight %d, want its real 255", g.Weight)
		}
	}
	incumbent.handlePeerHeartbeat(rejoiner.buildHeartbeat())
	if st = incumbent.PeerGroupStates()[1]; !st.takeoverReady {
		t.Fatal("peer takeoverReady must be true once the rejoiner is ready and armed")
	}
}

// The takeover-hold row: ready but inside the hold window. The hold debt
// is bounded by the same 30s class; while installed the incumbent stays.
func TestRejoinerInTakeoverHoldAdvertisesNotReady16741(t *testing.T) {
	rejoiner, incumbent := preemptRejoinFixture16741(t, true)
	rejoiner.mu.Lock()
	rejoiner.takeoverHoldTime = time.Hour
	rejoiner.mu.Unlock()
	rejoiner.SetRGReady(1, true, nil) // ready, but the hour-long hold has just started
	exchange16741(rejoiner, incumbent)
	if !incumbent.IsLocalPrimary(1) || rejoiner.IsLocalPrimary(1) {
		t.Fatal("takeover hold must keep the incumbent the single owner, same as the sync hold")
	}

	// Elapse the hold on BOTH clocks and clear the debt: the RG hands over.
	rejoiner.SetMonitorWeight(1, startupSyncHoldMonitorIface, false, startupSyncHoldMonitorCost)
	rejoiner.mu.Lock()
	rejoiner.groups[1].ReadySince = time.Now().Add(-2 * time.Hour)
	rejoiner.mu.Unlock()
	incumbent.mu.Lock()
	incumbent.takeoverHoldTime = time.Hour
	incumbent.mu.Unlock()
	exchange16741(rejoiner, incumbent)
	if !rejoiner.IsLocalPrimary(1) || incumbent.IsLocalPrimary(1) {
		t.Fatal("after the takeover hold elapses the rejoiner must own RG1")
	}
}

// The non-preempt row of the same acceptance criterion. The incumbent
// already stays under ordinary election, so this cell pins that the fix
// does not disturb it — and that the wire clamp does not accidentally
// demote the incumbent there either.
func TestNonPreemptIncumbentKeepsRGWhileRejoinerHeld16741(t *testing.T) {
	rejoiner, incumbent := preemptRejoinFixture16741(t, false)

	for round := range 10 {
		exchange16741(rejoiner, incumbent)
		if !incumbent.IsLocalPrimary(1) || rejoiner.IsLocalPrimary(1) {
			t.Fatalf("round %d: non-preempt incumbent must stay the single owner "+
				"(incumbent=%v rejoiner=%v)", round,
				incumbent.IsLocalPrimary(1), rejoiner.IsLocalPrimary(1))
		}
	}
	// Non-preempt: releasing the hold does not move the RG either; only a
	// failover does. Pinning this guards the #9452 green cells.
	rejoiner.SetMonitorWeight(1, startupSyncHoldMonitorIface, false, startupSyncHoldMonitorCost)
	rejoiner.SetRGReady(1, true, nil)
	exchange16741(rejoiner, incumbent)
	if !incumbent.IsLocalPrimary(1) || rejoiner.IsLocalPrimary(1) {
		t.Fatal("non-preempt incumbent must keep RG1 after the rejoiner's hold releases")
	}
}

// A cold-booting peer is also gate-closed, so it also advertises weight 0.
// That must NOT read as a yielded/failed peer to a not-ready local node:
// the #9452 cold-boot control still holds (no DEGRADED promotion against a
// healthy-weight-0 cold boot). The readiness flag is deliberately NOT a
// cold-boot discriminator here — weight-0 peers failing open through
// peerYieldedOwnership is the #9452 contract — this cell pins that the
// incumbent-yield suppression did not leak into the promotion side.
func TestGateClosedPeerDoesNotPromoteHeldLocal16741(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	cfg.ControlInterface = "em0"
	m.UpdateConfig(cfg)
	m.mu.Lock()
	rg := m.groups[0]
	rg.State = StateSecondary
	rg.Ready = false
	rg.ReadySince = time.Time{}
	rg.ReadinessReasons = []string{"session sync startup hold: bulk sync not yet complete"}
	m.mu.Unlock()

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			// A held rejoiner on the wire after the clamp: full priority,
			// weight 0, secondary.
			{GroupID: 0, Priority: 200, Weight: 0, State: uint8(StateSecondary)},
		},
	})
	// Identical expectation to the #9452 weight-0 cell: the peer has
	// resigned its claim (weight 0 forces secondary), so holding the
	// local node secondary leaves the RG ownerless and the degraded
	// gate fails open to a DEGRADED promotion. What this cell guards is
	// that the clamp did not break that path.
	if !m.IsLocalPrimary(0) {
		t.Fatal("weight-0 peer + not-ready local must still fail open via peerYieldedOwnership (#9452)")
	}
	var msg string
	for _, ev := range m.history.Events(EventRG) {
		if ev.GroupID == 0 && strings.Contains(ev.Message, "->primary") {
			msg = ev.Message
		}
	}
	if !strings.Contains(msg, "DEGRADED") {
		t.Fatalf("promotion against a weight-0 peer must name itself DEGRADED, got %q", msg)
	}
}

// A committed (pinned) owner must not be force-demoted by a gate-closed
// peer's demotion arms. Without the takeoverReady guard, a peer that
// re-registers after a restart (fresh PeerGroupState again, weight now
// clamped to 0 by #16741) runs the committed-secondary "arm debt" and
// grace arms against a peer that cannot take over. Positive-weight peer
// (the pre-#16741 wire) keeps yielding exactly as before.
func TestCommittedOwnerNotDemotedByGateClosedPeer16741(t *testing.T) {
	for _, peerWeight := range []uint8{0, 255} {
		m := NewManager(0, 1)
		cfg := makeConfig(makeRG(1, true, map[int]int{0: 200}))
		cfg.ControlInterface = "em0"
		m.UpdateConfig(cfg)

		// Committed new owner: pinned primary via a completed transfer.
		m.mu.Lock()
		m.groups[1].transferCommitRolePinned = true
		m.groups[1].transferCommitRole = StatePrimary
		m.groups[1].State = StatePrimary
		m.groups[1].Ready = true
		m.groups[1].ReadySince = time.Now().Add(-time.Hour)
		m.mu.Unlock()

		// Arm debt so the yield exception would be eligible if the peer
		// were genuinely takeover-ready at full weight.
		m.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)

		// Peer session: primary earlier (so it is not a cold boot), now
		// reporting secondary at the requested wire weight.
		m.handlePeerHeartbeat(&HeartbeatPacket{
			NodeID:    1,
			ClusterID: 1,
			Groups: []HeartbeatGroup{
				{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
			},
		})
		m.handlePeerHeartbeat(&HeartbeatPacket{
			NodeID:    1,
			ClusterID: 1,
			Groups: []HeartbeatGroup{
				{GroupID: 1, Priority: 100, Weight: peerWeight, State: uint8(StateSecondary)},
			},
		})

		if peerWeight == 0 {
			if !m.IsLocalPrimary(1) {
				t.Fatal("committed owner must not yield to a gate-closed (weight-0) peer " +
					"that cannot take over (#16741)")
			}
		} else {
			// Control: at full weight the arm-debt yield still fires and
			// the peer takes the RG on its next heartbeat.
			if m.IsLocalPrimary(1) {
				t.Fatal("control: committed owner with arm debt must yield to a healthy " +
					"full-weight peer (#12164 arm-debt handover)")
			}
		}
		m.Stop()
	}
}
