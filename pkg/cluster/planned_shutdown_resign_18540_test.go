package cluster

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #18540: an orderly private-RG stop must hand every redundancy group to the
// peer at once, including to a peer parked in secondary-hold by an earlier
// manual failover — the state `test-restart-connectivity`'s restore step
// leaves fw1 in before every cycle after the first.
//
// The cells are BLACK-BOX over the wire shape: two real managers exchange
// buildHeartbeat/handlePeerHeartbeat frames, so the peer sees exactly what
// the stopping node advertises. Injecting PeerGroupState by hand would let a
// resign that never reached the wire weight pass.

var restartRGs18540 = []int{0, 1, 2}

// restartFixture18540 builds the loss-cluster shape before a restart cycle:
//
//	leaving (node0, fw0): primary for RG0/1/2, armed, ready.
//	holder  (node1, fw1): secondary-hold on RG0/1/2 after
//	  `request chassis cluster failover redundancy-group N` ran on it.
//
// Non-preempt, priorities 200/100 as in docs/ha-cluster-userspace.conf.
func restartFixture18540(t *testing.T) (leaving, holder *Manager) {
	t.Helper()
	cfg := func() *config.ClusterConfig {
		var rgs []*config.RedundancyGroup
		for _, id := range restartRGs18540 {
			rgs = append(rgs, makeRG(id, false, map[int]int{0: 200, 1: 100}))
		}
		c := makeConfig(rgs...)
		c.ControlInterface = "em0"
		return c
	}
	leaving = NewManager(0, 1)
	holder = NewManager(1, 1)
	t.Cleanup(leaving.Stop)
	t.Cleanup(holder.Stop)
	leaving.UpdateConfig(cfg())
	holder.UpdateConfig(cfg())
	for _, id := range restartRGs18540 {
		leaving.SetMonitorWeight(id, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
		holder.SetMonitorWeight(id, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	}
	for _, m := range []*Manager{leaving, holder} {
		m.mu.Lock()
		for _, id := range restartRGs18540 {
			m.groups[id].Ready = true
			m.groups[id].ReadySince = time.Now().Add(-time.Hour)
		}
		m.mu.Unlock()
	}
	leaving.mu.Lock()
	for _, id := range restartRGs18540 {
		leaving.groups[id].State = StatePrimary
	}
	leaving.mu.Unlock()
	holder.mu.Lock()
	for _, id := range restartRGs18540 {
		rg := holder.groups[id]
		rg.State = StateSecondaryHold
		rg.ManualFailover = true
		// The restore step ran well before the cycle: the 2s dual-resign
		// guard in electRG is long past, as it was on the loss cluster.
		rg.ManualFailoverAt = time.Now().Add(-time.Minute)
	}
	holder.mu.Unlock()
	exchange18540(leaving, holder)
	for _, id := range restartRGs18540 {
		if !leaving.IsLocalPrimary(id) || holder.IsLocalPrimary(id) {
			t.Fatalf("fixture RG%d: leaving primary=%v holder primary=%v, want leaving the only owner",
				id, leaving.IsLocalPrimary(id), holder.IsLocalPrimary(id))
		}
	}
	return leaving, holder
}

func exchange18540(a, b *Manager) {
	for range 4 {
		b.handlePeerHeartbeat(a.buildHeartbeat())
		a.handlePeerHeartbeat(b.buildHeartbeat())
	}
}

// ownersOf18540 reports, per RG, which of the two nodes is primary.
func ownersOf18540(a, b *Manager) map[int][2]bool {
	out := map[int][2]bool{}
	for _, id := range restartRGs18540 {
		out[id] = [2]bool{a.IsLocalPrimary(id), b.IsLocalPrimary(id)}
	}
	return out
}

// The control row is what the stop advertised before #18540: the
// fail-closed arm floor (weight 1) and nothing else. It is the cycle-2/3
// shape: nothing moves while the stopping node is still heard, so the RGs
// wait for heartbeat loss with the stopping node's helper already gone.
// This row pins the defect's mechanism; it is not a regression bar.
func TestArmFloorAloneDoesNotMoveRGsToAHoldingPeer18540(t *testing.T) {
	leaving, holder := restartFixture18540(t)
	for _, id := range restartRGs18540 {
		leaving.SetMonitorWeight(id, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	}
	exchange18540(leaving, holder)
	for id, own := range ownersOf18540(leaving, holder) {
		if own[1] {
			t.Fatalf("RG%d moved to the holding peer on the arm floor alone; the #18540 "+
				"control row no longer describes the pre-fix stop — re-derive the fixture", id)
		}
	}
}

// The acceptance row. After the resign, one frame from the stopping node
// promotes the holding peer on EVERY RG — RG0 included, which never yields
// on arm debt — and the stopping node holds none.
func TestPlannedShutdownResignHandsEveryRGToHoldingPeer18540(t *testing.T) {
	leaving, holder := restartFixture18540(t)
	// The fail-closed stop's arm floor is installed first in the real
	// sequence (markDataplaneNotArmed precedes the resign).
	for _, id := range restartRGs18540 {
		leaving.SetMonitorWeight(id, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	}
	if got := leaving.ResignForPlannedShutdown(); got != len(restartRGs18540) {
		t.Fatalf("ResignForPlannedShutdown resigned %d groups, want %d", got, len(restartRGs18540))
	}
	pkt := leaving.buildHeartbeat()
	for _, g := range pkt.Groups {
		if g.Weight != 0 {
			t.Errorf("wire RG%d weight=%d after the resign, want 0: the peer's takeover arms key on "+
				"an advertised weight of 0", g.GroupID, g.Weight)
		}
	}
	// ONE frame, no reply: the peer must act on the resign alone, before
	// the stopping node's heartbeat goes silent.
	holder.handlePeerHeartbeat(pkt)
	for id, own := range ownersOf18540(leaving, holder) {
		if !own[1] {
			t.Errorf("RG%d: holding peer did not take over on the planned-shutdown resign "+
				"(it stays parked until heartbeat loss, the #18540 blackhole)", id)
		}
		if own[0] {
			t.Errorf("RG%d: the stopping node still claims primary after resigning", id)
		}
	}
	if got := leaving.ResignForPlannedShutdown(); got != 0 {
		t.Errorf("a repeated resign re-installed %d debts, want 0 (idempotent)", got)
	}
}

// The resign must outlive everything that can recompute weight on the way
// out: the dataplane-arm debt clearing or re-arming, and a config apply's
// monitor reconcile. A resign that a later recalc lifts back to the floor
// re-creates the control row above.
func TestPlannedShutdownResignSurvivesRecalcAndReconcile18540(t *testing.T) {
	leaving, _ := restartFixture18540(t)
	leaving.ResignForPlannedShutdown()

	leaving.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
	leaving.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	var rgs []*config.RedundancyGroup
	for _, id := range restartRGs18540 {
		rgs = append(rgs, makeRG(id, false, map[int]int{0: 200, 1: 100}))
	}
	c := makeConfig(rgs...)
	c.ControlInterface = "em0"
	leaving.UpdateConfig(c)

	for _, rg := range leaving.GroupStates() {
		if rg.Weight != 0 {
			t.Errorf("RG%d weight=%d after a recalc and a config reconcile, want 0 — the "+
				"planned-shutdown debt must be a reserved, full-cost debt", rg.GroupID, rg.Weight)
		}
	}
}

// The resign is useful only if the peer hears it before the heartbeat stops,
// so it must not wait for the next cadence tick. The sender here ticks once
// an hour; the only way a frame arrives within the budget is the kick.
func TestPlannedShutdownResignSendsAHeartbeatAtOnce18540(t *testing.T) {
	leaving, _ := restartFixture18540(t)

	rx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rx.Close()
	tx, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen tx: %v", err)
	}
	sender := newHeartbeatSender(leaving, tx, rx.LocalAddr().(*net.UDPAddr), time.Hour)
	leaving.mu.Lock()
	leaving.hbSender = sender
	leaving.mu.Unlock()
	sender.start()
	// leaving.Stop (t.Cleanup) stops the sender and closes tx.

	leaving.ResignForPlannedShutdown()

	// Clause 3 (#8218): a wait budget sized for a loaded box, not a
	// pass criterion. The healthy path delivers in microseconds.
	if err := rx.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 64*1024)
	n, _, err := rx.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no heartbeat within the budget after the resign (the sender's cadence is 1h, "+
			"so only an immediate send can arrive): %v", err)
	}
	pkt, err := UnmarshalHeartbeat(buf[:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(pkt.Groups) != len(restartRGs18540) {
		t.Fatalf("frame carries %d groups, want %d", len(pkt.Groups), len(restartRGs18540))
	}
	for _, g := range pkt.Groups {
		if g.Weight != 0 {
			t.Errorf("immediate frame advertises RG%d weight=%d, want the resigned 0", g.GroupID, g.Weight)
		}
	}
}

// A resign after Stop cannot reach the peer (the heartbeat sender is gone),
// so it must not install a debt that makes a misordered shutdown look as if
// it had handed over.
func TestPlannedShutdownResignAfterStopIsRefused18540(t *testing.T) {
	leaving, _ := restartFixture18540(t)
	leaving.Stop()
	if got := leaving.ResignForPlannedShutdown(); got != 0 {
		t.Fatalf("resign after Stop installed %d debts, want 0", got)
	}
	for _, rg := range leaving.GroupStates() {
		for _, f := range rg.MonitorFails {
			if f == PlannedShutdownMonitorIface {
				t.Fatalf("RG%d carries the planned-shutdown debt after a refused resign", rg.GroupID)
			}
		}
	}
}

// #18540 review: with no live peer the resign is a no-op. A lone node keeps
// ownership through its stop; demoting it would hand the daemon's still-live
// event watcher an RG0 demotion that confirms a pending commit-confirmed.
func TestPlannedShutdownResignSkippedWithoutLivePeer18540(t *testing.T) {
	var rgs []*config.RedundancyGroup
	for _, id := range restartRGs18540 {
		rgs = append(rgs, makeRG(id, false, map[int]int{0: 200, 1: 100}))
	}
	lone := NewManager(0, 1)
	t.Cleanup(lone.Stop)
	lone.UpdateConfig(makeConfig(rgs...))
	for _, id := range restartRGs18540 {
		if !lone.IsLocalPrimary(id) {
			t.Fatalf("fixture: lone node must own RG%d", id)
		}
	}
	if got := lone.ResignForPlannedShutdown(); got != 0 {
		t.Fatalf("lone-node resign installed %d debts, want 0", got)
	}
	for _, rg := range lone.GroupStates() {
		if rg.State != StatePrimary {
			t.Errorf("RG%d demoted by a lone-node resign", rg.GroupID)
		}
		for _, f := range rg.MonitorFails {
			if f == PlannedShutdownMonitorIface {
				t.Errorf("RG%d carries the planned-shutdown debt with no live peer", rg.GroupID)
			}
		}
	}
}

// #18540 x #18521: the leaving node is the REQUESTER of an in-flight
// transfer. The owner has demoted for it and holds the #18521 lease with the
// session-sync connection intact, so neither the 2s dual-resign guard nor the
// lease path would release it — and a leaving requester will never commit.
// The planned-shutdown resign must release that hold on the resign frame;
// otherwise the RG is unowned until heartbeat loss.
//
// The #18521 row "requester advertising weight 0" (bare weight 0, no marker)
// must keep holding: TestInFlightRemoteTransferHoldOutlivesDualResignTimer18521
// stays green, which is why the release keys on the reserved monitor marker
// and not on weight 0.
func TestPlannedShutdownResignReleasesInFlightTransferLease18540(t *testing.T) {
	owner := inflightOwner18521(t) // node1, demoted for RG2, lease live, sync intact
	requester := NewManager(0, 1)
	t.Cleanup(requester.Stop)
	requester.UpdateConfig(makeConfig(makeRG(2, false, map[int]int{0: 100, 1: 200})))
	requester.SetMonitorWeight(2, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	requester.handlePeerHeartbeat(owner.buildHeartbeat()) // the requester hears its peer

	owner.mu.Lock()
	_, leased := owner.remoteTransferOutLeaseUntil[2]
	intact := owner.transferChannelIntactLocked(2)
	owner.mu.Unlock()
	if held, _ := ownerHold18521(owner); !held || !leased || !intact {
		t.Fatalf("fixture: owner must be parked by a live lease on an intact channel "+
			"(held=%v leased=%v intact=%v)", held, leased, intact)
	}

	if got := requester.ResignForPlannedShutdown(); got != 1 {
		t.Fatalf("requester resigned %d groups, want 1", got)
	}
	pkt := requester.buildHeartbeat()
	marked := false
	for _, mon := range pkt.Monitors {
		if mon.Interface == PlannedShutdownMonitorIface && !mon.Up && mon.RGID == 2 {
			marked = true
		}
	}
	if !marked {
		t.Fatal("the resign frame must carry the planned-shutdown marker for RG2")
	}
	// ONE frame: the leaving requester's heartbeat stops soon after.
	owner.handlePeerHeartbeat(pkt)

	if held, _ := ownerHold18521(owner); held || !owner.IsLocalPrimary(2) {
		t.Fatalf("the owner stayed parked behind the in-flight transfer lease after its requester "+
			"resigned for a planned shutdown (primary=%v): the RG is unowned until heartbeat loss",
			owner.IsLocalPrimary(2))
	}
	owner.mu.Lock()
	_, stillLeased := owner.remoteTransferOutLeaseUntil[2]
	owner.mu.Unlock()
	if stillLeased {
		t.Error("the abandoned transfer's lease must end with the hold")
	}
}

// The 2s dual-resign guard is measured from this node's OWN yield; it keeps a
// just-made handoff from being undone by stale peer state. A peer that is
// leaving completes no handoff, so a fresh operator hold must release on the
// resign frame too, not after heartbeat loss.
func TestPlannedShutdownResignReleasesFreshManualFailoverHold18540(t *testing.T) {
	leaving, holder := restartFixture18540(t)
	holder.mu.Lock()
	for _, id := range restartRGs18540 {
		holder.groups[id].ManualFailoverAt = time.Now() // inside the 2s guard
	}
	holder.mu.Unlock()
	leaving.ResignForPlannedShutdown()
	holder.handlePeerHeartbeat(leaving.buildHeartbeat())
	for _, id := range restartRGs18540 {
		if !holder.IsLocalPrimary(id) {
			t.Errorf("RG%d: a hold under the 2s guard outlived the peer's planned-shutdown resign", id)
		}
	}
}

// A marker without the resign (weight > 0) is inconsistent and must not
// release the #18521 hold: the marker announces a resign, it does not replace
// one.
func TestPlannedShutdownMarkerWithoutResignKeepsLease18540(t *testing.T) {
	// Each row is one way the frame fails to say "RG2 is resigned for a
	// planned shutdown". Bare weight 0 on RG2 (a requester momentarily at
	// weight 0 inside its commit window, #18521) must keep the hold unless
	// the marker for RG2 itself is present and down.
	for _, row := range []struct {
		name   string
		weight uint8
		state  NodeState
		mon    HeartbeatMonitor
	}{
		{"marker on a weight-255 frame", 255, StateSecondaryHold,
			HeartbeatMonitor{RGID: 2, Weight: 255, Up: false, Interface: PlannedShutdownMonitorIface}},
		{"marker for a different RG", 0, StateSecondary,
			HeartbeatMonitor{RGID: 7, Weight: 255, Up: false, Interface: PlannedShutdownMonitorIface}},
		{"marker reported up", 0, StateSecondary,
			HeartbeatMonitor{RGID: 2, Weight: 255, Up: true, Interface: PlannedShutdownMonitorIface}},
	} {
		t.Run(row.name, func(t *testing.T) {
			owner := inflightOwner18521(t)
			owner.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1,
				Groups:   []HeartbeatGroup{{GroupID: 2, Priority: 100, Weight: row.weight, State: uint8(row.state)}},
				Monitors: []HeartbeatMonitor{row.mon},
			})
			if held, state := ownerHold18521(owner); !held || state == StatePrimary {
				t.Fatalf("%s released the in-flight lease hold (held=%v state=%s)", row.name, held, state)
			}
		})
	}
}
