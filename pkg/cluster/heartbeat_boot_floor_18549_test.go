package cluster

import (
	"testing"
	"time"
)

// #18549: a rejoined node reported "Takeover ready: yes" ~2s after its
// heartbeat started, yet the 30s cold-boot floor kept it from declaring its
// peer lost: test-double-failover's second takeover waited for the floor
// (loss: peer lost at heartbeat-start + 30.005s, 13s outage; tcp: +30.008s,
// 5s). The floor's boot part now ends once bring-up is proven over: inbound
// bulk complete, then the peer heard gap-free for heartbeatBootStableWindow.

const crashedAgo18549 = 2 * time.Second // > threshold*interval at defaults

// rejoinedReceiver18549 is the double-failover shape on the rejoined node:
// a cold-start receiver 20s into its 30s floor, the peer heard steadily since
// the start, the inbound bulk complete 2s in, and the peer silent for
// crashedAgo18549 (it crashed).
func rejoinedReceiver18549(t *testing.T) (*Manager, *heartbeatReceiver) {
	t.Helper()
	m, r := seenPeerManager9722(t)
	now := MonotonicNanos()
	r.startedAt = time.Now().Add(-20 * time.Second)
	if time.Since(r.startedAt) >= heartbeatStartupGrace {
		t.Fatal("fixture: must sit inside the cold-boot floor")
	}
	r.lastSeen.Store(now - crashedAgo18549.Nanoseconds())
	m.mu.Lock()
	m.syncBulkPrimed = true
	m.syncBulkPrimedAtMono = now - (18 * time.Second).Nanoseconds()
	m.peerHBSteadySinceMono = now - (19900 * time.Millisecond).Nanoseconds()
	m.peerHBLastAdmitMono = now - crashedAgo18549.Nanoseconds()
	m.mu.Unlock()
	return m, r
}

func TestRejoinedTakeoverReadyNodeDetectsPeerLossInsideBootFloor18549(t *testing.T) {
	m, r := rejoinedReceiver18549(t)
	r.checkTimeout()
	if m.PeerAlive() {
		t.Fatalf("a rejoined node with its inbound bulk complete and the peer heard gap-free for "+
			"~16s did not declare the peer lost %v after it went silent: the %v cold-boot floor "+
			"is still holding, so a takeover-ready node blackholes the peer's RGs until it ends (#18549)",
			crashedAgo18549, heartbeatStartupGrace)
	}
}

// Each piece of the proof is necessary: without it the boot floor holds
// exactly as #4386 requires.
func TestBootFloorHoldsWithoutTheFullProof18549(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(m *Manager, now int64)
	}{
		{"inbound bulk not complete", func(m *Manager, now int64) {
			m.syncBulkPrimed = false
			m.syncBulkPrimedAtMono = 0
		}},
		{"stable for less than the window after the bulk", func(m *Manager, now int64) {
			// bulk 3s ago, last frame 2s ago: 1s of post-bulk stability
			m.syncBulkPrimedAtMono = now - (3 * time.Second).Nanoseconds()
		}},
		{"silence after the bulk is not stability", func(m *Manager, now int64) {
			// bulk 8s ago, last admitted frame 6s ago: only 2s of
			// post-bulk stability, followed by 6s of silence. Measured to
			// NOW the run would read 8s and end the floor on silence.
			m.syncBulkPrimedAtMono = now - (8 * time.Second).Nanoseconds()
			m.peerHBLastAdmitMono = now - (6 * time.Second).Nanoseconds()
			m.hbReceiver.lastSeen.Store(m.peerHBLastAdmitMono)
		}},
		{"the run restarted after a gap", func(m *Manager, now int64) {
			// a gap 4s ago reset the run; last frame 2s ago: 2s of run
			m.peerHBSteadySinceMono = now - (4 * time.Second).Nanoseconds()
		}},
		{"no admitted heartbeat run recorded", func(m *Manager, now int64) {
			m.peerHBSteadySinceMono, m.peerHBLastAdmitMono = 0, 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, r := rejoinedReceiver18549(t)
			m.mu.Lock()
			tc.mutate(m, MonotonicNanos())
			m.mu.Unlock()
			r.checkTimeout()
			if !m.PeerAlive() {
				t.Fatalf("the cold-boot floor ended without the full proof (%s); a boot-time RX "+
					"disruption would now declare a live peer lost (#4386)", tc.name)
			}
		})
	}
}

// A restart receiver's own 5s grace is never shortened by the proof (#9722),
// but a BOOT floor it inherited (#17764) is.
func TestBootFloorProofEndsOnlyTheBootFloor18549(t *testing.T) {
	t.Run("restart grace still holds", func(t *testing.T) {
		m, r := rejoinedReceiver18549(t)
		r.armRestart(r.lastSeen.Load(), time.Now().Add(10*time.Second))
		r.startedAt = time.Now().Add(-time.Second) // inside the 5s restart grace
		r.checkTimeout()
		if !m.PeerAlive() {
			t.Fatal("the boot-floor proof shortened a heartbeat restart's own grace (#9722)")
		}
	})
	t.Run("inherited boot floor ends", func(t *testing.T) {
		m, r := rejoinedReceiver18549(t)
		r.armRestart(r.lastSeen.Load(), time.Now().Add(10*time.Second)) // boot floor 10s away
		r.startedAt = time.Now().Add(-(heartbeatRestartGrace + time.Second))
		r.checkTimeout()
		if m.PeerAlive() {
			t.Fatal("a proven-over boot floor inherited across a heartbeat restart still held the " +
				"timeout (#17764 inheritance must end with the proof)")
		}
	})
}

// The run bookkeeping is wired to the real admission and loss paths.
func TestPeerHeartbeatRunTrackingWiring18549(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.Stop)
	m.UpdateConfig(makeConfig(makeRG(1, false, map[int]int{0: 200, 1: 100})))
	pkt := &HeartbeatPacket{NodeID: 1, ClusterID: 1, Groups: []HeartbeatGroup{
		{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
	}}
	m.handlePeerHeartbeat(pkt)
	m.mu.RLock()
	first, last := m.peerHBSteadySinceMono, m.peerHBLastAdmitMono
	m.mu.RUnlock()
	if first == 0 || last == 0 {
		t.Fatal("handlePeerHeartbeat did not start the admitted-heartbeat run")
	}
	m.handlePeerHeartbeat(pkt)
	m.mu.RLock()
	if m.peerHBSteadySinceMono != first || m.peerHBLastAdmitMono < last {
		t.Errorf("a gap-free frame restarted the run (since %d -> %d) or did not advance it",
			first, m.peerHBSteadySinceMono)
	}
	m.mu.RUnlock()

	// A frame after a gap of threshold*interval restarts the run.
	m.mu.Lock()
	m.peerHBLastAdmitMono -= (10 * time.Second).Nanoseconds()
	m.peerHBSteadySinceMono -= (10 * time.Second).Nanoseconds()
	old := m.peerHBSteadySinceMono
	m.mu.Unlock()
	m.handlePeerHeartbeat(pkt)
	m.mu.RLock()
	if m.peerHBSteadySinceMono == old {
		t.Error("a frame after a 10s gap did not restart the gap-free run")
	}
	m.mu.RUnlock()

	m.SetSyncBulkPrimed(true)
	m.mu.RLock()
	if m.syncBulkPrimedAtMono == 0 {
		t.Error("SetSyncBulkPrimed(true) did not stamp the bulk completion")
	}
	m.mu.RUnlock()

	m.handlePeerTimeout()
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.peerHBSteadySinceMono != 0 || m.peerHBLastAdmitMono != 0 {
		t.Error("peer loss did not reset the admitted-heartbeat run")
	}
}
