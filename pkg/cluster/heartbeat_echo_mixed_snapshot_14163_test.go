package cluster

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #14163: buildHeartbeat chose the echoed peer session/sequence by ranging
// over m.peerGroups and taking the first nonzero entry. handlePeerHeartbeat
// normally stamps every entry with the same packet identity, but
// restorePeerTransferOutOverrideLocked can put an older PeerGroupState back
// for one RG after a newer heartbeat has already refreshed the others.
// The mixed map then lets a transmit echo the stale sequence (map order
// decides), and the peer's strict > freshness check in handlePeerHeartbeat
// refuses to renew the echo lease for that frame. Newer heartbeats keep
// arriving, so the lease can expire while the peer is alive and heard —
// the hearing node then yields on an expired echo lease (or stalls
// recovery) even though the peer echoed a fresh sequence in its latest
// frame for the other RG.
//
// The fix tracks the last received peer heartbeat identity at Manager
// level (latestPeerHeartbeatSession/Sequence, stamped under m.mu in
// handlePeerHeartbeat) and echoes that, never a per-RG entry. This test
// drives the exact interleave: reception, transfer restore, heartbeat
// construction, next reception, and peer lease expiry.

func heartbeatEchoFixture14163(t *testing.T) (nodeA, nodeB *Manager, lease time.Duration) {
	t.Helper()
	cfg := &config.ClusterConfig{
		RethCount: 2,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
			{ID: 1, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	}
	nodeA = NewManager(0, 1)
	nodeB = NewManager(1, 1)
	nodeA.UpdateConfig(cfg)
	nodeB.UpdateConfig(cfg)
	drainEvents(nodeA, 100)
	drainEvents(nodeB, 100)
	// Short deterministic lease: interval*threshold.
	nodeA.mu.Lock()
	nodeA.hbInterval = 50 * time.Millisecond
	nodeA.hbThreshold = 4
	nodeA.mu.Unlock()
	nodeB.mu.Lock()
	nodeB.hbInterval = 50 * time.Millisecond
	nodeB.hbThreshold = 4
	nodeB.mu.Unlock()
	lease = 200 * time.Millisecond
	// nodeA primary for both RGs (higher priority, preempt defaults false?
	// makeRG not used; priorities give A higher. States start secondary;
	// exchange a few rounds to settle.
	nodeA.SetRGReady(0, true, nil)
	nodeA.SetRGReady(1, true, nil)
	nodeB.SetRGReady(0, true, nil)
	nodeB.SetRGReady(1, true, nil)
	for range 6 {
		nodeB.handlePeerHeartbeat(nodeA.buildHeartbeat())
		nodeA.handlePeerHeartbeat(nodeB.buildHeartbeat())
		drainEvents(nodeA, 100)
		drainEvents(nodeB, 100)
	}
	return nodeA, nodeB, lease
}

// TestHeartbeatEchoUsesLatestReceivedNotRestoredStaleRG14163 is the
// regression. It must fail on master (first-nonzero map pick can echo the
// restored stale sequence, so B's lease is not renewed and expires) and
// pass with the Manager-level latest-identity echo.
func TestHeartbeatEchoUsesLatestReceivedNotRestoredStaleRG14163(t *testing.T) {
	// Iterate the whole scenario many times: on master the stale pick is
	// map-order dependent (~50% per buildHeartbeat with 2 RGs), so a
	// single round could pass by luck. 40 rounds makes a false pass on
	// master vanishingly unlikely, while the fixed code passes
	// deterministically every round.
	for round := range 40 {
		nodeA, nodeB, lease := heartbeatEchoFixture14163(t)

		// Both nodes must have exchanged heartbeats: A echoes B's identity,
		// B echoes A's. Record B's latest sequence as seen by A.
		pktB := nodeB.buildHeartbeat()
		if pktB.HeartbeatSequence == 0 {
			t.Fatalf("round %d: B heartbeat sequence is zero", round)
		}
		nodeA.handlePeerHeartbeat(pktB)
		drainEvents(nodeA, 100)
		drainEvents(nodeB, 100)

		// Snapshot A's view of B for RG0 via the transfer-override arm,
		// exactly as commitRequestedPeerFailover does before election.
		const reqID = uint64(14163)
		nodeA.mu.Lock()
		nodeA.applyPeerTransferOutOverrideLocked(0, reqID)
		staleSeqA := nodeA.peerGroups[0].heartbeatSequence
		staleSessA := nodeA.peerGroups[0].heartbeatSession
		nodeA.mu.Unlock()
		if staleSeqA == 0 {
			t.Fatalf("round %d: fixture: A has no peer sequence for RG0 to snapshot", round)
		}

		// B sends several newer heartbeats. handlePeerHeartbeat rebuilds
		// ALL peerGroups from each packet, so every RG now carries B's
		// newest sequence — strictly greater than the snapshot.
		var newestSeq uint64
		for range 3 {
			p := nodeB.buildHeartbeat()
			newestSeq = p.HeartbeatSequence
			nodeA.handlePeerHeartbeat(p)
		}
		drainEvents(nodeA, 100)
		if newestSeq <= staleSeqA {
			t.Fatalf("round %d: fixture: newest B sequence %d did not advance past snapshot %d", round, newestSeq, staleSeqA)
		}

		// Abort the transfer: restore puts the OLD snapshot back for RG0
		// while RG1 keeps the newest identity — the mixed snapshot.
		nodeA.mu.Lock()
		if !nodeA.restorePeerTransferOutOverrideLocked(0, reqID) {
			nodeA.mu.Unlock()
			t.Fatalf("round %d: restorePeerTransferOutOverrideLocked did not restore", round)
		}
		restored := nodeA.peerGroups[0]
		fresh := nodeA.peerGroups[1]
		nodeA.mu.Unlock()
		if restored.heartbeatSequence != staleSeqA || restored.heartbeatSession != staleSessA {
			t.Fatalf("round %d: restored RG0 = (%d,%d), want stale snapshot (%d,%d)",
				round, restored.heartbeatSession, restored.heartbeatSequence, staleSessA, staleSeqA)
		}
		if fresh.heartbeatSequence != newestSeq {
			t.Fatalf("round %d: RG1 sequence = %d, want newest %d (mixed-snapshot precondition)",
				round, fresh.heartbeatSequence, newestSeq)
		}

		// A transmits in the mixed interval. It must echo B's LATEST
		// received identity, not whichever RG map iteration hits first.
		echoPkt := nodeA.buildHeartbeat()
		if echoPkt.PeerHeartbeatSession != staleSessA {
			t.Fatalf("round %d: echoed session = %d, want %d", round, echoPkt.PeerHeartbeatSession, staleSessA)
		}
		if echoPkt.PeerHeartbeatSequence != newestSeq {
			t.Fatalf("round %d: echoed peer sequence = %d, want latest received %d (stale snapshot %d was echoed; peer will not renew the lease for this frame)",
				round, echoPkt.PeerHeartbeatSequence, newestSeq, staleSeqA)
		}

		// Deliver A's echo to B and check B's lease renewal. B's previous
		// stored echo (from A's earlier heartbeats in the fixture) is the
		// stale snapshot sequence; the fresh echo must advance past it
		// and push the lease a full lease duration out from now. On
		// master with the stale pick, peerEchoSequence == previous, so
		// freshPeerEcho is false and the old lease (near expiry or
		// already carried) is kept instead.
		nodeB.mu.RLock()
		beforeEchoSeq := nodeB.peerGroups[1].heartbeatEchoSequence
		nodeB.mu.RUnlock()
		before := time.Now()
		nodeB.handlePeerHeartbeat(echoPkt)
		drainEvents(nodeB, 100)
		nodeB.mu.RLock()
		after := nodeB.peerGroups[1]
		nodeB.mu.RUnlock()
		if after.heartbeatEchoSequence != newestSeq {
			t.Fatalf("round %d: B stored echo sequence = %d, want %d", round, after.heartbeatEchoSequence, newestSeq)
		}
		if beforeEchoSeq != 0 && after.heartbeatEchoSequence <= beforeEchoSeq {
			t.Fatalf("round %d: B echo sequence did not advance: before=%d after=%d", round, beforeEchoSeq, after.heartbeatEchoSequence)
		}
		if after.heartbeatEchoLeaseUntil.Before(before.Add(lease / 2)) {
			t.Fatalf("round %d: B echo lease not renewed to a fresh deadline: until=%v, want >= %v (lease %v) — stale echo was refused by the strict freshness check",
				round, after.heartbeatEchoLeaseUntil, before.Add(lease/2), lease)
		}
	}
}

// TestHeartbeatEchoSingleRGAndColdStart14163 pins the non-mixed behaviour:
// with one RG and with no peer heartbeat yet, the echo is exactly the
// latest received identity or absent.
func TestHeartbeatEchoSingleRGAndColdStart14163(t *testing.T) {
	a := NewManager(0, 1)
	b := NewManager(1, 1)
	cfg := &config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	}
	a.UpdateConfig(cfg)
	b.UpdateConfig(cfg)
	drainEvents(a, 100)
	drainEvents(b, 100)

	if pkt := a.buildHeartbeat(); pkt.PeerHeartbeatSession != 0 || pkt.PeerHeartbeatSequence != 0 {
		t.Fatalf("cold start echoed (%d,%d), want (0,0)", pkt.PeerHeartbeatSession, pkt.PeerHeartbeatSequence)
	}
	pktB := b.buildHeartbeat()
	a.handlePeerHeartbeat(pktB)
	drainEvents(a, 100)
	if pkt := a.buildHeartbeat(); pkt.PeerHeartbeatSession != pktB.HeartbeatSession || pkt.PeerHeartbeatSequence != pktB.HeartbeatSequence {
		t.Fatalf("single-RG echo = (%d,%d), want latest received (%d,%d)",
			pkt.PeerHeartbeatSession, pkt.PeerHeartbeatSequence, pktB.HeartbeatSession, pktB.HeartbeatSequence)
	}
	// Newer B frame advances the echo.
	pktB2 := b.buildHeartbeat()
	a.handlePeerHeartbeat(pktB2)
	drainEvents(a, 100)
	if pkt := a.buildHeartbeat(); pkt.PeerHeartbeatSequence != pktB2.HeartbeatSequence {
		t.Fatalf("echo after newer frame = %d, want %d", pkt.PeerHeartbeatSequence, pktB2.HeartbeatSequence)
	}
}
