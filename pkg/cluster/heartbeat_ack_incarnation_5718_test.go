package cluster

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newAckTestSync builds a SessionSync with a small, explicit silence window so
// "the peer has been quiet" is deterministic without sleeping.
func newAckTestSync(t *testing.T) *SessionSync {
	t.Helper()
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.peerSilenceLimit = 50 * time.Millisecond
	return ss
}

// installAckTestConn wires conn into a fabric slot through the production
// install path and then backdates the peer-receive clock past the silence
// window, which installConn refreshes.
func installAckTestConn(t *testing.T, ss *SessionSync, fabricIdx int, conn net.Conn) {
	t.Helper()
	ss.installConn(fabricIdx, conn)
	ss.lastPeerRxMono.Store(MonotonicNanos() - int64(time.Second))
}

// pipeConn returns one end of a net.Pipe and registers both ends for cleanup.
func pipeConn(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a
}

// connInSlot reads the connection currently installed in a fabric slot.
func (s *SessionSync) connInSlot(fabricIdx int) net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fabricIdx == 0 {
		return s.conn0
	}
	return s.conn1
}

// fabricPairName labels a subtest by the fabric ordering it exercises. Both
// installConn's supersession classification and the acceptance test branch per
// fabric, so every incarnation scenario runs in both directions.
func fabricPairName(first, second int) string {
	return fmt.Sprintf("fabric%d_then_fabric%d", first, second)
}

// TestPeerHeartbeatAckEverIsPeerIncarnationScoped_5718 is the #5718 C01a
// fail-on-revert for the FULL-DISCONNECT edge.
//
// peerHeartbeatAckEver is a capability probe of the PEER PROCESS: it latches
// when the peer replies syncMsgHeartbeatAck, and both readers then switch from
// "assume healthy" to "enforce". The two readers are sync_conn_read.go's
// missed-heartbeat teardown and sync.go's PeerHealthy() silence window; both
// consult this single flag, so binding the flag binds both.
//
// The defect the fix removes: the flag was SessionSync-lifetime, written once
// and never cleared, so it survived the end of the peer incarnation that
// earned it. A peer DOWNGRADE (new build acks -> latch true -> peer rolls back
// to a build that never sends syncMsgHeartbeatAck) left the latch armed
// against a peer that can never satisfy it, so a perfectly healthy old peer
// was treated as failing: PeerHealthy() demands inbound traffic that never
// comes, which fails computeUserspaceTransferReadiness with "session sync
// disconnected" and blocks manual failover.
func TestPeerHeartbeatAckEverIsPeerIncarnationScoped_5718(t *testing.T) {
	ss := newAckTestSync(t)

	// Peer incarnation #1 connects, and has been quiet for far longer than the
	// silence window (the state a heartbeat-capable peer must not be in).
	connA := pipeConn(t)
	installAckTestConn(t, ss, 0, connA)

	// Incarnation #1 proves it understands heartbeats.
	ss.handleMessage(connA, syncMsgHeartbeatAck, nil)
	if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("syncMsgHeartbeatAck from an installed connection must latch the peer heartbeat-ack capability")
	}
	// Enforcement is now armed for THIS peer: it acks, so silence is a fault.
	if ss.PeerHealthy() {
		t.Fatal("an ack-capable peer that has been silent past the silence window must read unhealthy")
	}

	// Incarnation #1 ends. Full disconnect (conn1 was never set, so removing
	// conn0 leaves no active connection) must end the capability with it.
	ss.handleDisconnect(connA)
	if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("full disconnect must clear peerHeartbeatAckEver: the capability " +
			"belongs to the peer incarnation that proved it, not to this " +
			"SessionSync. Leaving it latched arms the missed-heartbeat teardown " +
			"(sync_conn_read.go) and PeerHealthy's silence window against the " +
			"NEXT peer, which may be a downgraded build that never acks")
	}

	// Peer incarnation #2 is a DOWNGRADED build: it never sends
	// syncMsgHeartbeatAck, so it is legitimately quiet.
	connB := pipeConn(t)
	installAckTestConn(t, ss, 0, connB)

	if !ss.PeerHealthy() {
		t.Fatal("a reconnected peer that has not proved heartbeat-ack support must " +
			"read HEALTHY (probe-then-enforce). Reading unhealthy here is the " +
			"#5718 C01a downgrade defect: a stale capability latch from the " +
			"previous peer incarnation blocks manual-failover readiness with " +
			"\"session sync disconnected\" for a peer that is fine")
	}
}

// TestPeerHeartbeatAckEverClearedOnSupersession_5718 is the fold F1
// fail-on-revert: the SUPERSESSION edge, which handleDisconnect structurally
// cannot see.
//
// A peer that reboots hard sends no FIN/RST, so our TCP connection stays
// ESTABLISHED and fabricConnectLoop will not redial a slot it believes is
// connected. The peer's NEW process dials in, acceptLoop admits it, and
// installConn replaces the slot's connection. The superseded connection's
// receiveLoop then calls handleDisconnect, which finds the slot already
// holding the NEW conn and returns down the "ignoring stale disconnect"
// default branch WITHOUT clearing anything.
//
// So the full-disconnect clear alone leaves the previous incarnation's
// capability enforced against the new one — the same peer-downgrade blackhole
// C01a exists to prevent, reached through a different edge.
func TestPeerHeartbeatAckEverClearedOnSupersession_5718(t *testing.T) {
	ss := newAckTestSync(t)

	// Peer incarnation #1: connected on fabric 0 and proves ack support.
	connA := pipeConn(t)
	installAckTestConn(t, ss, 0, connA)
	ss.handleMessage(connA, syncMsgHeartbeatAck, nil)
	if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("setup: incarnation #1 must latch the capability")
	}

	// Peer incarnation #2 (a downgraded build) dials in on the same fabric
	// while our half-open connection to incarnation #1 is still registered.
	connB := pipeConn(t)
	ss.installConn(0, connB)

	// handleDisconnect for the superseded connection runs afterwards, from the
	// old receiveLoop's defer. It must not be what the fix depends on: the
	// slot now holds connB, so this call takes the stale-disconnect branch and
	// changes nothing.
	ss.handleDisconnect(connA)

	if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("a connection SUPERSEDING a live one in its fabric slot starts a new " +
			"peer incarnation and must clear peerHeartbeatAckEver. handleDisconnect " +
			"cannot do it: by the time the superseded connection's receiveLoop " +
			"reports the drop, the slot already holds the new conn, so it returns " +
			"down the stale-disconnect branch. Leaving the latch armed enforces " +
			"the OLD incarnation's capability against a peer that may never ack")
	}

	// The new incarnation must therefore read healthy despite being silent.
	ss.lastPeerRxMono.Store(MonotonicNanos() - int64(time.Second))
	if !ss.PeerHealthy() {
		t.Fatal("after a supersession the new peer incarnation must read HEALTHY " +
			"until it proves ack support itself (probe-then-enforce)")
	}
}

// TestPeerHeartbeatAckTwoFabricStaleSurvivorCannotRearm_5718 is the #5718 fold
// F1b fail-on-revert: the TWO-FABRIC incarnation edge.
//
// Clearing the flag on supersession is not enough once there are two fabric
// slots. A peer that reboots hard sends no FIN/RST, so BOTH of its connections
// stay ESTABLISHED on our side. Its new process dials in and supersedes ONE
// slot; the OTHER slot still holds the dead incarnation's connection. A
// membership-only acceptance test — `s.conn0 == conn || s.conn1 == conn` —
// asks whether the connection sits in EITHER slot, so an in-flight ack off
// that survivor is accepted and RE-ARMS the capability the supersession just
// cleared. That is the previous incarnation enforced against the current one:
// the same defect C01a exists to prevent, one level up.
//
// The per-slot incarnation stamp is what closes it: the survivor keeps the old
// stamp, so it is no longer current. Since fold r4b the survivor is also
// EVICTED rather than left installed, so on the live path this test now drives
// a state production tears down in the same critical section. It is kept
// because the stamp comparison is still what rejects an ack already in flight
// when the eviction runs, and because it is the belt if eviction is ever
// narrowed.
//
// Both fabric orderings run. The install and acceptance paths each branch on
// the fabric index, so a fixture that only ever supersedes slot 0 leaves the
// slot-1 arm of both switches unexercised — a guard scoped narrower than the
// claim it makes.
func TestPeerHeartbeatAckTwoFabricStaleSurvivorCannotRearm_5718(t *testing.T) {
	for _, tc := range []struct{ superseded, survivor int }{{0, 1}, {1, 0}} {
		t.Run(fabricPairName(tc.superseded, tc.survivor), func(t *testing.T) {
			ss := newAckTestSync(t)

			// Peer incarnation A holds BOTH fabric slots and proves ack support.
			aSup, aSurv := pipeConn(t), pipeConn(t)
			ss.installConn(tc.superseded, aSup)
			ss.installConn(tc.survivor, aSurv)
			ss.handleMessage(aSup, syncMsgHeartbeatAck, nil)
			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatal("setup: incarnation A must latch the capability")
			}

			// A's node reboots. Neither socket sees a FIN/RST, so BOTH stay
			// installed. A's replacement dials one fabric and supersedes only
			// that slot.
			b := pipeConn(t)
			ss.installConn(tc.superseded, b)
			if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatal("setup: the supersession must clear the capability")
			}

			// aSurv's socket is still ESTABLISHED and its receiveLoop may already
			// hold an ack frame read before the reboot. That frame must not speak
			// for the incarnation that replaced it — whether acceptance rejects it
			// on the slot's incarnation stamp (fold F1b) or because the r4b
			// eviction removed it from the registry outright, the observable is
			// the same: the latch stays clear.
			ss.handleMessage(aSurv, syncMsgHeartbeatAck, nil)
			if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatalf("an ack from the PREVIOUS incarnation's fabric-%d connection re-armed "+
					"the capability microseconds after the supersession cleared it — the old "+
					"incarnation enforced against the new one. A membership-only acceptance "+
					"test (`s.conn0 == conn || s.conn1 == conn`) accepts that frame for as "+
					"long as the connection sits in a slot", tc.survivor)
			}

			// The current incarnation's own connection still arms it.
			ss.handleMessage(b, syncMsgHeartbeatAck, nil)
			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatal("the CURRENT incarnation's connection must still be able to latch the capability")
			}
		})
	}
}

// TestPeerHeartbeatAckReclaimingStaleSlotKeepsCapability_5718 is the scope
// control for the stamp: advancing the incarnation must be driven by replacing
// a CURRENT connection, not by any supersession at all.
//
// After the new incarnation takes one slot, it eventually dials the other
// fabric too. That is the SAME peer taking its second link, not a third
// incarnation.
//
// #5718 fold r4b changes HOW that slot is free, not what must happen: the
// eviction removed the dead incarnation's leftover connection when the
// incarnation advanced, so the reclaim now installs into an EMPTY slot rather
// than superseding a stale one. The requirement is unchanged.
// Advancing on it would clear a capability this peer legitimately proved and —
// worse — strand its first connection at a now-stale stamp, so that connection
// could never re-arm the capability again: a permanent disarm of both
// enforcement paths.
//
// Both orderings run for the same reason as above: `supersededCurrent` is
// computed in a per-fabric switch, so a single-fabric fixture leaves the other
// arm free to be mutated to an unconditional true.
func TestPeerHeartbeatAckReclaimingStaleSlotKeepsCapability_5718(t *testing.T) {
	for _, tc := range []struct{ taken, reclaimed int }{{0, 1}, {1, 0}} {
		t.Run(fabricPairName(tc.taken, tc.reclaimed), func(t *testing.T) {
			ss := newAckTestSync(t)

			aTaken, aReclaimed := pipeConn(t), pipeConn(t)
			ss.installConn(tc.taken, aTaken)
			ss.installConn(tc.reclaimed, aReclaimed)
			ss.handleMessage(aTaken, syncMsgHeartbeatAck, nil)

			// Incarnation B takes one slot and proves ack support for itself.
			bTaken := pipeConn(t)
			ss.installConn(tc.taken, bTaken)
			ss.handleMessage(bTaken, syncMsgHeartbeatAck, nil)
			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatal("setup: incarnation B must latch the capability")
			}

			// B now takes the other fabric. A's connection there was evicted
			// when the incarnation advanced (fold r4b), so this lands in an
			// empty slot; before that it superseded a stale one.
			if got := ss.connInSlot(tc.reclaimed); got != nil {
				t.Fatalf("setup: fabric %d must be free of the retired incarnation's "+
					"connection before B reclaims it", tc.reclaimed)
			}
			bReclaimed := pipeConn(t)
			ss.installConn(tc.reclaimed, bReclaimed)

			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatalf("reclaiming fabric %d is the current peer taking its second fabric "+
					"link, not a new incarnation. Clearing here discards a capability this "+
					"peer proved", tc.reclaimed)
			}

			// And B's original connection must still count as current — the
			// decisive half. If the reclaim had advanced the incarnation,
			// bTaken would be stranded at the old stamp and could never re-arm.
			ss.peerIncarnationState().peerHeartbeatAckEver.Store(false)
			ss.handleMessage(bTaken, syncMsgHeartbeatAck, nil)
			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatalf("the fabric-%d connection that proved the capability was stranded at "+
					"a stale incarnation stamp by the reclaim of fabric %d, so it can never "+
					"re-arm — a permanent disarm of the missed-heartbeat teardown and "+
					"PeerHealthy's silence window for the whole life of that connection",
					tc.taken, tc.reclaimed)
			}
		})
	}
}

// TestPeerHeartbeatAckStaleConnCannotRearm_5718 pins the ordering half of the
// fold F1 fix.
//
// installConn's clear is not sufficient on its own: a heartbeat-ack frame that
// was already read off the superseded connection is still in flight in that
// connection's receiveLoop. If handleMessage latched unconditionally, that
// stale frame would re-arm the capability for the incoming incarnation
// immediately after the clear — restoring exactly the state the clear removed.
//
// The membership test and the store therefore both run under s.mu in
// noteHeartbeatAck, atomic with installConn's clear, and an ack from a
// connection that is no longer installed is ignored.
func TestPeerHeartbeatAckStaleConnCannotRearm_5718(t *testing.T) {
	ss := newAckTestSync(t)

	connA := pipeConn(t)
	installAckTestConn(t, ss, 0, connA)

	connB := pipeConn(t)
	ss.installConn(0, connB)
	if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("setup: the supersession must leave the capability cleared")
	}

	// The superseded connection's in-flight ack arrives after the swap.
	ss.handleMessage(connA, syncMsgHeartbeatAck, nil)
	if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("an ack from a SUPERSEDED connection must not latch the capability: " +
			"it speaks for the previous peer incarnation, and honouring it " +
			"re-arms the enforcement paths against the new one")
	}

	// The current incarnation's own ack still latches — the gate rejects stale
	// connections, not acks in general.
	ss.handleMessage(connB, syncMsgHeartbeatAck, nil)
	if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("an ack from the CURRENTLY installed connection must latch the capability")
	}
}

// TestPeerHeartbeatAckStoreIsAtomicWithSupersession_5718 binds the ATOMICITY
// that noteHeartbeatAck's doc claims (#5718 fold r3).
//
// Every other test here calls installConn and handleMessage in sequence, so
// none of them ever opens the window the lock exists to close. That makes
// "the check and the store both run under s.mu, so they are atomic" a comment
// no test can contradict: an implementation that checks under the lock,
// RELEASES it, and only then stores passes all of them, while allowing
//
//	ack: check passes (conn is current)
//	     ...lock released...
//	                          install: supersede the other slot, clear the latch
//	ack: store(true)          <-- resurrects a capability that was just cleared
//
// which is the very fail-open the incarnation stamp was added to prevent.
//
// The midpoint hook widens the window to something observable. The competing
// installConn is started from INSIDE it and then waited for:
//
//   - correct: the competitor blocks on s.mu until noteHeartbeatAck returns,
//     so the wait times out, the store lands first, and the supersession's
//     clear lands after it — final state CLEARED.
//   - released-early: the competitor runs to completion inside the window and
//     clears, then the stale store lands on top — final state LATCHED.
//
// The assertion is on the final state, so it is deterministic in both shapes;
// only the (generous) wait is timing-based, and it is the correct
// implementation that relies on it EXPIRING, never on it firing.
func TestPeerHeartbeatAckStoreIsAtomicWithSupersession_5718(t *testing.T) {
	ss := newAckTestSync(t)

	// Peer incarnation A holds both fabric slots.
	a0, a1 := pipeConn(t), pipeConn(t)
	ss.installConn(0, a0)
	ss.installConn(1, a1)

	// The competing supersession: incarnation B takes fabric 1, which advances
	// the incarnation and clears the capability.
	b1 := pipeConn(t)
	supersedeDone := make(chan struct{})

	var once sync.Once
	hook := func() {
		once.Do(func() {
			started := make(chan struct{})
			go func() {
				close(started)
				ss.installConn(1, b1)
				close(supersedeDone)
			}()
			<-started
			// Give the supersession every chance to complete WHILE we are
			// between the check and the store. Under the correct
			// implementation it cannot: it is blocked on s.mu, which this
			// goroutine holds.
			select {
			case <-supersedeDone:
			case <-time.After(2 * time.Second):
			}
		})
	}
	noteHeartbeatAckMidpointHook.Store(&hook)
	t.Cleanup(func() { noteHeartbeatAckMidpointHook.Store(nil) })

	// a0 is current, so this ack passes the check and reaches the window.
	ss.handleMessage(a0, syncMsgHeartbeatAck, nil)

	// Let the competitor finish now that the lock is free.
	select {
	case <-supersedeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the competing installConn never completed")
	}

	if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("a supersession interleaved between the incarnation check and the " +
			"capability store, so the ack resurrected a capability the supersession " +
			"had already cleared. The check and the store must BOTH happen under the " +
			"same s.mu hold — releasing the lock between them reopens exactly the " +
			"stale-incarnation fail-open the per-slot stamp closes")
	}

	// The supersession really did happen, so the assertion above is about
	// ordering and not about a supersession that silently did not run.
	if got := ss.connInSlot(1); got != b1 {
		t.Fatal("setup: the competing installConn must have taken fabric 1")
	}
}

// TestPeerHeartbeatAckNotLatchedBeforeInstall_5718 covers the third writer
// path: handleNewConnection processes a handshake-pending frame BEFORE the
// connection is installed into a fabric slot.
//
// An ack can never legitimately be a peer's first frame — we only send
// syncMsgHeartbeat after a read deadline elapses on an established connection
// — so an unsolicited ack arriving before the connection is wired in must not
// arm an enforcement path on its behalf.
func TestPeerHeartbeatAckNotLatchedBeforeInstall_5718(t *testing.T) {
	ss := newAckTestSync(t)

	pending := pipeConn(t)
	ss.handleMessage(pending, syncMsgHeartbeatAck, nil)
	if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("an ack from a connection that is not installed in a fabric slot " +
			"must not latch the capability")
	}

	// nil is the unit-test / no-connection shape and must be inert too.
	ss.handleMessage(nil, syncMsgHeartbeatAck, nil)
	if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
		t.Fatal("an ack with no originating connection must not latch the capability")
	}
}

// TestPeerHeartbeatAckClearedWheneverRegistryEmpties_5718 carries the PREMISE
// that lets installConn scope its clear to supersession alone.
//
// installConn deliberately does not clear on a full-disconnect -> connect edge
// (`d.wasDisconnected`), on the grounds that whenever the registry is empty the
// capability is already clear. Note the precise form: NOT "an empty registry
// always means handleDisconnect's clear ran" — the `fresh SessionSync` subtest
// below is empty having never seen a disconnect at all. The invariant is that
// an empty registry implies a CLEAR capability, reached either by
// initialization or because handleDisconnect owns the nonempty-to-empty
// transition. That is a claim about the rest of the package, not about
// installConn, and adding the
// condition back is INERT rather than wrong — which is exactly why no
// behavioural test can reject it. What can go wrong is the premise: a future
// teardown path that empties conn0/conn1 without clearing would silently make
// the narrowing incorrect, and the supersession tests above would not notice.
//
// So this pins the premise directly: every way the registry reaches empty
// leaves the capability cleared. If a new path nils a slot without clearing,
// this fails and the narrowing must be revisited.
func TestPeerHeartbeatAckClearedWheneverRegistryEmpties_5718(t *testing.T) {
	registryEmpty := func(ss *SessionSync) bool {
		ss.mu.Lock()
		defer ss.mu.Unlock()
		return ss.conn0 == nil && ss.conn1 == nil
	}

	t.Run("fresh SessionSync", func(t *testing.T) {
		ss := newAckTestSync(t)
		if !registryEmpty(ss) {
			t.Fatal("setup: a fresh SessionSync must have no connections")
		}
		if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
			t.Fatal("a fresh SessionSync must not carry the capability")
		}
	})

	t.Run("single fabric disconnects", func(t *testing.T) {
		ss := newAckTestSync(t)
		c := pipeConn(t)
		ss.installConn(0, c)
		ss.handleMessage(c, syncMsgHeartbeatAck, nil)
		if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
			t.Fatal("setup: the capability must be latched before the disconnect")
		}
		ss.handleDisconnect(c)
		if !registryEmpty(ss) {
			t.Fatal("setup: the registry must be empty after the only fabric drops")
		}
		if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
			t.Fatal("the registry emptied with the capability still latched. installConn " +
				"omits a clear on the full-disconnect edge BECAUSE reaching an empty " +
				"registry implies handleDisconnect already cleared — that premise no " +
				"longer holds, so the narrowing is now a real gap")
		}
	})

	t.Run("both fabrics disconnect in turn", func(t *testing.T) {
		ss := newAckTestSync(t)
		c0, c1 := pipeConn(t), pipeConn(t)
		ss.installConn(0, c0)
		ss.installConn(1, c1)
		ss.handleMessage(c0, syncMsgHeartbeatAck, nil)
		if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
			t.Fatal("setup: the capability must be latched before the disconnects")
		}
		// Partial first: the capability must SURVIVE (same peer process).
		ss.handleDisconnect(c0)
		if registryEmpty(ss) {
			t.Fatal("setup: fabric 1 must survive the fabric 0 disconnect")
		}
		if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
			t.Fatal("a partial disconnect must not clear the capability")
		}
		// Now the last one goes.
		ss.handleDisconnect(c1)
		if !registryEmpty(ss) {
			t.Fatal("setup: the registry must be empty once both fabrics drop")
		}
		if ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
			t.Fatal("the registry emptied via the second fabric's disconnect with the " +
				"capability still latched — installConn's omitted full-disconnect clear " +
				"relies on this never happening")
		}
	})
}

// TestOnlyHandleDisconnectEmptiesTheRegistry_5718 is the STRUCTURAL half of
// the premise above, and the part the behavioural test cannot reach.
//
// The behavioural premise test can only assert about the paths it invokes; it
// says nothing about a path added later. Removing handleDisconnect's clear is
// already caught by an older assertion, so the behavioural test adds no
// sensitivity there — its unique job is this: the narrowing in installConn is
// sound only while `handleDisconnect` is the sole function that can take the
// registry from nonempty to EMPTY. That is not the same as "only one function
// nils a slot" — since fold r4b the allowlist below carries two names — so the
// invariant a second slot-niller has to satisfy is intrinsic preservation of an
// occupied slot, which is what the eviction's keep-slot refusal supplies. A new
// teardown without that property could empty the registry without clearing the
// capability, and every behavioural test in this file would still pass.
//
// So assert the ownership directly on the package's AST.
//
// #5718 fold r4b widens the allowlist by exactly one name.
// evictStaleIncarnationConnsLocked also nils a slot — that is its job — but it
// provably cannot cause the nonempty-to-EMPTY transition, for two reasons that
// are both properties of the function itself:
//
//   - it never touches the keep slot (keepIdx), and
//   - it refuses to evict anything at all unless that keep slot is occupied.
//
// #5718 fold r6 added the second one. Before it, the exemption rested on what
// the single caller happened to do — installConn installs before it evicts —
// which is not something this allowlist can enforce. A future caller naming a
// slot it had not filled yet would have emptied the registry while BOTH guards
// stayed green: this one allowlists the function by NAME, and
// TestInstallConnNeverLeavesTheRegistryEmpty_5718 drives the existing call
// site, so a second call site is invisible to it. The refusal closes that by
// making the exemption true for callers that do not exist yet;
// TestEvictionRefusesToEmptyTheRegistry_5718 binds it directly, and
// TestInstallConnNeverLeavesTheRegistryEmpty_5718 still covers the live path.
func TestOnlyHandleDisconnectEmptiesTheRegistry_5718(t *testing.T) {
	allowed := map[string]bool{
		"handleDisconnect":                 true,
		"evictStaleIncarnationConnsLocked": true,
	}
	fset := token.NewFileSet()
	pkgFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	type site struct{ fn, pos string }
	var sites []site
	for _, path := range pkgFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				// #18521 review round 2: production slot writes go through
				// setConnSlotLocked (TestConnSlotWritesGoThroughTheSetter18525),
				// so a slot is nilled by `s.setConnSlotLocked(idx, nil)`. Count
				// that call as the site, attributed to its caller, alongside
				// any direct `s.connN = nil` the setter census would also reject.
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "setConnSlotLocked" &&
						len(call.Args) == 2 {
						if id, ok := call.Args[1].(*ast.Ident); ok && id.Name == "nil" {
							sites = append(sites, site{fn: fn.Name.Name, pos: fset.Position(call.Pos()).String()})
						}
					}
					return true
				}
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, lhs := range as.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || (sel.Sel.Name != "conn0" && sel.Sel.Name != "conn1") {
						continue
					}
					if i >= len(as.Rhs) {
						continue
					}
					if id, ok := as.Rhs[i].(*ast.Ident); !ok || id.Name != "nil" {
						continue
					}
					sites = append(sites, site{fn: fn.Name.Name, pos: fset.Position(as.Pos()).String()})
				}
				return true
			})
		}
	}

	if len(sites) == 0 {
		t.Fatal("no `s.connN = nil` / `setConnSlotLocked(idx, nil)` site found in package cluster — if the fabric registry " +
			"was restructured, re-point this guard rather than deleting it")
	}
	for _, s := range sites {
		if !allowed[s.fn] {
			t.Fatalf("%s nils a fabric connection slot at %s. installConn deliberately does "+
				"NOT clear peerHeartbeatAckEver on the full-disconnect edge, because an "+
				"empty registry is supposed to imply a CLEAR capability — by initialization, "+
				"or because handleDisconnect owns the nonempty-to-empty transition. A second "+
				"function that can perform that transition breaks the premise: "+
				"the registry can then go empty with the capability still latched, and the "+
				"previous incarnation is enforced against the next peer. Either clear the "+
				"capability there too, or restore the clear in installConn (#5718 fold r3). "+
				"evictStaleIncarnationConnsLocked is exempt ONLY because it cannot empty "+
				"the registry on its own terms — it skips the keep slot AND refuses to "+
				"evict unless that slot is occupied, so the guarantee does not depend on "+
				"which caller invoked it. A new site has no such argument until one is "+
				"written INTO the function and tested",
				s.fn, s.pos)
		}
	}
}

// TestPeerHeartbeatAckEverSurvivesPartialDisconnect_5718 is the scope control
// for the full-disconnect clear: the reset must be scoped to the PEER
// INCARNATION, not to any connection event.
//
// A single fabric link flapping while the other stays up is the SAME peer
// process. Clearing the capability there would silently disarm the
// missed-heartbeat teardown and the silence window on every fabric-link blip —
// a fail-open that a reset-on-every-disconnect implementation would exhibit
// and the tests above alone would not catch.
// #5718 fold r4b: both directions run. handleDisconnect classifies the dropped
// connection in a per-slot switch, so a fixture that only ever drops fabric 0
// leaves the fabric-1 arm free — a branch-local regression there would pass.
func TestPeerHeartbeatAckEverSurvivesPartialDisconnect_5718(t *testing.T) {
	for _, tc := range []struct{ dropped, survivor int }{{0, 1}, {1, 0}} {
		t.Run(fabricPairName(tc.dropped, tc.survivor), func(t *testing.T) {
			ss := newAckTestSync(t)

			dropped, survivor := pipeConn(t), pipeConn(t)

			// Both fabric links up to one peer incarnation, which proves ack
			// support.
			ss.installConn(tc.dropped, dropped)
			ss.installConn(tc.survivor, survivor)
			ss.handleMessage(dropped, syncMsgHeartbeatAck, nil)
			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatal("setup: capability must be latched before the partial disconnect")
			}

			// One fabric drops; the other survives. Same peer process, so the
			// capability it proved is still true.
			ss.handleDisconnect(dropped)

			if got := ss.connInSlot(tc.survivor); got != survivor {
				t.Fatalf("setup: fabric %d must survive a fabric %d disconnect",
					tc.survivor, tc.dropped)
			}
			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatalf("a PARTIAL disconnect (fabric %d down, fabric %d still up) "+
					"must NOT clear peerHeartbeatAckEver: the peer process never "+
					"changed. Clearing on any disconnect disarms the missed-heartbeat "+
					"teardown and PeerHealthy's silence window on every link blip",
					tc.dropped, tc.survivor)
			}
		})
	}
}

// TestPeerHeartbeatAckEverSurvivesSecondFabricComingUp_5718 is the scope
// control for the SUPERSESSION clear.
//
// A second fabric link coming up beside a surviving one is not a supersession:
// its slot was empty, so no live connection was replaced, and it is the same
// peer process that is already acking on the other link. Clearing there would
// disarm both enforcement paths every time a flapped fabric link came back —
// the mirror image of the partial-disconnect fail-open above.
// #5718 fold r4b: both directions run. installConn's supersession
// classification is a per-fabric switch, so a fixture that only ever adds
// fabric 1 leaves the fabric-0 arm free to be mutated into an unconditional
// clear.
func TestPeerHeartbeatAckEverSurvivesSecondFabricComingUp_5718(t *testing.T) {
	for _, tc := range []struct{ first, second int }{{0, 1}, {1, 0}} {
		t.Run(fabricPairName(tc.first, tc.second), func(t *testing.T) {
			ss := newAckTestSync(t)

			firstConn := pipeConn(t)
			ss.installConn(tc.first, firstConn)
			ss.handleMessage(firstConn, syncMsgHeartbeatAck, nil)
			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatalf("setup: capability must be latched before fabric %d comes up", tc.second)
			}

			// The second fabric comes up into an EMPTY slot beside the live one.
			secondConn := pipeConn(t)
			ss.installConn(tc.second, secondConn)

			if !ss.peerIncarnationState().peerHeartbeatAckEver.Load() {
				t.Fatalf("fabric %d coming up into an EMPTY slot beside the live fabric %d "+
					"must NOT clear peerHeartbeatAckEver: nothing was superseded and the "+
					"peer process never changed. Clearing on every install disarms the "+
					"missed-heartbeat teardown and PeerHealthy's silence window whenever "+
					"a flapped fabric link returns", tc.second, tc.first)
			}
		})
	}
}

// TestConnIsCurrentIncarnationRejectsAStaleStamp_5718 pins the ACK-acceptance
// belt directly, on a state the production install path can no longer produce.
//
// Since fold r4b evicts a retired incarnation's connections when the
// incarnation advances, "installed in a slot but stamped by a retired
// incarnation" is unreachable through installConn — which is why no behavioural
// test can bind the stamp comparison in connIsCurrentIncarnationLocked any
// more. That comparison is a fail-closed belt for an install path added later
// that forgets to evict, and this test hand-builds the state it defends against
// so the belt is not silently weakened to a membership test. It is labelled a
// belt deliberately: it proves the guard fires, not that the state occurs in
// production today.
func TestConnIsCurrentIncarnationRejectsAStaleStamp_5718(t *testing.T) {
	for _, fabricIdx := range []int{0, 1} {
		t.Run(fmt.Sprintf("fabric%d", fabricIdx), func(t *testing.T) {
			ss := newAckTestSync(t)
			conn := pipeConn(t)

			ss.mu.Lock()
			ss.peerIncarnation = 7
			if fabricIdx == 0 {
				ss.conn0, ss.conn0Gen = conn, 6
			} else {
				ss.conn1, ss.conn1Gen = conn, 6
			}
			current := ss.connIsCurrentIncarnationLocked(conn)
			ss.mu.Unlock()

			if current {
				t.Fatalf("a connection installed in fabric slot %d with incarnation stamp 6 was "+
					"accepted as current while the peer incarnation is 7. The acceptance test "+
					"has degenerated to slot membership, so a retired incarnation's in-flight "+
					"ack would re-arm the capability for its successor", fabricIdx)
			}

			// Direction control: the same slot at the CURRENT stamp is accepted,
			// so the assertion above is not satisfied by a helper that rejects
			// everything.
			ss.mu.Lock()
			if fabricIdx == 0 {
				ss.conn0Gen = 7
			} else {
				ss.conn1Gen = 7
			}
			current = ss.connIsCurrentIncarnationLocked(conn)
			ss.mu.Unlock()
			if !current {
				t.Fatalf("a connection installed in fabric slot %d at the CURRENT incarnation "+
					"stamp must be accepted", fabricIdx)
			}
		})
	}
}
