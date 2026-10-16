package cluster

import (
	"errors"
	"testing"
	"time"
)

// #14158: a heartbeat delivered during the confirmed-fence wait must not be
// clobbered. The fence confirm callback runs with m.mu released; a live peer
// heartbeat landing there sets peerAlive and rebuilds peer groups, and the
// fence then ERRORS (fabric sync down while the control link lives), so the
// peer was never told to relinquish. awaitPeerFenceLocked must not re-assert
// peerAlive=false over that heartbeat, and handlePeerTimeout must not proceed
// to electSingleNode — otherwise the local node promotes while the peer (never
// fenced) remains primary: transient dual-active.
func TestHandlePeerTimeoutHeartbeatDuringFailedFenceDoesNotPromote14158(t *testing.T) {
	m := confirmFenceManager(t)

	// The peer reports itself PRIMARY for RG0. If the post-fence flow elects
	// as if the peer were gone, this node promotes alongside it.
	peerPrimary := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)},
		},
	}

	called := false
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		called = true
		// Inside the window: m.mu is released, so a heartbeat on the receive
		// goroutine can land. Deliver it through the real handler.
		m.handlePeerHeartbeat(peerPrimary)
		// The fence itself failed: the peer never received/acked it.
		return FenceAck{}, errors.New("peer not connected")
	})

	m.handlePeerTimeout()

	if !called {
		t.Fatal("the confirm function was never called under disable-rg-confirmed")
	}
	if !m.PeerAlive() {
		t.Fatal("peerAlive was clobbered by awaitPeerFenceLocked after a heartbeat " +
			"arrived during the fence wait (#14158)")
	}
	if got := rgState(t, m, 0); got == StatePrimary {
		t.Fatalf("local node promoted to %v after a FAILED fence while the peer "+
			"heartbeat during the wait reported the peer PRIMARY — dual-active (#14158)", got)
	}
	if got := len(m.PeerGroupStates()); got != 1 {
		t.Fatalf("peer groups = %d, want 1 — the heartbeat that arrived during the "+
			"fence wait must survive the failed fence", got)
	}
}

// Control: when NO heartbeat arrives during the fence wait, a failed fence must
// still fail open and promote (existing #7147 liveness). This pins that the
// #14158 abort is conditioned on the heartbeat, not on the fence error alone.
func TestHandlePeerTimeoutNoHeartbeatDuringFailedFenceStillPromotes14158(t *testing.T) {
	m := confirmFenceManager(t)
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		return FenceAck{}, errors.New("peer not connected")
	})
	m.handlePeerTimeout()
	if m.PeerAlive() {
		t.Fatal("peer marked alive without any heartbeat during the fence wait")
	}
	if got := rgState(t, m, 0); got != StatePrimary {
		t.Fatalf("node is %v after a failed fence with no intervening heartbeat, "+
			"want primary — fail-open takeover must be preserved", got)
	}
}
