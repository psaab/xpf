package cluster

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestHandlePeerTimeout_FreshHeartbeatDuringGuardWindow exercises the #2080
// bug directly: a slow guard window during which a fresh peer heartbeat
// arrives. The post-guard re-check must consult heartbeat STALENESS, not just
// peerAlive — a fresh heartbeat that landed during the guard must abort the
// peer-lost transition.
//
// This test FAILS against the pre-fix code (which only re-checked peerAlive,
// essentially always true) and PASSES with the staleness re-check.
func TestHandlePeerTimeout_FreshHeartbeatDuringGuardWindow(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = 1
	m.peerGroups = map[int]PeerGroupState{
		0: {GroupID: 0, Priority: 100, Weight: 255, State: StatePrimary},
	}
	// Model the receiver's freshness via the seam. heartbeatArrived flips to
	// true while the guard runs, simulating a heartbeat landing on the read
	// path during the (slow) guard window.
	var heartbeatArrived atomic.Bool
	m.peerHeartbeatFreshFn = func() bool { return heartbeatArrived.Load() }
	m.mu.Unlock()

	guardCalled := false
	// The guard does NOT itself suppress (returns false); it only consumes
	// wall time, during which a fresh heartbeat arrives. This isolates the
	// post-guard staleness re-check as the only thing that can save the peer.
	m.SetPeerTimeoutGuard(func() (bool, string) {
		guardCalled = true
		heartbeatArrived.Store(true) // peer heartbeat lands during the guard
		return false, ""
	})

	m.handlePeerTimeout()

	if !guardCalled {
		t.Fatal("guard was not invoked")
	}
	if !m.PeerAlive() {
		t.Fatal("peer marked lost despite a fresh heartbeat arriving during the guard window (#2080)")
	}
	if got := len(m.PeerGroupStates()); got != 1 {
		t.Fatalf("peer groups = %d, want 1 — peer state must be preserved when the heartbeat is fresh", got)
	}
}

// TestHandlePeerTimeout_StaleAfterGuardStillMarksLost is the negative control:
// when NO fresh heartbeat arrives during the guard window (the heartbeat is
// genuinely stale), the peer must still be marked lost. This guards against an
// over-eager abort that would break real failover.
func TestHandlePeerTimeout_StaleAfterGuardStillMarksLost(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = 1
	m.peerGroups = map[int]PeerGroupState{
		0: {GroupID: 0, Priority: 100, Weight: 255, State: StatePrimary},
	}
	// Heartbeat stays stale throughout — no heartbeat arrives during the guard.
	m.peerHeartbeatFreshFn = func() bool { return false }
	m.mu.Unlock()

	guardCalled := false
	m.SetPeerTimeoutGuard(func() (bool, string) {
		guardCalled = true
		return false, "" // do not suppress
	})

	m.handlePeerTimeout()

	if !guardCalled {
		t.Fatal("guard was not invoked")
	}
	if m.PeerAlive() {
		t.Fatal("peer should be marked lost when the heartbeat is genuinely stale after the guard")
	}
	if got := len(m.PeerGroupStates()); got != 0 {
		t.Fatalf("peer groups = %d, want 0 — peer state must be cleared on a real peer loss", got)
	}
}

// TestHandlePeerTimeout_NoReceiverNoSeamStillMarksLost pins the default
// behavior: with no receiver wired and no seam set, peerHeartbeatFreshLocked
// reports not-fresh, so the peer-lost transition proceeds exactly as it did
// before the re-check existed. This protects the many existing callers that
// drive handlePeerTimeout without a real heartbeat receiver.
func TestHandlePeerTimeout_NoReceiverNoSeamStillMarksLost(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200, 1: 100}),
	)
	m.UpdateConfig(cfg)

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerGroups = map[int]PeerGroupState{
		0: {GroupID: 0, Priority: 100, Weight: 255, State: StatePrimary},
	}
	m.mu.Unlock()

	// No guard, no seam, no receiver.
	m.handlePeerTimeout()

	if m.PeerAlive() {
		t.Fatal("peer should be marked lost with no receiver/seam (default fall-through)")
	}
}

// TestPeerHeartbeatFresh_ReceiverBacked exercises the real receiver-backed
// freshness check (the production path that peerHeartbeatFreshLocked defers to
// when no seam is set), so the test seam used above is not the only thing
// validated.
func TestPeerHeartbeatFresh_ReceiverBacked(t *testing.T) {
	r := &heartbeatReceiver{
		threshold: DefaultHeartbeatThreshold,
		interval:  DefaultHeartbeatInterval,
	}

	// Never seen → not fresh.
	if r.peerHeartbeatFresh() {
		t.Fatal("receiver with lastSeen==0 must report not-fresh")
	}

	// A heartbeat that just landed → fresh.
	r.lastSeen.Store(MonotonicNanos())
	if !r.peerHeartbeatFresh() {
		t.Fatal("receiver with a just-stored lastSeen must report fresh")
	}

	// A heartbeat older than the timeout window → stale.
	timeout := time.Duration(r.threshold) * r.interval
	r.lastSeen.Store(MonotonicNanos() - (2 * timeout).Nanoseconds())
	if r.peerHeartbeatFresh() {
		t.Fatal("receiver with a lastSeen older than the timeout must report stale")
	}
}

// TestPeerHeartbeatFreshLocked_ReceiverWiring confirms peerHeartbeatFreshLocked
// defers to the live receiver when no seam is set — closing the seam-vs-real
// gap end to end (handlePeerTimeout → Manager helper → receiver).
func TestPeerHeartbeatFreshLocked_ReceiverWiring(t *testing.T) {
	m := NewManager(0, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	// No receiver, no seam → not fresh.
	if m.peerHeartbeatFreshLocked() {
		t.Fatal("no receiver and no seam must report not-fresh")
	}

	// Wire a receiver with a fresh heartbeat.
	m.hbReceiver = &heartbeatReceiver{
		threshold: DefaultHeartbeatThreshold,
		interval:  DefaultHeartbeatInterval,
	}
	m.hbReceiver.lastSeen.Store(MonotonicNanos())
	if !m.peerHeartbeatFreshLocked() {
		t.Fatal("receiver with a fresh heartbeat must report fresh through peerHeartbeatFreshLocked")
	}

	// Seam takes precedence over the receiver.
	m.peerHeartbeatFreshFn = func() bool { return false }
	if m.peerHeartbeatFreshLocked() {
		t.Fatal("seam must take precedence over the receiver")
	}
}

// A heartbeat can be admitted after the daemon guard's stamp clear but before
// that guard finishes storing its first suppression timestamp. The timeout
// path must re-check freshness even when the guard suppresses, then clear that
// late stamp before it returns.
func TestHandlePeerTimeout_SuppressedGuardClearsLateHeartbeatStamp12165(t *testing.T) {
	m := NewManager(0, 1)
	var heartbeatFresh atomic.Bool
	var suppressionStart atomic.Int64

	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerHeartbeatFreshFn = heartbeatFresh.Load
	m.mu.Unlock()
	m.SetPeerHeartbeatRecoveredFunc(func() {
		suppressionStart.Store(0)
	})

	guardStarted := make(chan struct{})
	releaseGuard := make(chan struct{})
	m.SetPeerTimeoutGuard(func() (bool, string) {
		close(guardStarted)
		<-releaseGuard
		// Model the daemon guard storing its first stamp after heartbeat
		// admission cleared it.
		suppressionStart.Store(1)
		return true, "recent session-sync traffic"
	})

	done := make(chan struct{})
	go func() {
		m.handlePeerTimeout()
		close(done)
	}()
	<-guardStarted

	// The receiver advances lastSeen before dispatching the packet to the
	// Manager, so expose freshness and admit the heartbeat while the guard is
	// blocked outside m.mu.
	heartbeatFresh.Store(true)
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 1})
	close(releaseGuard)
	<-done

	if got := suppressionStart.Load(); got != 0 {
		t.Fatalf("suppression stamp after a fresh heartbeat during a suppressing guard = %d, want cleared", got)
	}
	if !m.PeerAlive() {
		t.Fatal("fresh heartbeat during the suppressing guard must keep the peer alive")
	}
}
