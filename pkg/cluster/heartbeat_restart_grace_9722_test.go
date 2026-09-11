package cluster

import (
	"testing"
	"time"
)

// #9722: every config apply that rebinds the management VRF restarts the
// heartbeat. The replacement receiver used to arm the 30s COLD-BOOT grace, and
// checkTimeout's seen-then-lost arm returns inside that grace before it looks at
// staleness. So a peer that died within 30s after a commit was declared lost up
// to 30s late. A replacement for a receiver that had seen the peer now holds for
// heartbeatRestartGrace only; a cold start keeps the 30s floor.
//
// FAIL-ON-REVERT: make seenThenLostGrace return heartbeatStartupGrace
// unconditionally and the first cell goes red, with the peer still alive
// heartbeatRestartGrace+500ms after the restart.

const staleAge9722 = 10 * time.Second // far past threshold*interval

// seenPeerManager9722 is a manager that has seen its peer, with a fresh
// receiver installed so handlePeerTimeout's freshness re-check reads it. No
// sockets and no goroutines: checkTimeout is driven directly.
func seenPeerManager9722(t *testing.T) (*Manager, *heartbeatReceiver) {
	t.Helper()
	m := NewManager(0, 1)
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	m.hbReceiver = r
	m.mu.Unlock()
	return m, r
}

func TestRestartedReceiverDeclaresAStalePeerLostAfterTheRestartGrace_9722(t *testing.T) {
	sinceRestart := heartbeatRestartGrace + 500*time.Millisecond
	if sinceRestart >= heartbeatStartupGrace {
		t.Fatalf("fixture: %v after the restart must still be inside the %v cold-boot grace", sinceRestart, heartbeatStartupGrace)
	}
	m, r := seenPeerManager9722(t)
	r.armRestart(MonotonicNanos() - staleAge9722.Nanoseconds())
	r.startedAt = time.Now().Add(-sinceRestart)

	r.checkTimeout()
	if m.PeerAlive() {
		t.Errorf("peer still ALIVE %v after a heartbeat restart whose last heartbeat is %v old: the "+
			"restarted receiver is holding the %v cold-boot grace, so a peer that died just after a "+
			"commit is declared lost up to that late", sinceRestart, staleAge9722, heartbeatStartupGrace)
	}
}

func TestRestartedReceiverHoldsInsideTheRestartGraceAndForAResumedPeer_9722(t *testing.T) {
	m, r := seenPeerManager9722(t)
	r.armRestart(MonotonicNanos() - staleAge9722.Nanoseconds())
	r.startedAt = time.Now().Add(-time.Second) // inside the restart grace

	r.checkTimeout()
	if !m.PeerAlive() {
		t.Fatalf("peer declared lost 1s after a heartbeat restart; the %v restart grace must hold", heartbeatRestartGrace)
	}

	// The peer's heartbeats resume inside the grace. Past the grace it is fresh, not lost.
	r.lastSeen.Store(MonotonicNanos())
	r.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))
	r.checkTimeout()
	if !m.PeerAlive() {
		t.Error("peer declared lost after its heartbeats resumed inside the restart grace")
	}
}

func TestColdStartReceiverKeepsTheStartupGrace_9722(t *testing.T) {
	m, r := seenPeerManager9722(t)
	// Not armed: a cold start. The same stale heartbeat, the same time since start.
	r.lastSeen.Store(MonotonicNanos() - staleAge9722.Nanoseconds())
	r.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))

	r.checkTimeout()
	if !m.PeerAlive() {
		t.Errorf("a cold-start receiver declared the peer lost %v after start, inside the %v cold-boot grace (#4386)",
			heartbeatRestartGrace+500*time.Millisecond, heartbeatStartupGrace)
	}

	// armRestart(0) is a cold start too: the replaced receiver never saw the peer.
	r2 := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r2.armRestart(0)
	if r2.seenGrace != 0 || r2.lastSeen.Load() != 0 {
		t.Errorf("armRestart(0) armed the receiver (seenGrace=%v lastSeen=%d); a restart whose "+
			"predecessor never saw the peer must stay a cold start", r2.seenGrace, r2.lastSeen.Load())
	}
}

// Through the real RestartHeartbeat: the replacement is armed before it
// starts, and only when the replaced receiver had seen the peer.
func TestRestartHeartbeatArmsTheReplacementOnlyWhenThePeerWasSeen_9722(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	defer m.StopHeartbeat()

	// Never seen: the replacement is a cold start.
	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat returned false while running")
	}
	m.mu.RLock()
	r1 := m.hbReceiver
	m.mu.RUnlock()
	if r1 == nil {
		t.Fatal("no receiver after RestartHeartbeat")
	}
	if r1.seenGrace != 0 {
		t.Errorf("replacement for a receiver that never saw the peer has seenGrace=%v, want 0 (cold start)", r1.seenGrace)
	}

	// Seen: the replacement carries the seed and the restart grace.
	seed := MonotonicNanos() - staleAge9722.Nanoseconds()
	r1.lastSeen.Store(seed)
	if !m.RestartHeartbeat() {
		t.Fatal("second RestartHeartbeat returned false while running")
	}
	m.mu.RLock()
	r2 := m.hbReceiver
	m.mu.RUnlock()
	if r2 == nil || r2 == r1 {
		t.Fatalf("receiver not replaced by the second RestartHeartbeat (r2=%p r1=%p)", r2, r1)
	}
	if r2.seenGrace != heartbeatRestartGrace {
		t.Errorf("replacement for a receiver that had seen the peer has seenGrace=%v, want %v", r2.seenGrace, heartbeatRestartGrace)
	}
	if got := r2.lastSeen.Load(); got != seed {
		t.Errorf("replacement lastSeen = %d, want the pre-restart %d", got, seed)
	}
}
