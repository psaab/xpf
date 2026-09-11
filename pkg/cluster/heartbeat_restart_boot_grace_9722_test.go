package cluster

import (
	"testing"
	"time"
)

// #9722 follow-up, found by the failover gate on merge f6433a59a.
//
// The first #9722 change held every replacement for a receiver that had seen the
// peer for only heartbeatRestartGrace. But the boot-time config apply restarts
// the heartbeat too, about a second after the cold start, while the node is
// still inside the 30s cold-boot grace that exists for exactly that disruption
// (#4386). On the loss cluster, fw1 cold-started its heartbeat at 12:57:02,
// restarted it at 12:57:03, and at 12:57:16 declared fw0 lost and took RG0, RG1
// and RG2 while fw0 held RG0 and RG1. The deploy reassert could not recover RG2.
//
// A restart now never SHORTENS a grace in progress. The replacement inherits the
// end of the grace its predecessor was inside, and a failed restart's debt
// (#9751) carries it into the retry.

func TestRestartInsideTheBootGraceKeepsTheRestOfIt_9722(t *testing.T) {
	m, r := seenPeerManager9722(t)
	// The predecessor cold-started 1s ago and had already seen the peer; the
	// boot-time apply's VRF rebind restarts it now.
	predStarted := time.Now().Add(-time.Second)
	r.armRestart(MonotonicNanos()-staleAge9722.Nanoseconds(), predStarted.Add(heartbeatStartupGrace))
	// Past the short restart grace, still inside the predecessor's boot grace.
	r.startedAt = time.Now().Add(-(heartbeatRestartGrace + 500*time.Millisecond))

	r.checkTimeout()
	if !m.PeerAlive() {
		t.Fatalf("#9722: a heartbeat restart 1s into boot cut the cold-boot grace short: the peer was declared "+
			"lost %v after the restart with about %v of boot grace left (the loss-cluster gate failure)",
			heartbeatRestartGrace+500*time.Millisecond, time.Until(r.inheritedHold).Round(time.Second))
	}

	// Once both the restart grace and the inherited hold have passed, a stale
	// peer is lost as usual.
	r.inheritedHold = time.Now().Add(-time.Millisecond)
	r.checkTimeout()
	if m.PeerAlive() {
		t.Error("the stale peer was still alive after the restart grace and the inherited hold had both passed")
	}
}

// Through the real RestartHeartbeat: the replacement inherits exactly the end of
// the grace the running receiver was inside.
func TestRestartHeartbeatPassesTheRunningGraceToTheReplacement_9722(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	defer m.StopHeartbeat()

	m.mu.RLock()
	r0 := m.hbReceiver
	want := r0.startedAt.Add(r0.seenThenLostGrace())
	m.mu.RUnlock()
	r0.lastSeen.Store(MonotonicNanos() - staleAge9722.Nanoseconds())

	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat returned false while running")
	}
	m.mu.RLock()
	r1 := m.hbReceiver
	got := r1.inheritedHold
	m.mu.RUnlock()
	if r1 == r0 {
		t.Fatal("receiver was not replaced")
	}
	if !got.Equal(want) {
		t.Errorf("replacement inheritedHold = %v, want the predecessor's grace end %v", got, want)
	}
	if left := time.Until(got); left < heartbeatStartupGrace-5*time.Second {
		t.Errorf("a restart just after a cold start must keep most of the %v boot grace; %v left", heartbeatStartupGrace, left)
	}
}

// A failed restart (#9751) carries the grace end into its retry, so a boot-time
// restart that fails does not lose the boot grace either.
func TestFailedRestartCarriesTheHoldIntoItsRetry_9722(t *testing.T) {
	fastRestartRetries9751(t)
	bad := unbindableAddr9751(t)
	m := startedManager9751(t)
	m.mu.RLock()
	r0 := m.hbReceiver
	want := r0.startedAt.Add(r0.seenThenLostGrace())
	m.mu.RUnlock()
	r0.lastSeen.Store(MonotonicNanos() - staleAge9722.Nanoseconds())

	setLocalAddr9751(m, bad)
	if m.RestartHeartbeat() || !m.HeartbeatRestartOwed() {
		t.Fatal("setup: want a failed restart that recorded a debt")
	}
	m.mu.RLock()
	owedHold := m.hbRestartOwedHold
	m.mu.RUnlock()
	if !owedHold.Equal(want) {
		t.Fatalf("the restart debt carries hold %v, want the predecessor's grace end %v", owedHold, want)
	}

	setLocalAddr9751(m, "127.0.0.1")
	if !m.RestartHeartbeat() {
		t.Fatal("the retry did not start the heartbeat")
	}
	m.mu.RLock()
	got := m.hbReceiver.inheritedHold
	m.mu.RUnlock()
	if !got.Equal(want) {
		t.Errorf("the retry's receiver inherited %v, want %v: a failed boot-time restart lost the boot grace", got, want)
	}
}
