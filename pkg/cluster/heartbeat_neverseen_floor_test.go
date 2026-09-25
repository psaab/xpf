package cluster

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// #4386 cold-boot split-brain regression coverage.
//
// The heartbeat "peer never seen" path (lastSeen == 0) used to confirm the
// peer absent and drive single-node election after only threshold*interval
// (~500ms). On a SIMULTANEOUS cold boot the local config apply phase (FRR
// reload, fabric creation, RETH MAC down/up) disrupts the control-link UDP RX
// for 10-15+ seconds, so the first heartbeats from a live peer are dropped and
// lastSeen stays 0 on BOTH nodes. Both then promoted at T0+500ms and both
// claimed the RETH virtual MAC — a 10-15s split-brain. The fix holds the
// never-seen promotion behind heartbeatStartupGrace, the same cold-boot grace
// the seen-then-lost path already uses.

// TestNeverSeenConfirmedFloor pins the startup-floor boundary. Within the
// grace the never-seen decision is held; at/after the grace it fires, so a
// genuinely-absent peer (single-node deployment) still promotes — the floor
// delays the decision, it never blocks it permanently.
func TestNeverSeenConfirmedFloor(t *testing.T) {
	const grace = 30 * time.Second
	cases := []struct {
		name       string
		sinceStart time.Duration
		want       bool
	}{
		{"steady-state timeout is NOT enough at boot", 500 * time.Millisecond, false},
		{"mid config-apply disruption window", 5 * time.Second, false},
		{"just under grace", grace - time.Millisecond, false},
		{"exactly at grace still promotes (no permanent no-master)", grace, true},
		{"well past grace promotes", grace + 10*time.Second, true},
	}
	for _, tc := range cases {
		if got := neverSeenConfirmed(tc.sinceStart, grace); got != tc.want {
			t.Errorf("%s: neverSeenConfirmed(%v, %v) = %v, want %v",
				tc.name, tc.sinceStart, grace, got, tc.want)
		}
	}
}

// coldBootManager builds a cluster-mode manager with one non-preempt RG that
// starts secondary (blocked from initial promotion by controlInterface +
// non-preempt + no confirmed peer absence), mirroring a fresh boot before any
// peer heartbeat has been received.
func coldBootManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg.ControlInterface = "em0" // enables cluster-mode election gating
	m.UpdateConfig(cfg)
	if m.IsLocalPrimary(0) {
		t.Fatal("setup: node should start secondary before any peer heartbeat")
	}
	return m
}

func peerEverSeen(m *Manager) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerEverSeen
}

func peerConfirmedAbsent(m *Manager) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerConfirmedAbsent
}

// TestColdBootNeverSeenFloorSuppressesPromotion is the RED-on-revert guard for
// #4386. A receiver that has never seen a peer, still inside the cold-boot
// grace, must NOT confirm the peer absent — so it does not promote and cannot
// join a dual-primary. After the grace, an RG that becomes ready must promote;
// an unready RG stays secondary until the degraded fallback (#10697).
// Reverting the never-seen floor to the old threshold*interval check promotes
// at ~500ms, making the within-grace assertion fail.
func TestColdBootNeverSeenFloorSuppressesPromotion(t *testing.T) {
	// Within the grace (simulating the 5s config-apply RX disruption): no
	// heartbeat ever seen, but we must hold — a live peer is likely just
	// slow to be heard. On the buggy path 5s > 500ms → promote → split-brain.
	m := coldBootManager(t)
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-5 * time.Second)
	// r.lastSeen defaults to 0 (never seen).
	r.checkTimeout()
	if peerConfirmedAbsent(m) {
		t.Fatal("never-seen peer confirmed absent within the cold-boot grace (split-brain risk)")
	}
	if peerEverSeen(m) {
		t.Fatal("never-seen peer incorrectly recorded as ever seen")
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node promoted to primary within the cold-boot grace on a never-seen peer")
	}

	// Once ready, a confirmed-absent single-node deployment must promote. This
	// checks that the grace still delays, rather than permanently blocks, takeover.
	m.SetRGReady(0, true, nil)
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	r.checkTimeout()
	if !peerConfirmedAbsent(m) {
		t.Fatal("never-seen peer not confirmed absent after the grace elapsed")
	}
	if peerEverSeen(m) {
		t.Fatal("confirmed absence must not rewrite the peer-ever-seen history")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("ready node did not promote after the cold-boot grace with a genuinely-absent peer")
	}
}

// TestColdBootNeverSeenReadinessGate10697 drives the real checkTimeout →
// handlePeerNeverSeen → electSingleNode path. Confirming absence must release
// the non-preempt hold without bypassing readiness; the node promotes only
// after the degraded timeout and reports that promotion as degraded.
func TestColdBootNeverSeenReadinessGate10697(t *testing.T) {
	m := coldBootManager(t)
	m.mu.Lock()
	m.degradedPromoteTimeout = 250 * time.Millisecond
	m.groups[0].Weight = 200
	m.groups[0].ReadinessReasons = []string{"dataplane not ready"}
	m.mu.Unlock()

	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	r.checkTimeout()

	m.mu.RLock()
	rg := m.groups[0]
	stayedSecondary := rg.State == StateSecondary
	absenceConfirmed := m.peerConfirmedAbsent
	everSeen := m.peerEverSeen
	notReadySince := rg.NotReadySince
	degraded := rg.DegradedPromoted
	m.mu.RUnlock()
	if !absenceConfirmed || everSeen {
		t.Fatalf("wrong cold-boot peer state: confirmedAbsent=%v everSeen=%v", absenceConfirmed, everSeen)
	}
	if !stayedSecondary {
		t.Fatal("unready RG promoted immediately after confirmed absence at the 30s startup grace")
	}
	if notReadySince.IsZero() || degraded {
		t.Fatalf("readiness gate did not arm the degraded fallback: NotReadySince=%v DegradedPromoted=%v",
			notReadySince, degraded)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.IsLocalPrimary(0) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	m.mu.RLock()
	promoted := m.groups[0].State == StatePrimary
	degraded = m.groups[0].DegradedPromoted
	m.mu.RUnlock()
	if !promoted || !degraded {
		t.Fatalf("degraded fallback did not promote and mark the unready RG: promoted=%v degraded=%v",
			promoted, degraded)
	}
	if !strings.Contains(logs.String(), "cluster: promoting NOT-READY RG after degraded timeout") {
		t.Fatalf("degraded promotion warning missing: %s", logs.String())
	}
}

func TestPeerHeartbeatClearsConfirmedAbsence10697(t *testing.T) {
	m := coldBootManager(t)
	m.mu.Lock()
	m.peerConfirmedAbsent = true
	m.mu.Unlock()
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 255, Weight: 200, State: uint8(StatePrimary)},
		},
	})
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.peerConfirmedAbsent || !m.peerEverSeen {
		t.Fatalf("heartbeat did not replace confirmed absence with seen-peer state: confirmedAbsent=%v everSeen=%v",
			m.peerConfirmedAbsent, m.peerEverSeen)
	}
}

// TestSeenThenLostPathUnchangedByNeverSeenFloor confirms the fix only touches
// the never-seen branch. A peer that WAS seen (lastSeen != 0) then went silent
// is still governed by the existing cold-boot grace, then declared lost via
// the unchanged staleness path.
func TestSeenThenLostPathUnchangedByNeverSeenFloor(t *testing.T) {
	newSeenLostManager := func() *Manager {
		m := coldBootManager(t)
		m.mu.Lock()
		m.peerEverSeen = true // peer was heard at least once
		m.peerAlive = true
		m.mu.Unlock()
		return m
	}
	timeout := time.Duration(DefaultHeartbeatThreshold) * DefaultHeartbeatInterval

	// Within the grace: a stale heartbeat is suppressed (same grace as
	// before) so a recovering node does not declare its live peer dead.
	m := newSeenLostManager()
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-5 * time.Second)
	r.lastSeen.Store(MonotonicNanos() - (timeout + time.Second).Nanoseconds())
	r.checkTimeout()
	m.mu.RLock()
	aliveInGrace := m.peerAlive
	m.mu.RUnlock()
	if !aliveInGrace {
		t.Fatal("seen-then-lost peer declared dead inside the cold-boot grace")
	}

	// Past the grace: the staleness path fires exactly as before the fix —
	// peer is marked lost at threshold*interval staleness.
	m = newSeenLostManager()
	r = newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	r.startedAt = time.Now().Add(-(heartbeatStartupGrace + time.Second))
	r.lastSeen.Store(MonotonicNanos() - (timeout + time.Second).Nanoseconds())
	r.checkTimeout()
	m.mu.RLock()
	aliveAfterGrace := m.peerAlive
	m.mu.RUnlock()
	if aliveAfterGrace {
		t.Fatal("seen-then-lost peer not declared dead after the grace (lost-peer path regressed)")
	}
}
