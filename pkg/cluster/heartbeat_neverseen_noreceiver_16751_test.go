package cluster

import (
	"testing"
	"time"
)

// #16751: peer-absence confirmation lived only in the heartbeat receiver.
// When the heartbeat could not start at all — the control interface has no
// address, e.g. a back-to-back control cable with no carrier while the peer
// is powered off, so networkd (ConfigureWithoutCarrier=false) never
// configures it and the daemon's 60s start-retry exhausts — no receiver
// existed, handlePeerNeverSeen was never driven, and every non-preempt RG
// stayed secondary indefinitely: no timer, no degraded fallback.
//
// These cells never create a receiver. They drive the Manager-owned
// never-seen clock armed by UpdateConfig. On the pre-fix tree they fail by
// timing out: nothing confirms absence without a receiver.

// shortenNeverSeenGrace swaps the Manager never-seen floor for a test value.
func shortenNeverSeenGrace(t *testing.T, d time.Duration) {
	t.Helper()
	orig := neverSeenGrace
	neverSeenGrace = d
	t.Cleanup(func() { neverSeenGrace = orig })
}

// waitPeerConfirmedAbsent polls until the Manager confirms the never-seen
// peer absent or the deadline passes.
func waitPeerConfirmedAbsent(t *testing.T, m *Manager, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if peerConfirmedAbsent(m) {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return peerConfirmedAbsent(m)
}

// DEFECT cell (ready RG): no receiver ever starts, yet after the never-seen
// floor the peer is confirmed absent and the ready RG promotes — the lone
// survivor of a dead pair forwards again.
func TestNoReceiverNeverSeenReadyPromotes16751(t *testing.T) {
	shortenNeverSeenGrace(t, 80*time.Millisecond)
	m := coldBootManager(t)
	m.SetRGReady(0, true, nil)
	// Deliberately no receiver: hbReceiver stays nil for the whole cell.
	if m.HeartbeatRunning() {
		t.Fatal("setup: no heartbeat should be running in the no-receiver cell")
	}
	if !waitPeerConfirmedAbsent(t, m, 3*time.Second) {
		t.Fatal("no receiver: peer never confirmed absent after the never-seen floor (unbounded secondary hold)")
	}
	if peerEverSeen(m) {
		t.Fatal("confirmed absence must not rewrite peer-ever-seen history")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("ready lone node did not promote after Manager-confirmed absence")
	}
}

// DEFECT cell (unready RG): absence still confirms, the readiness gate still
// holds the RG secondary, and the degraded fallback promotes it degraded
// after degradedPromoteTimeout — exactly the receiver path's #10697 shape,
// now reachable with no receiver.
func TestNoReceiverNeverSeenDegradedPromotes16751(t *testing.T) {
	shortenNeverSeenGrace(t, 80*time.Millisecond)
	m := coldBootManager(t)
	m.mu.Lock()
	m.degradedPromoteTimeout = 250 * time.Millisecond
	m.groups[0].Weight = 200
	m.groups[0].ReadinessReasons = []string{"dataplane not ready"}
	m.mu.Unlock()

	if !waitPeerConfirmedAbsent(t, m, 3*time.Second) {
		t.Fatal("no receiver: peer never confirmed absent after the never-seen floor")
	}
	m.mu.RLock()
	stayedSecondary := m.groups[0].State == StateSecondary
	notReadySince := m.groups[0].NotReadySince
	degraded := m.groups[0].DegradedPromoted
	m.mu.RUnlock()
	if !stayedSecondary {
		t.Fatal("unready RG promoted immediately on absence confirmation; readiness gate bypassed")
	}
	if notReadySince.IsZero() || degraded {
		t.Fatalf("readiness gate did not arm degraded fallback: NotReadySince=%v DegradedPromoted=%v", notReadySince, degraded)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !m.IsLocalPrimary(0) {
		time.Sleep(2 * time.Millisecond)
	}
	m.mu.RLock()
	promoted := m.groups[0].State == StatePrimary
	degraded = m.groups[0].DegradedPromoted
	m.mu.RUnlock()
	if !promoted || !degraded {
		t.Fatalf("degraded fallback did not promote the unready RG with no receiver: promoted=%v degraded=%v", promoted, degraded)
	}
}

// Floor cell: inside the grace the Manager clock must NOT confirm absence —
// the #4386 simultaneous-cold-boot split-brain protection is unchanged when
// the confirmation comes from the Manager instead of the receiver.
func TestNoReceiverNeverSeenFloorHolds16751(t *testing.T) {
	shortenNeverSeenGrace(t, time.Hour) // floor far away: armed but never due
	m := coldBootManager(t)
	m.SetRGReady(0, true, nil)
	time.Sleep(50 * time.Millisecond)
	if peerConfirmedAbsent(m) {
		t.Fatal("peer confirmed absent inside the never-seen floor (split-brain risk)")
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node promoted inside the never-seen floor with no receiver")
	}
}

// Sync-proof cell (#11566, Manager path): fresh session-sync proof keeps
// suppressing confirmation past the floor, re-probed periodically; once the
// proof goes silent the next recheck confirms absence and promotes.
func TestNoReceiverNeverSeenSyncFreshSuppresses16751(t *testing.T) {
	shortenNeverSeenGrace(t, 60*time.Millisecond)
	m := coldBootManager(t)
	m.SetPeerNeverSeenSyncFreshFunc(func() bool { return true })
	m.SetRGReady(0, true, nil)

	// Well past the floor plus several rechecks: still held.
	time.Sleep(300 * time.Millisecond)
	if peerConfirmedAbsent(m) {
		t.Fatal("fresh sync proof confirmed peer absent on the Manager clock")
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node promoted while sync proof remained fresh")
	}

	m.SetPeerNeverSeenSyncFreshFunc(func() bool { return false })
	if !waitPeerConfirmedAbsent(t, m, 3*time.Second) {
		t.Fatal("silent sync: Manager clock never confirmed absence after proof went stale")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("ready node did not promote after silent sync on the Manager clock")
	}
}

// Disarm cells: hearing the peer, removing the control link, and stopping
// the manager each retire the clock so it can never confirm absence late.
func TestNeverSeenClockDisarms16751(t *testing.T) {
	t.Run("peer heartbeat disarms", func(t *testing.T) {
		shortenNeverSeenGrace(t, 60*time.Millisecond)
		m := coldBootManager(t)
		m.handlePeerHeartbeat(&HeartbeatPacket{
			NodeID:    1,
			ClusterID: 1,
			Groups: []HeartbeatGroup{
				{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			},
		})
		if peerConfirmedAbsent(m) {
			t.Fatal("peer confirmed absent after a heartbeat was heard")
		}
	})

	t.Run("control link removal disarms", func(t *testing.T) {
		shortenNeverSeenGrace(t, 60*time.Millisecond)
		m := coldBootManager(t)
		cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
		cfg.ControlInterface = "" // standalone: no absence confirmation owed
		m.UpdateConfig(cfg)
		time.Sleep(200 * time.Millisecond)
		if peerConfirmedAbsent(m) {
			t.Fatal("peer confirmed absent after the control link was removed")
		}
	})

	t.Run("stop disarms", func(t *testing.T) {
		shortenNeverSeenGrace(t, 60*time.Millisecond)
		m := coldBootManager(t)
		m.Stop()
		time.Sleep(200 * time.Millisecond)
		if peerConfirmedAbsent(m) {
			t.Fatal("peer confirmed absent after manager Stop")
		}
	})
}

// Re-apply cell: a routine UpdateConfig re-apply (every commit re-applies)
// must not push the floor out — the clock keeps its original stamp.
func TestNeverSeenClockReapplyKeepsFloor16751(t *testing.T) {
	shortenNeverSeenGrace(t, 300*time.Millisecond)
	m := coldBootManager(t)
	m.SetRGReady(0, true, nil)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg.ControlInterface = "em0"
	// Re-apply repeatedly, well past one grace from the first arming. If a
	// re-apply re-stamped, confirmation would be pushed past the deadline.
	start := time.Now()
	for time.Since(start) < 500*time.Millisecond && !peerConfirmedAbsent(m) {
		m.UpdateConfig(cfg)
		time.Sleep(20 * time.Millisecond)
	}
	if !peerConfirmedAbsent(m) {
		t.Fatal("repeated UpdateConfig re-applies pushed the never-seen floor out indefinitely")
	}
}
