package cluster

import (
	"testing"
	"time"
)

// TestStop_CancelsArmedHoldTimer verifies that Manager.Stop() cancels and
// clears an armed per-RG takeover-hold timer (#4716). Before the fix, Stop()
// stopped only the monitor/heartbeat goroutines and never iterated m.groups,
// so a hold timer armed before Stop kept running — pinning the Manager in
// memory and firing a spurious election on a quiesced manager.
//
// Deterministic RED-on-revert: takeoverHoldTime is set to an hour so the timer
// never fires during the test. Reverting the Stop() cleanup leaves holdTimer
// non-nil, failing the assertion; the fix stops and nils it.
func TestStop_CancelsArmedHoldTimer(t *testing.T) {
	m := NewManager(0, 1)

	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg.ControlInterface = "hb0" // cluster mode
	m.UpdateConfig(cfg)
	// Set AFTER UpdateConfig — UpdateConfig resets takeoverHoldTime from the
	// (zero) config value. An hour ensures the timer never fires in-test.
	m.takeoverHoldTime = time.Hour
	drainEvents(m, 8)

	// Arm the hold timer via a not-ready -> ready transition.
	m.SetRGReady(0, true, nil)

	m.mu.RLock()
	armed := m.groups[0].holdTimer != nil
	m.mu.RUnlock()
	if !armed {
		t.Fatal("precondition: holdTimer should be armed after SetRGReady(true)")
	}

	m.Stop()

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.groups[0].holdTimer != nil {
		t.Fatal("Stop() must cancel and clear rg.holdTimer (#4716: leaked timer)")
	}
	if !m.stopped {
		t.Error("Stop() should mark the manager stopped")
	}
}

// TestStop_SuppressesHoldTimerElection is the behavioral counterpart: after
// Stop() the hold timer must not run an election. The setup blocks the initial
// election with the readiness gate (RG just became ready, hold time not yet
// elapsed) so that ONLY a timer firing after the hold window could promote the
// RG. Stop() is called before the (short) timer would fire.
//
// RED-on-revert: without the Stop() cleanup the timer fires after the hold
// window, runs runElection, promotes the RG, and emits a state-change event —
// caught here as a failure. With the fix the timer is cancelled, no event is
// ever produced, and the wait times out cleanly.
func TestStop_SuppressesHoldTimerElection(t *testing.T) {
	m := NewManager(0, 1)

	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200})) // higher priority than peer
	cfg.ControlInterface = "hb0"                            // cluster mode — enables the readiness gate
	m.UpdateConfig(cfg)
	m.takeoverHoldTime = 40 * time.Millisecond // AFTER UpdateConfig (see above)

	// Peer present and secondary → with a live peer the readiness gate is
	// active, so promotion is gated on the hold time rather than immediate.
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	})

	// Force a clean not-ready secondary baseline (mirrors the existing
	// election tests). No event is emitted by this direct state edit.
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.groups[0].Ready = false
	m.groups[0].ReadySince = time.Time{}
	m.mu.Unlock()
	drainEvents(m, 16)

	// Arm the hold timer. The election runs immediately but is blocked by the
	// readiness gate (ready < holdTime), so the RG stays secondary and only a
	// later timer fire could promote it.
	m.SetRGReady(0, true, nil)
	if m.IsLocalPrimary(0) {
		t.Fatal("precondition: RG should not be primary yet (readiness gate)")
	}
	m.mu.RLock()
	armed := m.groups[0].holdTimer != nil
	m.mu.RUnlock()
	if !armed {
		t.Fatal("precondition: holdTimer should be armed")
	}

	// Quiesce the manager before the timer fires.
	m.Stop()

	// No election event may arrive after Stop, even past the hold window.
	select {
	case ev := <-m.Events():
		t.Fatalf("hold timer fired an election after Stop() (#4716): %+v", ev)
	case <-time.After(300 * time.Millisecond): // >> 40ms hold time
	}
	if m.IsLocalPrimary(0) {
		t.Error("RG must not be promoted by a hold timer after Stop()")
	}
}

// TestHoldTimer_StillPromotesWhenRunning is the active-path guard: the fix must
// not break normal hold-timer operation. With the manager running (not
// stopped), a timer armed on a just-ready RG must still fire after the hold
// window and promote the RG. This proves the m.stopped closure guard is inert
// during normal operation.
func TestHoldTimer_StillPromotesWhenRunning(t *testing.T) {
	m := NewManager(0, 1)
	defer m.Stop() // clean up any live timer

	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	cfg.ControlInterface = "hb0"
	m.UpdateConfig(cfg)
	// #15669: authoring ControlInterface now also arms the dataplane
	// monitor debt on the new RG; clear it as election_test.go:471 does
	// so weight does not block the promotion this cell exists to observe.
	m.SetMonitorWeight(0, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	m.takeoverHoldTime = 40 * time.Millisecond // AFTER UpdateConfig (see above)

	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	})

	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.groups[0].Ready = false
	m.groups[0].ReadySince = time.Time{}
	m.mu.Unlock()
	drainEvents(m, 16)

	// Arm the timer; initial election is blocked by the readiness gate.
	m.SetRGReady(0, true, nil)
	if m.IsLocalPrimary(0) {
		t.Fatal("precondition: RG should not be primary before the hold window")
	}

	// The timer must fire after the hold window and promote the RG.
	select {
	case ev := <-m.Events():
		if ev.GroupID != 0 || ev.NewState != StatePrimary {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(500 * time.Millisecond): // >> 40ms hold time
		t.Fatal("hold timer never promoted the RG on a running manager")
	}
	if !m.IsLocalPrimary(0) {
		t.Error("RG should be primary after the hold timer fired")
	}
}
