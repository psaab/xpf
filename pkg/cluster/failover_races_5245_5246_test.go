package cluster

import (
	"testing"
	"time"
)

// TestUpdateConfig_RemovesGroup_StopsHoldTimer covers #5245: when a redundancy
// group is removed from config, its armed takeover-hold timer must be stopped
// and cleared so the AfterFunc closure cannot fire an election against removed
// state. Reverting the Stop()+nil in the group_state.go removal loop leaves
// rg.holdTimer non-nil (armed) after removal → this test goes RED.
func TestUpdateConfig_RemovesGroup_StopsHoldTimer(t *testing.T) {
	m := NewManager(0, 1)
	// A non-zero takeover-hold time is required for SetRGReady to arm the
	// per-RG hold timer. 60s keeps the timer armed (but never firing) for the
	// duration of this synchronous test.
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	cfg.TakeoverHoldTime = 60_000 // ms
	m.UpdateConfig(cfg)

	// Keep a direct reference to RG1's state so we can inspect its timer field
	// after the group is dropped from m.groups.
	rg1 := m.groups[1]
	if rg1 == nil {
		t.Fatal("precondition: RG1 should exist after UpdateConfig")
	}

	// Arm RG1's hold timer via a not-ready → ready transition.
	m.SetRGReady(1, true, nil)
	if rg1.holdTimer == nil {
		t.Fatal("precondition: RG1 hold timer should be armed after SetRGReady")
	}

	// Remove RG1 from config.
	cfg2 := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg2.TakeoverHoldTime = 60_000
	m.UpdateConfig(cfg2)

	if _, ok := m.groups[1]; ok {
		t.Fatal("RG1 should be removed from m.groups")
	}
	// The core assertion: the removal must have stopped and cleared the armed
	// timer so it cannot fire against removed state (#5245).
	if rg1.holdTimer != nil {
		t.Fatal("removed RG hold timer leaked: holdTimer is non-nil after UpdateConfig removal (#5245)")
	}
}

// TestUpdateConfig_RemovesGroup_TimerDoesNotElect is a stronger #5245 guard: it
// arms a SHORT hold timer, removes the group, and waits past the hold interval.
// The stopped-and-cleared timer must not fire an election that touches state.
// The removed RG's captured state must remain untouched (never promoted to
// primary by a stale closure).
func TestUpdateConfig_RemovesGroup_TimerDoesNotElect(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 100}),
	)
	cfg.TakeoverHoldTime = 20 // ms — short so a leaked timer would fire quickly
	m.UpdateConfig(cfg)

	rg1 := m.groups[1]
	if rg1 == nil {
		t.Fatal("precondition: RG1 should exist")
	}
	// Drive RG1 to a known non-primary state, then arm the hold timer.
	rg1.State = StateSecondary
	m.SetRGReady(1, true, nil)
	if rg1.holdTimer == nil {
		t.Fatal("precondition: RG1 hold timer should be armed")
	}

	// Remove RG1 while its short timer is armed.
	cfg2 := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	cfg2.TakeoverHoldTime = 20
	m.UpdateConfig(cfg2)

	// Force the captured state to a sentinel a stale election would overwrite.
	m.mu.Lock()
	rg1.State = StateSecondary
	m.mu.Unlock()

	// Wait well past the 20ms hold interval for any leaked timer to fire.
	time.Sleep(120 * time.Millisecond)

	m.mu.Lock()
	leaked := rg1.holdTimer != nil
	state := rg1.State
	m.mu.Unlock()
	if leaked {
		t.Fatal("removed RG hold timer leaked after grace wait (#5245)")
	}
	if state != StateSecondary {
		t.Fatalf("stale hold-timer closure mutated removed RG state to %s (#5245)", state)
	}
}

// TestManualFailover_ResetDuringPreHookWins covers #5246: a ResetFailover that
// lands while ManualFailover is parked in its pre-failover hook (m.mu released)
// must win. The trailing ManualFailover SecondaryHold write must be abandoned
// rather than clobbering the operator's reset. Reverting the failover-
// generation re-check in ManualFailover makes the trailing write clobber the
// reset (ManualFailover=true / State=SecondaryHold) → this test goes RED.
func TestManualFailover_ResetDuringPreHookWins(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	recvEvent19161(t, m.Events(), "drain the initial secondary→primary election event")

	if !m.IsLocalPrimary(0) {
		t.Fatal("precondition: node should be primary for RG0")
	}

	// A pre-hook that blocks until released, holding ManualFailover in the
	// unlocked window while ResetFailover runs.
	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	m.SetPreManualFailoverHook(func(rgID int) error {
		close(hookStarted)
		<-hookRelease
		return nil
	})

	errCh := make(chan error, 1)
	go func() {
		_, err := m.ManualFailover(0)
		errCh <- err
	}()

	// Wait for ManualFailover to enter the pre-hook (m.mu released here).
	<-hookStarted

	// Operator resets the failover during the unlocked window. This bumps the
	// per-RG failover generation and restores the node to primary.
	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover error = %v", err)
	}

	// Release the parked pre-hook so ManualFailover re-acquires m.mu.
	close(hookRelease)
	if err := <-errCh; err != nil {
		t.Fatalf("ManualFailover should return without error when superseded: %v", err)
	}

	// Final state must reflect the RESET, not the failover.
	states := m.GroupStates()
	if len(states) != 1 {
		t.Fatalf("expected 1 group, got %d", len(states))
	}
	if states[0].ManualFailover {
		t.Fatal("reset was clobbered: ManualFailover=true after ResetFailover won the race (#5246)")
	}
	if states[0].State != StatePrimary {
		t.Fatalf("reset was clobbered: state = %s, want primary (#5246)", states[0].State)
	}
}
