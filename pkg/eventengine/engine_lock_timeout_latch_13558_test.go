package eventengine

// engine_lock_timeout_latch_13558_test.go — #13558.
//
// An edge-triggered (`trigger on N`) policy arms rt.onLatched in
// evaluateEvent. If its queued action is then dropped because the config
// lock stays held past the retry deadline, the crossing produced no
// remediation — exactly like the queue-full drop #6810 already rolls back.
// Before the fix, runAction's ErrConfigLocked deadline path returned without
// releaseEdgeLatch, so the latch stayed armed forever: withinMatches
// suppresses every later at/above-threshold event and re-arms only when the
// count drops below N, which for a sustained fault never happens.
//
// FAIL-ON-REVERT: remove the releaseEdgeLatch call on the lock-timeout path
// and the post-drop sustained event is suppressed, so the remediation never
// commits and this test goes RED.

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestLockTimeoutDropDoesNotConsumeTheCrossing13558(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:          "remediate",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: 2}},
		ThenCommands:  []string{"set system host-name remediated"},
	}
	e := New(s, nil)
	e.retryInitial = time.Millisecond
	e.retryMax = time.Millisecond
	e.retryDeadline = 20 * time.Millisecond
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	// Hold the config lock as another session so every applyOnce attempt
	// fails with ErrConfigLocked and the action times out.
	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	defer s.ExitConfigureSession("operator")

	// Event 1: below threshold. Event 2: the crossing — latch armed, action
	// queued, worker retries against the held lock until the deadline.
	e.HandleEvent(eventFor("ping_test_failed"))
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "lock-held drop counter", func() bool { return e.Stats().DroppedLockHeld >= 1 })

	// The dropped crossing must not leave the edge latch armed.
	e.mu.Lock()
	latched := e.runtime["remediate"].onLatched["ping_test_failed"]
	e.mu.Unlock()
	if latched {
		t.Fatal("edge latch still armed after config-lock timeout drop — " +
			"the crossing was consumed by a remediation that never ran (#13558)")
	}

	// Release the lock; the fault is sustained, so the next event keeps the
	// count at/above the threshold without re-crossing. It must re-fire and
	// commit now that the lock is free.
	if !s.ExitConfigureSession("operator") {
		t.Fatal("failed to release the held lock")
	}
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "commit after lock release", func() bool { return e.Stats().Committed >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Errorf("host-name=%q; sustained-fault remediation should have committed after the lock released", got)
	}
}
