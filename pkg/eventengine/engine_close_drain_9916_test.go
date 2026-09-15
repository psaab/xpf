package eventengine

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9916 F-131: Close must explicitly abandon queued actions (counted, gauge reset,
// logged) instead of dropping them silently with the gauge stuck.
//
// Close's docstring said it "drains in-flight retries"; the body closed stopCh and
// the worker returned with buffered actions still queued. None ran, none were
// counted, the gauge was never decremented, nothing logged.
func TestEngineCloseAccountsQueued9916(t *testing.T) {
	e := New(nil, nil) // worker never started; direct enqueue only
	// NOTE: no defer Close — Close is the act under test.

	// Distinct policy names: same-policy actions collapse under #5853 supersede,
	// so N identical names would occupy 1 slot and the ==N assertion would fail.
	const n = 8
	for i := 0; i < n; i++ {
		if !e.enqueue(plannedAction{policyName: fmt.Sprintf("p9916_%02d", i)}) {
			t.Fatalf("enqueue %d was not admitted; queue unexpectedly full", i)
		}
	}
	if got := e.Stats().QueueDepth; got != n {
		t.Fatalf("pre-Close QueueDepth = %d, want %d (fixture did not queue)", got, n)
	}

	e.Close()

	if got := e.Stats().QueueDepth; got != 0 {
		t.Fatalf("post-Close QueueDepth = %d, want 0 — Close abandoned %d queued actions with the gauge stuck (#9916 F-131)", got, got)
	}
	if got := e.Stats().DroppedShutdown; got != n {
		t.Fatalf("post-Close DroppedShutdown = %d, want %d — abandoned actions must be explicitly counted (#9916 F-131)", got, n)
	}
	// Idempotent: a second Close finds an empty queue and does not double-count.
	e.Close()
	if got := e.Stats().DroppedShutdown; got != n {
		t.Fatalf("second Close DroppedShutdown = %d, want still %d (no double-count)", got, n)
	}
}

// #9916 F-131 (abort half): an in-flight lock retry abandoned by Close must be
// counted, not silently dropped. Parks the worker in backoff under a held lock,
// Closes mid-backoff, and asserts DroppedShutdown==1 from the abort path alone
// (the queue is empty — the action was dequeued — so the Close drain contributes 0).
func TestEngineCloseAbortsRetryCounted9916(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p9916abort",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name should-not-apply-9916"},
	}
	e := New(s, nil)
	fastRetry(e)
	// NOTE: no defer Close — Close is the act under test.
	e.Apply([]*config.EventPolicy{pol})

	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "worker retrying under held lock", func() bool { return e.Stats().Retried >= 1 })

	e.Close()
	// Release the lock after Close so the store is left clean (worker already gone).
	s.ExitConfigureSession("operator")

	if got := e.Stats().DroppedShutdown; got != 1 {
		t.Fatalf("DroppedShutdown = %d, want 1 — in-flight retry abort must be counted (#9916 F-131)", got)
	}
	if got := e.Stats().QueueDepth; got != 0 {
		t.Fatalf("QueueDepth = %d, want 0", got)
	}
}
