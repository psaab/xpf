package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #16070: a transient ErrCommitCheckBusy from applyOnce's CommitCheck (an
// operator's commit-check holds the store's single compile slot) must be
// retried on the held-lock backoff schedule, not discarded as a permanent
// CommitCheck reject. These pins create the busy condition through the
// sanctioned test seam configstore.HoldCommitCheckSlotForTest, which
// occupies the slot exactly as an in-flight compile does.

// busyPolicy16070 is a valid one-command remediation.
func busyPolicy16070() *config.EventPolicy {
	return &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name after-busy"},
	}
}

// TestQueue_CommitCheckBusyRetriesThenCommits_16070: while the compile slot
// is held, the worker retries (Retried bumps, nothing rejected/committed);
// once the slot frees, the valid remediation commits.
//
// FAIL-ON-REVERT: drop the ErrCommitCheckBusy arm from runAction's retry
// branch and the busy refusal lands in the permanent-reject arm —
// Rejected bumps, the action is discarded, and this test times out waiting
// for a commit that never comes.
func TestQueue_CommitCheckBusyRetriesThenCommits_16070(t *testing.T) {
	s := newStore(t)
	e := New(s, nil)
	e.retryInitial = time.Millisecond
	e.retryMax = 5 * time.Millisecond
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{busyPolicy16070()})

	release := configstore.HoldCommitCheckSlotForTest(s)
	e.HandleEvent(eventFor("ping_test_failed"))

	// The worker must retry the busy refusal, not reject the action.
	waitFor(t, "a busy retry", func() bool { return e.Stats().Retried >= 1 })
	if got := e.Stats().Rejected; got != 0 {
		t.Fatalf("Rejected=%d while compile slot held; a transient busy refusal must retry, not discard", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("host-name=%q while compile slot held; action must wait, not apply", got)
	}

	release()
	waitFor(t, "commit after compile slot release", func() bool { return e.Stats().Committed >= 1 })
	if got := s.ActiveConfig().System.HostName; got != "after-busy" {
		t.Fatalf("host-name=%q; action should have committed after the compile slot released", got)
	}
}

// TestQueue_CommitCheckBusyPastDeadlineDrops_16070: if the compile slot
// stays held past the retry deadline, the action drops (counted
// DroppedLockHeld, the same terminal counter as a held config lock) and
// never commits — the retry is bounded, not a spin.
func TestQueue_CommitCheckBusyPastDeadlineDrops_16070(t *testing.T) {
	s := newStore(t)
	e := New(s, nil)
	e.retryInitial = time.Millisecond
	e.retryMax = time.Millisecond
	e.retryDeadline = 20 * time.Millisecond
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{busyPolicy16070()})

	release := configstore.HoldCommitCheckSlotForTest(s)
	defer release()
	e.HandleEvent(eventFor("ping_test_failed"))

	waitFor(t, "drop counter", func() bool { return e.Stats().DroppedLockHeld >= 1 })
	if got := e.Stats().Rejected; got != 0 {
		t.Fatalf("Rejected=%d; a busy refusal past deadline must drop as lock-held, not reject", got)
	}
	if got := e.Stats().Committed; got != 0 {
		t.Fatalf("Committed=%d; a dropped action must not commit", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("host-name=%q; a dropped action must not apply", got)
	}
}
