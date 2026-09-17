package eventengine

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Regression tests for #3750 (revalidate-before-commit). A pre-classified
// remediation used to commit its plan with zero revalidation against live
// engine state, opening three fail-opens whenever an operator held the config
// lock while an RPM event fired (the worker retries on ErrConfigLocked). The
// fix stamps each action with the policy's semantic revision at evaluate time
// and revalidates it under e.mu inside applyOnce (after EnterConfigure, while
// holding the config lock so no operator Apply can interleave): the action is
// dropped as stale if the policy was removed, was redefined, or is now in its
// cooldown.
//
// Each test uses the held-lock pattern to park the worker retrying an action,
// mutates engine state, then releases the lock and asserts the queued action is
// DROPPED rather than committed. All are fail-on-revert: removing the
// staleReason gate in applyOnce makes the stale batch commit and each test goes
// RED.

// fastRetry configures a sub-millisecond backoff with a generous deadline so
// the worker retries rapidly under a held lock and reacts promptly once the
// lock releases, without ever hitting the lock-held drop deadline.
func fastRetry(e *Engine) {
	e.retryInitial = time.Millisecond
	e.retryMax = 5 * time.Millisecond
	e.retryDeadline = 10 * time.Second
}

// #3750 H1: an operator removes an event-options policy while its remediation
// is queued/retrying under a held config lock. When the lock releases, the
// worker must revalidate and DROP the stale action — NOT commit a batch that no
// active policy authorizes.
//
// FAIL-ON-REVERT: without the staleReason gate the worker commits the removed
// policy's command, so host-name becomes "should-not-apply" and Committed==1
// (DroppedStale==0), failing the assertions below.
func TestStale_RemovedPolicyDropsQueuedAction_3750(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name should-not-apply"},
	}
	e := New(s, nil)
	fastRetry(e)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	// Operator holds the config lock; the worker parks retrying the action.
	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "worker retrying under held lock", func() bool { return e.Stats().Retried >= 1 })

	// Operator commits a config that REMOVES policy p (Apply(nil)) while the
	// action is still in flight.
	applyPolicies9984(e, nil)

	// Release the lock: the worker's next attempt enters configure, revalidates,
	// and must drop the action (policy removed).
	if !s.ExitConfigureSession("operator") {
		t.Fatal("failed to release the held lock")
	}
	waitFor(t, "stale drop", func() bool { return e.Stats().DroppedStale >= 1 })

	// Give any (wrongly) racing commit time to land, then assert it did not.
	time.Sleep(50 * time.Millisecond)
	if got := e.Stats().Committed; got != 0 {
		t.Errorf("Committed=%d; a removed policy's queued action must not commit (#3750 H1)", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Errorf("host-name=%q; the removed policy's stale command must not apply (want unchanged 'base')", got)
	}
}

// #3750 H2: a same-name policy redefinition (different ThenCommands → new
// semantic revision) must invalidate the OLD queued command batch. The stale
// action carries the pre-redefine revision; the worker drops it rather than
// committing the old command set under the new policy's name.
//
// FAIL-ON-REVERT: without the gate the OLD batch commits, so host-name becomes
// "OLD" and Committed==1, failing the assertions below.
func TestStale_RedefinedPolicyDropsOldBatch_3750(t *testing.T) {
	s := newStore(t)
	old := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name OLD"},
	}
	e := New(s, nil)
	fastRetry(e)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{old})

	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "worker retrying under held lock", func() bool { return e.Stats().Retried >= 1 })

	// Redefine p in place: same name, different command set → revision changes.
	redef := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name NEW"},
	}
	applyPolicies9984(e, []*config.EventPolicy{redef})

	if !s.ExitConfigureSession("operator") {
		t.Fatal("failed to release the held lock")
	}
	waitFor(t, "stale drop", func() bool { return e.Stats().DroppedStale >= 1 })

	time.Sleep(50 * time.Millisecond)
	if got := e.Stats().Committed; got != 0 {
		t.Errorf("Committed=%d; a redefined policy's OLD queued batch must not commit (#3750 H2)", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Errorf("host-name=%q; the stale OLD command set must not apply (want unchanged 'base'; 'OLD' means the pre-fix bug)", got)
	}
}

// #3750 H3: the 30s cooldown must gate a QUEUED duplicate. The cooldown is
// checked at evaluate but armed only on commit. The worker dequeues event #1
// (now retrying under the held lock, so it is IN-FLIGHT and no longer in the
// channel); event #2 then enqueues — the queue holds no same-policy entry to
// supersede (#1 is in the worker, not queued), so #2 is queued (this is true
// both before and after the #5853 early-dedup change: the dedup is against
// QUEUED entries, and #1 is not one). When the lock releases the worker commits
// the first, arms the cooldown, then must DROP the second (cooldown active)
// instead of double-committing within the window.
//
// FAIL-ON-REVERT: without the gate the worker commits both queued actions, so
// Committed==2 and DroppedStale==0, failing the assertions below.
func TestStale_CooldownSuppressesQueuedDuplicate_3750(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name remediated"},
	}
	e := New(s, nil)
	fastRetry(e)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	// Operator holds the lock so the worker parks retrying action #1.
	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}

	// Event #1: dequeued by the worker, now retrying under the held lock.
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "worker retrying action #1", func() bool { return e.Stats().Retried >= 1 })

	// Event #2: evaluateEvent sees the cooldown UNARMED (arm-on-commit, and #1
	// has not committed), so it enqueues a duplicate. #1 is IN-FLIGHT in the
	// worker (not in the channel), so the early dedup (#5853) finds no same-policy
	// queued entry to supersede and #2 is queued — exactly the H3 setup.
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "duplicate queued", func() bool { return e.Stats().QueueDepth >= 1 })

	// Release the lock: #1 commits and arms the cooldown; the single worker then
	// dequeues #2 and revalidates it (cooldown now active) → drop as stale.
	if !s.ExitConfigureSession("operator") {
		t.Fatal("failed to release the held lock")
	}
	waitFor(t, "first commit", func() bool { return e.Stats().Committed >= 1 })
	waitFor(t, "duplicate dropped stale", func() bool { return e.Stats().DroppedStale >= 1 })

	// Give the worker time to (wrongly) commit the duplicate, then assert exactly
	// one commit total.
	time.Sleep(50 * time.Millisecond)
	if got := e.Stats().Committed; got != 1 {
		t.Errorf("Committed=%d; the cooldown must suppress the queued duplicate (want exactly 1, #3750 H3)", got)
	}
	if got := e.Stats().DroppedStale; got != 1 {
		t.Errorf("DroppedStale=%d; want exactly 1 (the within-cooldown duplicate)", got)
	}
}

// #3750: the gate must not suppress LEGITIMATE remediations. Two distinct
// policies triggered together both commit (neither is a stale/duplicate), with
// zero stale drops.
func TestStale_DistinctRemediationsFlow_3750(t *testing.T) {
	s := newStore(t)
	p1 := &config.EventPolicy{Name: "p1", Events: []string{"e1"}, ThenCommands: []string{"set system host-name h1"}}
	p2 := &config.EventPolicy{Name: "p2", Events: []string{"e2"}, ThenCommands: []string{"set system domain-name d2"}}
	e := New(s, nil)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{p1, p2})

	e.HandleEvent(rpm.Event{Name: "e1", TestOwner: "o", TestName: "t"})
	e.HandleEvent(rpm.Event{Name: "e2", TestOwner: "o", TestName: "t"})

	waitFor(t, "both commits", func() bool { return e.Stats().Committed >= 2 })
	if got := e.Stats().DroppedStale; got != 0 {
		t.Errorf("DroppedStale=%d; distinct legitimate policies must not be dropped as stale", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "h1" {
		t.Errorf("host-name=%q; p1 must commit 'h1'", got)
	}
	if got := s.ActiveConfig().System.DomainName; got != "d2" {
		t.Errorf("domain-name=%q; p2 must commit 'd2'", got)
	}
}

// #3750: a re-fire AFTER the cooldown elapses must commit again — the gate
// suppresses only WITHIN-window duplicates, not a legitimate later trigger.
// Uses an injected clock so the cooldown boundary is exercised deterministically.
func TestStale_PostCooldownRefire_3750(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name r"},
	}
	e := New(s, nil)
	defer e.Close()

	base := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	cur := base
	e.nowFn = func() time.Time { mu.Lock(); defer mu.Unlock(); return cur }
	advance := func(d time.Duration) { mu.Lock(); cur = cur.Add(d); mu.Unlock() }

	applyPolicies9984(e, []*config.EventPolicy{pol})

	// First trigger commits and arms the cooldown.
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "first commit", func() bool { return e.Stats().Committed >= 1 })
	// Wait until the cooldown is observably ARMED (armCooldown runs on the worker
	// just after the committed counter bumps) so the within-cooldown re-fire
	// below cannot race an unarmed window.
	waitFor(t, "cooldown armed", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		rt := e.runtime["p"]
		return rt != nil && !rt.lastTrigger.IsZero()
	})

	// A re-fire WITHIN the cooldown is suppressed at evaluate (never queued).
	e.HandleEvent(eventFor("ping_test_failed"))
	time.Sleep(20 * time.Millisecond)
	if got := e.Stats().Committed; got != 1 {
		t.Fatalf("Committed=%d; a within-cooldown re-fire must not commit", got)
	}

	// Advance past the 30s cooldown; the re-fire must now commit again and must
	// NOT be dropped as stale.
	advance(policyCooldown + time.Second)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "post-cooldown commit", func() bool { return e.Stats().Committed >= 2 })
	if got := e.Stats().DroppedStale; got != 0 {
		t.Errorf("DroppedStale=%d; a legitimate post-cooldown re-fire must not be dropped as stale", got)
	}
}
