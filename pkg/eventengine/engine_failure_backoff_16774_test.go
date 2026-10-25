package eventengine

// engine_failure_backoff_16774_test.go — #16774 (R3-F02-04).
//
// #14724 refunds a non-promoting commit's global-budget slot so a broken
// policy cannot starve healthy ones, but before this fix nothing throttled
// the failing policy itself: every event edge re-ran a full commit attempt
// under the config lock (48 attempts/min in the probe vs the documented 4).
// A post-CommitCheck commit failure now arms a per-policy failure backoff
// (failureBackoff = policyCooldown); later edges are cooldown-suppressed /
// parked and replayed after the backoff, while the refunded slot remains
// available to healthy policies immediately. The HA read-only deferral
// refunds WITHOUT backoff.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

func failedTrigger16774(e *Engine, pol string) time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	rt := e.runtime[pol]
	if rt == nil {
		return time.Time{}
	}
	return rt.failedTrigger
}

// Probe reproduction: 16 policies, frozen clock in one minute, failing
// commitFn, repeated edges. Pre-fix every edge attempted a commit per
// policy (48 attempts in the probe profile); post-fix each policy attempts
// once and is then backed off, while the refund keeps budgetCount at 0.
//
// FAIL-ON-REVERT: drop the armFailureBackoff calls in applyOnce and every
// edge re-attempts — calls climbs past one per policy.
func TestProbeFailingCommitsBoundedByFailureBackoff16774(t *testing.T) {
	s := newStore(t)
	base := time.Unix(1_800_000_000, 0)
	var calls atomic.Int32
	e := New(s, func(ctx context.Context, desc string) (*config.Config, error) {
		calls.Add(1)
		return nil, errors.New("simulated persistent commit failure")
	})
	defer e.Close()
	e.nowFn = func() time.Time { return base }

	const policyCount = 16
	pols := make([]*config.EventPolicy, 0, policyCount)
	for i := range policyCount {
		name := fmt.Sprintf("fail-%02d", i)
		pols = append(pols, &config.EventPolicy{
			Name:         name,
			Events:       []string{"ping_test_failed"},
			ThenCommands: []string{"set system host-name " + name},
		})
	}
	applyPolicies9984(e, pols)

	// Three edges inside the same frozen minute (the probe profile).
	for edge := range 3 {
		e.HandleEvent(eventFor("ping_test_failed"))
		waitFor(t, "first failing attempts settle", func() bool {
			return calls.Load() >= int32(policyCount) || edge > 0 && calls.Load() >= 1
		})
		// Give any unthrottled re-attempts a chance to run.
		time.Sleep(50 * time.Millisecond)
		_ = edge
	}
	if got := calls.Load(); got != policyCount {
		t.Fatalf("commitFn attempts in <60s = %d, want %d (one per policy, then failure backoff)", got, policyCount)
	}
	if got := e.Stats().Rejected; got != policyCount {
		t.Fatalf("Rejected=%d, want %d (one counted rejection per policy)", got, policyCount)
	}
	if got := budgetCount14724(e); got != 0 {
		t.Fatalf("budgetCount=%d, want 0 (non-promoting commits still refund, #14724)", got)
	}
	// Every failing policy is parked for replay after its backoff, not lost.
	if got := e.Stats().PendingDeferred; got != policyCount {
		t.Fatalf("PendingDeferred=%d, want %d (backed-off edges parked for replay)", got, policyCount)
	}
	for i := range policyCount {
		name := fmt.Sprintf("fail-%02d", i)
		if failedTrigger16774(e, name).IsZero() {
			t.Fatalf("policy %s has no failure-backoff anchor", name)
		}
	}

	// After the backoff expires the parked edges replay: exactly one more
	// attempt per policy (which fails again and re-arms the backoff).
	e.nowFn = func() time.Time { return base.Add(failureBackoff + time.Second) }
	e.drainDeferred()
	waitFor(t, "backoff-expired replay attempts", func() bool {
		return calls.Load() >= 2*policyCount
	})
	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != 2*policyCount {
		t.Fatalf("commitFn attempts after backoff expiry = %d, want %d (one replay per policy)", got, 2*policyCount)
	}
	if got := budgetCount14724(e); got != 0 {
		t.Fatalf("budgetCount=%d after replay failures, want 0 (refunded)", got)
	}
}

// #14724 starvation cell, preserved: a failing policy refunds its slot AND
// backs off, so a healthy policy still commits in the same minute — and
// keeps committing on later edges while the failing policy stays backed off.
//
// FAIL-ON-REVERT (refund): make refundGlobalCommit a no-op and the healthy
// policy's commit is budget-starved after four failing attempts.
// FAIL-ON-REVERT (backoff): drop armFailureBackoff and the healthy policy
// still commits, but the failing policy re-attempts on every edge.
func TestFailingPolicyDoesNotStarveHealthyPolicy16774(t *testing.T) {
	s := newStore(t)
	base := time.Unix(1_800_000_000, 0)
	var failCalls, okCalls atomic.Int32
	e := New(s, func(ctx context.Context, desc string) (*config.Config, error) {
		if strings.Contains(desc, "policy broken") {
			failCalls.Add(1)
			return nil, errors.New("simulated persistent commit failure")
		}
		okCalls.Add(1)
		return s.CommitWithDescriptionAs("system:event-engine", desc)
	})
	defer e.Close()
	e.nowFn = func() time.Time { return base }

	broken := &config.EventPolicy{Name: "broken", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name broken"}}
	healthy := &config.EventPolicy{Name: "healthy", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system domain-name healthy"}}
	applyPolicies9984(e, []*config.EventPolicy{broken, healthy})

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "healthy commits despite failing sibling", func() bool { return e.Stats().Committed >= 1 })
	waitFor(t, "broken rejected once", func() bool { return e.Stats().Rejected >= 1 })
	if got := s.ActiveConfig().System.DomainName; got != "healthy" {
		t.Fatalf("domain-name=%q, want healthy (healthy policy starved by failing sibling)", got)
	}
	if got := failCalls.Load(); got != 1 {
		t.Fatalf("broken commitFn attempts=%d, want 1", got)
	}
	if got := budgetCount14724(e); got != 1 {
		t.Fatalf("budgetCount=%d, want 1 (only the promoted healthy commit consumes)", got)
	}

	// Later edges in the same minute: broken stays backed off (no new
	// attempt), healthy is throttled only by its own commit cooldown.
	e.HandleEvent(eventFor("ping_test_failed"))
	e.HandleEvent(eventFor("ping_test_failed"))
	time.Sleep(100 * time.Millisecond)
	if got := failCalls.Load(); got != 1 {
		t.Fatalf("broken commitFn attempts after later edges=%d, want 1 (failure backoff)", got)
	}
	if failedTrigger16774(e, "broken").IsZero() {
		t.Fatal("broken policy has no failure-backoff anchor")
	}
	if !failedTrigger16774(e, "healthy").IsZero() {
		t.Fatal("healthy policy must not carry a failure-backoff anchor")
	}
}

// HA read-only deferral keeps its #14724 refund WITHOUT failure backoff:
// repeated read-only attempts hold zero budget slots, arm no backoff, and
// the action commits once after promotion.
//
// FAIL-ON-REVERT: arm the backoff on the read-only arm and the post-
// promotion replay is suppressed/parked instead of committing promptly.
func TestReadOnlyRefundArmsNoFailureBackoff16774(t *testing.T) {
	s := newStore(t)
	var readonly atomic.Bool
	readonly.Store(true)
	var calls atomic.Int32
	e := New(s, func(ctx context.Context, desc string) (*config.Config, error) {
		calls.Add(1)
		if readonly.Load() {
			return nil, fmt.Errorf("commit: %w", configstore.ErrClusterReadOnly)
		}
		return s.CommitWithDescriptionAs("system:event-engine", desc)
	})
	defer e.Close()
	pol := &config.EventPolicy{Name: "remediate", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name remediated"}}
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "multiple read-only attempts", func() bool { return calls.Load() >= 3 })
	if got := budgetCount14724(e); got != 0 {
		t.Fatalf("budgetCount=%d during read-only retries, want 0 (refunded)", got)
	}
	if !failedTrigger16774(e, "remediate").IsZero() {
		t.Fatal("read-only deferral armed the failure backoff; standby replay would be throttled")
	}
	if got := e.Stats().Rejected; got != 0 {
		t.Fatalf("Rejected=%d during read-only deferral, want 0", got)
	}

	readonly.Store(false)
	waitFor(t, "commit after promotion", func() bool { return e.Stats().Committed >= 1 })
	if got := budgetCount14724(e); got != 1 {
		t.Fatalf("budgetCount=%d after promoted commit, want 1", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Fatalf("host-name=%q, want remediated", got)
	}
}

// Recovery: once the failing policy's commit succeeds after the backoff,
// the failure anchor is cleared and the policy is throttled only by the
// ordinary commit cooldown.
func TestFailureBackoffClearsOnRecovery16774(t *testing.T) {
	s := newStore(t)
	base := time.Unix(1_800_000_000, 0)
	cur := base
	var fail atomic.Bool
	fail.Store(true)
	var calls atomic.Int32
	e := New(s, func(ctx context.Context, desc string) (*config.Config, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("simulated transient commit failure")
		}
		return s.CommitWithDescriptionAs("system:event-engine", desc)
	})
	defer e.Close()
	e.nowFn = func() time.Time { return cur }
	pol := &config.EventPolicy{Name: "remediate", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name remediated"}}
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "first failure", func() bool { return e.Stats().Rejected >= 1 })
	if failedTrigger16774(e, "remediate").IsZero() {
		t.Fatal("no failure-backoff anchor after commit failure")
	}
	// A fresh edge inside the backoff parks for replay; after expiry the
	// drain replays it and the recovered commit clears the anchor.
	cur = base.Add(5 * time.Second)
	e.HandleEvent(eventFor("ping_test_failed"))
	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("PendingDeferred=%d, want 1 (backed-off edge parked)", got)
	}
	fail.Store(false)
	cur = base.Add(failureBackoff + time.Second)
	e.drainDeferred()
	waitFor(t, "recovery commit", func() bool { return e.Stats().Committed >= 1 })
	if !failedTrigger16774(e, "remediate").IsZero() {
		t.Fatal("failure-backoff anchor not cleared after successful commit")
	}
	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Fatalf("host-name=%q, want remediated", got)
	}
	if got := budgetCount14724(e); got != 1 {
		t.Fatalf("budgetCount=%d after recovery commit, want 1", got)
	}
}
