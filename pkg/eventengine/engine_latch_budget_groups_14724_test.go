package eventengine

// engine_latch_budget_groups_14724_test.go — #14724 (D19-02).
//
// evaluateEvent arms rt.onLatched on a trigger-on crossing. Every terminal
// exit that did NOT commit must release it, refund any reserved global
// budget slot, and groups-wrapped security/firewall paths must classify
// critical. Pre-fix, the stale drop, the permanent-rejection return, the
// HandleEvent pre-enqueue continues, and a failed commitFn all leaked.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/rpm"
)

func budgetCount14724(e *Engine) int {
	e.budgetMu.Lock()
	defer e.budgetMu.Unlock()
	return e.budgetCount
}

func latch14724(e *Engine, pol, ev string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	rt := e.runtime[pol]
	if rt == nil {
		return false
	}
	return rt.onLatched[ev]
}

// (a) Transient commitFn (nil, err): latch released, budget refunded, and a
// sustained fault re-fires after recovery.
func TestCommitFailureReleasesLatchAndRefundsBudget14724(t *testing.T) {
	s := newStore(t)
	var fail atomic.Bool
	fail.Store(true)
	var calls atomic.Int32
	e := New(s, func(ctx context.Context, desc string) (*config.Config, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("simulated transient commit error")
		}
		return s.CommitWithDescriptionAs("system:event-engine", desc)
	})
	defer e.Close()
	pol := &config.EventPolicy{
		Name:          "remediate",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: 2}},
		ThenCommands:  []string{"set system host-name remediated"},
	}
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "rejected after transient commit failure", func() bool { return e.Stats().Rejected >= 1 })
	if latch14724(e, "remediate", "ping_test_failed") {
		t.Fatal("edge latch still armed after transient commit failure")
	}
	if got := budgetCount14724(e); got != 0 {
		t.Fatalf("budgetCount=%d after failed commit, want 0 (refunded)", got)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("commitCalls=%d, want 1", got)
	}
	// Recovery: sustained fault (count stays >= threshold) must re-fire.
	fail.Store(false)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "commit after recovery", func() bool { return e.Stats().Committed >= 1 })
	if got := calls.Load(); got != 2 {
		t.Fatalf("commitCalls=%d after recovery, want 2 (policy wedged)", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Fatalf("host-name=%q, want remediated", got)
	}
	if got := budgetCount14724(e); got != 1 {
		t.Fatalf("budgetCount=%d after successful commit, want 1", got)
	}
}

// (b) Cooldown-stale drop: latch released but cooldown still throttles.
// A1 commits and arms cooldown; A2 was armed by a genuine re-crossing while
// A1 was in flight and is then dropped stale (cooldown active). After the
// cooldown expires a sustained event must re-fire; before expiry it must not.
func TestCooldownStaleDropReleasesLatchButCooldownThrottles14724(t *testing.T) {
	s := newStore(t)
	var clock atomic.Int64
	base := time.Unix(1_800_000_000, 0)
	clock.Store(base.UnixNano())
	e := New(s, nil)
	defer e.Close()
	e.nowFn = func() time.Time { return time.Unix(0, clock.Load()) }
	e.retryInitial = time.Millisecond
	e.retryMax = time.Millisecond
	e.retryDeadline = 5 * time.Second
	pol := &config.EventPolicy{
		Name:          "remediate",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: 2}},
		ThenCommands:  []string{"set system host-name remediated"},
	}
	applyPolicies9984(e, []*config.EventPolicy{pol})

	// Hold the lock so A1 stays in-flight in the worker.
	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	// t=0: crossing -> A1 queued/in-flight, latch armed.
	e.HandleEvent(eventFor("ping_test_failed"))
	e.HandleEvent(eventFor("ping_test_failed"))
	// Advance past window decay? Instead force re-crossing: prune window by
	// moving clock beyond 300s window then back? Simpler: directly verify
	// stale-drop latch release through runAction seam below after A1 commits.
	// Release lock -> A1 commits, arms cooldown (lastTrigger = t0).
	if !s.ExitConfigureSession("operator") {
		t.Fatal("release lock")
	}
	waitFor(t, "A1 commit", func() bool { return e.Stats().Committed >= 1 })

	// A2: simulate the action that evaluateEvent armed before A1 committed.
	// Its latch is currently armed by A1's crossing; staleReason will say
	// "cooldown active". Run it directly.
	ops, ok := e.classifyPlan(pol)
	if !ok {
		t.Fatal("classifyPlan")
	}
	// Re-arm latch as evaluateEvent would for A2's crossing.
	e.mu.Lock()
	e.runtime["remediate"].onLatched["ping_test_failed"] = true
	e.mu.Unlock()
	a2 := plannedAction{
		policyName: pol.Name,
		semRev:     policySemanticRevision(pol),
		event:      "ping_test_failed",
		testOwner:  "owner",
		testName:   "tname",
		ops:        ops,
	}
	e.runAction(a2)
	if got := e.Stats().DroppedStale; got < 1 {
		t.Fatalf("DroppedStale=%d, want >=1 (fixture did not reach stale drop)", got)
	}
	if latch14724(e, "remediate", "ping_test_failed") {
		t.Fatal("edge latch still armed after cooldown-stale drop")
	}
	// Cooldown still throttles: a sustained event now (within 30s) must NOT fire.
	committedBefore := e.Stats().Committed
	e.HandleEvent(eventFor("ping_test_failed"))
	// Give worker a chance; no new commit should appear.
	time.Sleep(50 * time.Millisecond)
	if got := e.Stats().Committed; got != committedBefore {
		t.Fatalf("Committed=%d within cooldown, want %d (cooldown not throttling)", got, committedBefore)
	}
	// After cooldown expiry the sustained fault re-fires.
	clock.Store(base.Add(31 * time.Second).UnixNano())
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "post-cooldown re-fire", func() bool { return e.Stats().Committed >= committedBefore+1 })
}

// (c) Read-only retry loop does not consume budget across iterations.
// commitFn returns (nil, ErrClusterReadOnly) wrapping the sentinel; each
// applyOnce reserves then fails. After promotion the action commits once
// and exactly one budget slot is held.
func TestReadOnlyRetryDoesNotConsumeBudget14724(t *testing.T) {
	s := newStore(t)
	var readonly atomic.Bool
	readonly.Store(true)
	var calls atomic.Int32
	e := New(s, func(ctx context.Context, desc string) (*config.Config, error) {
		calls.Add(1)
		if readonly.Load() {
			return nil, configstore.ErrClusterReadOnly
		}
		return s.CommitWithDescriptionAs("system:event-engine", desc)
	})
	defer e.Close()
	// Store itself stays writable so EnterConfigure/Set succeed and the
	// failure surfaces only at commitFn (reserve-then-fail seam).
	pol := &config.EventPolicy{
		Name:         "remediate",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name remediated"},
	}
	applyPolicies9984(e, []*config.EventPolicy{pol})
	e.HandleEvent(eventFor("ping_test_failed"))
	// Wait for several read-only retries.
	waitFor(t, "multiple read-only commit attempts", func() bool { return calls.Load() >= 3 })
	if got := budgetCount14724(e); got != 0 {
		t.Fatalf("budgetCount=%d during read-only retries, want 0 (each retry leaked a slot)", got)
	}
	if got := e.Stats().Rejected; got != 0 {
		t.Fatalf("Rejected=%d during deferral, want 0", got)
	}
	// Promote: gate already open (store writable), flip commitFn to succeed.
	readonly.Store(false)
	e.SetPublishEnabled(true)
	waitFor(t, "commit after promotion", func() bool { return e.Stats().Committed >= 1 })
	if got := budgetCount14724(e); got != 1 {
		t.Fatalf("budgetCount=%d after promoted commit, want exactly 1", got)
	}
	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Fatalf("host-name=%q, want remediated", got)
	}
}

// HandleEvent pre-enqueue: classify-reject and empty-plan release the latch
// so a later corrected generation is not the only re-fire path; sustained
// events re-attempt (counter climbs) rather than wedging silently.
// This reverses the #6810 deliberate-keep decision per #14724.
func TestHandleEventPreEnqueueReleasesLatch14724(t *testing.T) {
	t.Run("classify-reject", func(t *testing.T) {
		e, at := newInertEngine6810(t)
		const event = "ping_probe_failed"
		bad := edgePolicy6810("broken", event, 2)
		bad.ThenCommands = []string{"reboot the router"}
		applyPolicies9984(e, []*config.EventPolicy{bad})
		at(0)
		e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
		at(1)
		e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
		if got := e.Stats().Rejected; got != 1 {
			t.Fatalf("Rejected=%d, want 1", got)
		}
		if latch14724(e, "broken", event) {
			t.Fatal("latch still armed after classify-reject")
		}
		at(2)
		e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
		if got := e.Stats().Rejected; got != 2 {
			t.Fatalf("Rejected=%d after sustained event, want 2 (re-attempted)", got)
		}
	})
	t.Run("empty-plan", func(t *testing.T) {
		e, at := newInertEngine6810(t)
		const event = "ping_probe_failed"
		empty := edgePolicy6810("noop", event, 2)
		empty.ThenCommands = nil
		applyPolicies9984(e, []*config.EventPolicy{empty})
		at(0)
		e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
		at(1)
		e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
		if latch14724(e, "noop", event) {
			t.Fatal("latch still armed after empty plan")
		}
		at(2)
		e.HandleEvent(rpm.Event{Name: event, TestOwner: "o", TestName: "t"})
		// No counters, no queue — just latch released (re-evaluated).
		if st := e.Stats(); st.Rejected != 0 || st.DroppedQueueFull != 0 {
			t.Fatalf("empty plan counters: %+v", st)
		}
		if queued := drainPolicyNames(e); len(queued) != 0 {
			t.Fatalf("empty plan queued %v", queued)
		}
	})
}

// (d) criticalConfigPath groups cases.
func TestCriticalConfigPathGroups14724(t *testing.T) {
	cases := []struct {
		path []string
		want bool
	}{
		{[]string{"security", "policies"}, true},
		{[]string{"firewall", "family"}, true},
		{[]string{"system", "host-name"}, false},
		{[]string{"groups", "g1", "security", "policies"}, true},
		{[]string{"groups", "g1", "firewall", "family"}, true},
		{[]string{"groups", "g1", "system", "host-name"}, false},
		{[]string{"groups"}, false},
		{[]string{"groups", "g1"}, false},
		{[]string{"apply-groups", "g1"}, false},
		{[]string{"apply-groups-except", "g1"}, false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := criticalConfigPath(tc.path); got != tc.want {
			t.Errorf("criticalConfigPath(%v)=%v, want %v", tc.path, got, tc.want)
		}
	}
	// End-to-end via classifyPlan.
	e := New(nil, nil)
	defer e.Close()
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		{"set groups g1 security policies default-policy deny-all", true},
		{"set groups g1 firewall family inet filter f term t then accept", true},
		{"set groups g1 system host-name x", false},
		{"delete groups g1 security zones security-zone trust", true},
		{"set apply-groups g1", false},
	} {
		ops, ok := e.classifyPlan(&config.EventPolicy{Name: "p", ThenCommands: []string{tc.cmd}})
		if !ok || len(ops) != 1 {
			t.Fatalf("classifyPlan(%q) ok=%v ops=%d", tc.cmd, ok, len(ops))
		}
		if ops[0].critical != tc.want {
			t.Errorf("classifyPlan(%q) critical=%v, want %v", tc.cmd, ops[0].critical, tc.want)
		}
	}
}
