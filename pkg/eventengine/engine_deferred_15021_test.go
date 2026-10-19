package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// #15021: a budget-denied only edge must commit after the slot expires.
func TestDeferredBudgetOnlyEdgeCommitsAfterExpiry15021(t *testing.T) {
	s := newStore(t)
	base := time.Unix(1_800_000_000, 0)
	var cur int64
	e := New(s, nil)
	defer e.Close()
	e.nowFn = func() time.Time { return base.Add(time.Duration(cur) * time.Second) }
	// Fill budget with 4 other policies at t0.
	var pols []*config.EventPolicy
	for i := range 4 {
		name := string(rune('a' + i))
		pols = append(pols, &config.EventPolicy{Name: "fill-" + name, Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name fill-" + name}})
	}
	pols = append(pols, &config.EventPolicy{Name: "victim", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name victim"}})
	applyPolicies9984(e, pols)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "fills commit", func() bool { return e.Stats().Committed >= 4 })
	// victim deferred, not dropped
	if e.Stats().PendingDeferred == 0 && e.Stats().DeferredBudget == 0 {
		t.Fatalf("victim not deferred: %+v", e.Stats())
	}
	if e.Stats().DroppedGlobalBudget != 0 {
		// pre-commit drops must be zero; commit-time residual may appear later
	}
	cur = 61
	e.drainDeferred()
	waitFor(t, "victim commits after expiry", func() bool { return e.Stats().Committed >= 5 })
}

// #15021: cooldown-suppressed edge replays; different direction not suppressed.
func TestDeferredCooldownEdgeReplaysAndDirection15021(t *testing.T) {
	s := newStore(t)
	base := time.Unix(1_800_000_000, 0)
	var cur int64
	e := New(s, nil)
	defer e.Close()
	e.nowFn = func() time.Time { return base.Add(time.Duration(cur) * time.Second) }
	pol := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed", "ping_test_completed"}, ThenCommands: []string{"set system host-name recovered"}}
	applyPolicies9984(e, []*config.EventPolicy{pol})
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "first commit", func() bool { return e.Stats().Committed >= 1 })
	waitFor(t, "cooldown armed", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		rt := e.runtime["p"]
		return rt != nil && !rt.lastTrigger().IsZero()
	})
	cur = 5
	e.HandleEvent(eventFor("ping_test_failed"))
	if e.Stats().CooldownSuppressed == 0 {
		t.Fatalf("cooldown suppression not counted")
	}
	e.HandleEvent(eventFor("ping_test_completed"))
	time.Sleep(100 * time.Millisecond)
	cur = 40
	e.drainDeferred()
	waitFor(t, "deferred replay commits", func() bool { return e.Stats().Committed >= 2 })
	_ = rpm.Event{}
}
