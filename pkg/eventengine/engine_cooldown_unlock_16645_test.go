package eventengine

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16645: maybeDeferCooldownLocked released e.mu mid-loop to take pendingMu,
// so a concurrent same-name redefinition landing in the unlock window paired
// the OLD policy's commands/plant class with the NEW semantic revision. The
// later triggered policy (and the parked edge) then passed the #3750
// "policy redefined" gate and the retracted batch committed once.
//
// Fix: capture cooldown parks under e.mu and insert them under pendingMu
// only after evaluate returns; e.mu is never released inside the loop.
//
// Interleave: p1 and p2 both list ping_test_failed and both are in cooldown.
// The test holds pendingMu, so pre-fix p1's park blocks with e.mu RELEASED;
// ApplyWithConfig then redefines p2 and the old loop stamps old p2 with the
// new revision (and parks it stamped new, so staleReason passes). Post-fix
// evaluate holds e.mu throughout, so the redefinition can only land after
// evaluate and p2's park carries the OLD revision, which staleReason then
// rejects as "policy redefined".
func TestEvaluateCooldownUnlockRedefinition16645(t *testing.T) {
	s := newStore(t)
	base := time.Unix(1_800_000_000, 0)
	clk := &clock15945{}
	e := New(s, nil)
	defer e.Close()
	e.nowFn = func() time.Time { return clk.now(base) }

	p1Old := &config.EventPolicy{Name: "p1", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name p1-old"}}
	p2Old := &config.EventPolicy{Name: "p2", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name p2-old"}}
	p2New := &config.EventPolicy{Name: "p2", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name p2-new"}}

	applyPolicies9984(e, []*config.EventPolicy{p1Old, p2Old})
	e.mu.Lock()
	oldRevP2 := e.semRev["p2"]
	e.mu.Unlock()
	if oldRevP2 == "" {
		t.Fatal("p2 has no semantic revision after Apply")
	}

	// Commit p1 and p2 once so both cooldowns are armed; the next event is
	// then cooldown-suppressed for both.
	clk.set(0)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "initial commits", func() bool { return e.Stats().Committed >= 2 })
	waitFor(t, "cooldowns armed", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, n := range []string{"p1", "p2"} {
			rt := e.runtime[n]
			if rt == nil || rt.lastTrigger().IsZero() {
				return false
			}
		}
		return true
	})

	// Hold pendingMu so that, pre-fix, p1's park blocks while holding no
	// e.mu (the unlock window) and the redefinition below can land in it;
	// post-fix, evaluate never touches pendingMu until it has released
	// e.mu, so the redefinition cannot interleave with the loop at all.
	e.pendingMu.Lock()
	var pendingOnce sync.Once
	releasePending := func() { pendingOnce.Do(e.pendingMu.Unlock) }
	defer releasePending()

	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		applyPolicies9984(e, []*config.EventPolicy{p1Old, p2New})
	}()

	// Run evaluate on this goroutine. Pre-fix it blocks on pendingMu with
	// e.mu released, letting Apply land first; post-fix it holds e.mu
	// throughout, so Apply waits and evaluate's post-loop insert blocks
	// on pendingMu. A watchdog releases pendingMu after 2s either way, so
	// neither generation deadlocks: pre-fix the release lets the old loop
	// proceed to its (buggy) stamp; post-fix it lets the insert land.
	go func() {
		select {
		case <-applyDone:
			// Pre-fix: Apply already landed in the unlock window; still
			// release so the blocked park can proceed.
			time.Sleep(100 * time.Millisecond)
			releasePending()
		case <-time.After(2 * time.Second):
			releasePending()
		}
	}()
	clk.set(5)
	triggered := e.evaluateEvent(eventFor("ping_test_failed"))
	releasePending()
	select {
	case <-applyDone:
	case <-time.After(10 * time.Second):
		t.Fatal("redefinition Apply did not complete")
	}

	for _, tp := range triggered {
		if tp.pol == p2Old && tp.semRev != oldRevP2 {
			t.Fatalf("old p2 paired with new revision: semRev=%q want old %q", tp.semRev, oldRevP2)
		}
		if tp.pol.Name == "p2" {
			t.Fatalf("p2 must not trigger from a cooldown-suppressed evaluation, got %+v", tp)
		}
	}

	// pendingMu and Apply are settled above; inspect the parked edges.

	// Both p1 and p2 edges must be parked, and every parked action must
	// carry the revision of the generation that produced it.
	e.pendingMu.Lock()
	parked := make(map[string]deferredEdge, len(e.pending.cooldown))
	for k, v := range e.pending.cooldown {
		parked[k] = v
	}
	e.pendingMu.Unlock()

	p2Edge, ok := parked["p2\x00ping_test_failed"]
	if !ok {
		t.Fatalf("p2 cooldown edge not parked; parked keys=%v", keysOf16645(parked))
	}
	if p2Edge.action.semRev != oldRevP2 {
		t.Fatalf("parked p2 action semRev=%q, want old generation %q; a stale batch would pass the #3750 redefined gate", p2Edge.action.semRev, oldRevP2)
	}
	if len(p2Edge.action.ops) == 0 {
		t.Fatal("parked p2 action has no ops")
	}
	// The worker commit-time backstop must reject the parked old batch now
	// that the redefinition has landed.
	if reason := e.staleReason(p2Edge.action); reason != "policy redefined" {
		t.Fatalf("staleReason(parked old p2) = %q, want %q", reason, "policy redefined")
	}
	if _, ok := parked["p1\x00ping_test_failed"]; !ok {
		t.Fatalf("p1 cooldown edge not parked; parked keys=%v", keysOf16645(parked))
	}
}

func keysOf16645(m map[string]deferredEdge) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// Control: without any concurrent redefinition, a cooldown-parked edge still
// replays after the cooldown (#15021), i.e. the collect-then-insert refactor
// did not drop the deferral path.
func TestEvaluateCooldownParkControl16645(t *testing.T) {
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name recovered"},
	}
	e, cur := setupCooldown15945(t, pol)

	cur.set(0)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitCommitted15945(t, e, 1)
	waitCooldownArmed15945(t, e)

	cur.set(5)
	e.HandleEvent(eventFor("ping_test_failed"))
	if got := e.Stats().PendingDeferred; got == 0 {
		t.Fatalf("genuine in-cooldown event was not parked: %+v", e.Stats())
	}

	cur.set(40)
	e.drainDeferred()
	waitCommitted15945(t, e, 2)
}
