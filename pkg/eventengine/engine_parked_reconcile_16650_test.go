package eventengine

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16650: parked-edge maps are keyed by policy name (cooldown also by
// event) and were not reconciled on Apply. A predecessor's parked entry
// occupied the key across a same-name redefine, so the successor's
// in-cooldown edge found the key taken in maybeDeferCooldownLocked and
// was silently dropped; drain then deleted the stale entry on semRev
// mismatch. Apply now purges parked entries whose stamped semRev no
// longer matches the live revision (gauge-adjusted).

type clock16650 struct {
	mu  sync.Mutex
	cur int64
}

func (c *clock16650) set(v int64) {
	c.mu.Lock()
	c.cur = v
	c.mu.Unlock()
}

func (c *clock16650) now(base time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return base.Add(time.Duration(c.cur) * time.Second)
}

func setup16650(t *testing.T, pol *config.EventPolicy) (*Engine, *clock16650) {
	t.Helper()
	s := newStore(t)
	base := time.Unix(1_800_000_000, 0)
	clk := &clock16650{}
	e := New(s, nil)
	t.Cleanup(func() { e.Close() })
	e.nowFn = func() time.Time { return clk.now(base) }
	applyPolicies9984(e, []*config.EventPolicy{pol})
	return e, clk
}

func waitCooldown16650(t *testing.T, e *Engine) {
	t.Helper()
	waitFor(t, "cooldown armed", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		rt := e.runtime["p"]
		return rt != nil && !rt.lastTrigger().IsZero()
	})
}

func rev16650(e *Engine, name string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.semRev[name]
}

// DEFECT arm (fails pre-fix): R1 commits, R1 edge parks, redefine to R2
// (different ThenCommands => different semRev), R2 fires and commits,
// R2 edge parks and must replay once at cooldown expiry.
func TestParkedEdgeRedefineCooldownReplays16650(t *testing.T) {
	polR1 := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name r1"}}
	e, cur := setup16650(t, polR1)

	cur.set(0)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "R1 commit", func() bool { return e.Stats().Committed >= 1 })
	waitCooldown16650(t, e)

	cur.set(5)
	e.HandleEvent(eventFor("ping_test_failed")) // R1 edge parks
	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("R1 edge not parked: PendingDeferred=%d, want 1", got)
	}

	// Redefine at t=10: new ThenCommands => new semRev, fresh runtime.
	polR2 := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name r2"}}
	cur.set(10)
	applyPolicies9984(e, []*config.EventPolicy{polR2})
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("stale R1 parked entry survived redefine: PendingDeferred=%d, want 0 (purged on Apply)", got)
	}

	// Successor fires (re-armed, no cooldown anchor) and commits.
	cur.set(12)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "R2 commit", func() bool { return e.Stats().Committed >= 2 })
	waitCooldown16650(t, e)

	// Successor edge during its cooldown must park, not be swallowed.
	cur.set(15)
	e.HandleEvent(eventFor("ping_test_failed"))
	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("R2 edge swallowed by predecessor entry: PendingDeferred=%d, want 1; stats=%+v", got, e.Stats())
	}
	// Parked entry must carry R2's revision / commands, not R1's.
	e.pendingMu.Lock()
	de, ok := e.pending.cooldown["p\x00ping_test_failed"]
	e.pendingMu.Unlock()
	if !ok {
		t.Fatalf("no parked cooldown entry for successor")
	}
	if de.action.semRev != rev16650(e, "p") {
		t.Fatalf("parked entry semRev is stale (predecessor), want successor rev")
	}
	if len(de.action.ops) == 0 {
		t.Fatalf("parked successor entry has no ops")
	}

	// Drain after cooldown: successor edge replays exactly once.
	cur.set(50)
	e.drainDeferred()
	waitFor(t, "R2 deferred replay", func() bool { return e.Stats().Committed >= 3 })
	time.Sleep(150 * time.Millisecond)
	if got := e.Stats().Committed; got != 3 {
		t.Fatalf("commits=%d, want exactly 3 (R1, R2, R2 replay)", got)
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("PendingDeferred=%d after drain, want 0", got)
	}
}

// Control arm: unchanged policy re-Applied (same semRev, e.g. engine's
// own remediation commit re-entering Apply) must keep its parked entry.
func TestParkedEdgeUnchangedApplyKeepsEntry16650(t *testing.T) {
	pol := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name recovered"}}
	e, cur := setup16650(t, pol)

	cur.set(0)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "first commit", func() bool { return e.Stats().Committed >= 1 })
	waitCooldown16650(t, e)

	cur.set(5)
	e.HandleEvent(eventFor("ping_test_failed"))
	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("edge not parked: PendingDeferred=%d, want 1", got)
	}

	// Re-Apply identical policy (fresh struct, same semantics).
	applyPolicies9984(e, []*config.EventPolicy{{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name recovered"}}})
	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("unchanged Apply purged parked entry: PendingDeferred=%d, want 1", got)
	}

	cur.set(40)
	e.drainDeferred()
	waitFor(t, "deferred replay", func() bool { return e.Stats().Committed >= 2 })
}

// Budget arm: a stale budget hold for a redefined/removed policy must
// be purged on Apply so deferBudget can park the successor's action.
func TestParkedBudgetRedefinePurged16650(t *testing.T) {
	polR1 := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name r1"}}
	e, _ := setup16650(t, polR1)

	// Park a budget hold stamped with R1's revision, gauge=1.
	e.pendingMu.Lock()
	if e.pending.budget == nil {
		e.pending.budget = make(map[string]plannedAction)
	}
	e.pending.budget["p"] = plannedAction{policyName: "p", semRev: rev16650(e, "p"), event: "ping_test_failed"}
	e.pendingMu.Unlock()
	e.counters.pendingDeferred.Add(1)
	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("setup: PendingDeferred=%d, want 1", got)
	}

	// Redefine: stale budget hold must be purged and gauge decremented.
	polR2 := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name r2"}}
	applyPolicies9984(e, []*config.EventPolicy{polR2})
	e.pendingMu.Lock()
	_, stillThere := e.pending.budget["p"]
	e.pendingMu.Unlock()
	if stillThere {
		t.Fatalf("stale budget hold survived redefine (deferBudget would refuse successor)")
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("gauge not adjusted after budget purge: PendingDeferred=%d, want 0", got)
	}

	// Successor can now park its budget-denied action.
	a2 := plannedAction{policyName: "p", semRev: rev16650(e, "p"), event: "ping_test_failed"}
	if !e.deferBudget(a2) {
		t.Fatalf("deferBudget refused successor after purge")
	}
	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("successor budget hold not counted: PendingDeferred=%d, want 1", got)
	}

	// Removed policy: its parked cooldown+budget entries purge too.
	e.pendingMu.Lock()
	e.pending.cooldown["p\x00ping_test_failed"] = deferredEdge{action: a2, evName: "ping_test_failed", triggers: true}
	e.pendingMu.Unlock()
	e.counters.pendingDeferred.Add(1) // now budget(1)+cooldown(1)=2
	if got := e.Stats().PendingDeferred; got != 2 {
		t.Fatalf("setup2: PendingDeferred=%d, want 2", got)
	}
	applyPolicies9984(e, nil)
	e.pendingMu.Lock()
	nb, nc := len(e.pending.budget), len(e.pending.cooldown)
	e.pendingMu.Unlock()
	if nb != 0 || nc != 0 {
		t.Fatalf("removed policy parked entries survived: budget=%d cooldown=%d, want 0/0", nb, nc)
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("gauge after removal purge: PendingDeferred=%d, want 0", got)
	}
}
