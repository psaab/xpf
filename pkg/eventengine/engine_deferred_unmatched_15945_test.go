package eventengine

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #15945 (H22-01): a non-crossing event during cooldown must not be
// parked as a deferred edge, and a parked edge whose window decayed
// before drain must not replay.
//
// Pre-fix, evaluateEventMode computed matched := withinMatches(...),
// discarded it (_ = matched), and parked every cooldown event that had
// ThenCommands. drainDeferred then enqueued the parked action at
// cooldown expiry with no re-evaluation. A sub-threshold, over-ceiling,
// or already-latched event therefore fired the remediation once even
// though withinMatches was false when it was parked.
// clock15945 is a mutex-guarded fake clock: the deferred worker reads
// nowFn from its own goroutine while the test advances time.
type clock15945 struct {
	mu  sync.Mutex
	cur int64
}

func (c *clock15945) set(v int64) {
	c.mu.Lock()
	c.cur = v
	c.mu.Unlock()
}

func (c *clock15945) now(base time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return base.Add(time.Duration(c.cur) * time.Second)
}

// setupCooldown15945 returns an engine whose policy p has already
// committed once at t=0, so its cooldown anchor is armed.
func setupCooldown15945(t *testing.T, pol *config.EventPolicy) (*Engine, *clock15945) {
	t.Helper()
	s := newStore(t)
	base := time.Unix(1_800_000_000, 0)
	clk := &clock15945{}
	e := New(s, nil)
	t.Cleanup(func() { e.Close() })
	e.nowFn = func() time.Time { return clk.now(base) }
	applyPolicies9984(e, []*config.EventPolicy{pol})
	return e, clk
}
func waitCommitted15945(t *testing.T, e *Engine, n uint64) {
	t.Helper()
	waitFor(t, "commit", func() bool { return e.Stats().Committed >= n })
}

func waitCooldownArmed15945(t *testing.T, e *Engine) {
	t.Helper()
	waitFor(t, "cooldown armed", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		rt := e.runtime["p"]
		return rt != nil && !rt.lastTrigger().IsZero()
	})
}

// (a) Sustained latched level: trigger on 2 fires at the crossing; a
// third event during cooldown is the same level (already latched), so
// it must not park a replay. After cooldown, exactly 1 commit total.
func TestDeferredSustainedLatchedNoReplay15945(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "p",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: 2}},
		ThenCommands:  []string{"set system host-name recovered"},
	}
	e, cur := setupCooldown15945(t, pol)

	cur.set(0)
	e.HandleEvent(eventFor("ping_test_failed"))
	cur.set(1)
	e.HandleEvent(eventFor("ping_test_failed")) // crossing: fires
	waitCommitted15945(t, e, 1)
	waitCooldownArmed15945(t, e)

	cur.set(2)
	e.HandleEvent(eventFor("ping_test_failed")) // sustained, latched, in cooldown
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("sustained latched event parked a deferred edge: PendingDeferred=%d, want 0", got)
	}

	cur.set(40)
	e.drainDeferred()
	// Give the worker a bounded chance to (incorrectly) commit.
	time.Sleep(200 * time.Millisecond)
	if got := e.Stats().Committed; got != 1 {
		t.Fatalf("commits=%d, want exactly 1 (no deferred replay of a latched level)", got)
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("PendingDeferred=%d after drain, want 0", got)
	}
}

// (b) Over-ceiling / latched in-cooldown events park nothing, and a
// parked edge whose window decayed before drain does not replay. The
// first half drives the evaluate-time gate; the second half parks a
// synthetic edge (as pre-fix code would have) and lets its window
// age out before drain, exercising the drain-time re-evaluation.
func TestDeferredSubThresholdNoReplay15945(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "p",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: 3}},
		ThenCommands:  []string{"set system host-name recovered"},
	}
	e, cur := setupCooldown15945(t, pol)

	// Three events cross and fire once.
	for i := int64(0); i < 3; i++ {
		cur.set(i)
		e.HandleEvent(eventFor("ping_test_failed"))
	}
	waitCommitted15945(t, e, 1)
	waitCooldownArmed15945(t, e)

	// A fourth event during cooldown: count is 4 (still at/above the
	// threshold) but the edge is already latched, so withinMatches is
	// false. It must not park.
	cur.set(5)
	e.HandleEvent(eventFor("ping_test_failed"))
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("latched in-cooldown event parked: PendingDeferred=%d, want 0", got)
	}

	// Drain-replay guard, exercised directly: park a synthetic edge
	// whose window has since decayed below the threshold (only the
	// parked timestamp remains, aged out of a short window). Use a
	// second engine with a 10s window so decay is reachable.
	pol2 := &config.EventPolicy{
		Name:          "p",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 10, TriggerOn: 3}},
		ThenCommands:  []string{"set system host-name recovered2"},
	}
	e2, cur2 := setupCooldown15945(t, pol2)
	for i := int64(0); i < 3; i++ {
		cur2.set(i)
		e2.HandleEvent(eventFor("ping_test_failed"))
	}
	waitCommitted15945(t, e2, 1)
	waitCooldownArmed15945(t, e2)
	// Manually park an edge as the pre-fix code would have, with the
	// live semantic revision, then advance past both the window (10s)
	// and the cooldown (30s): at drain the count has decayed to 0, so
	// the re-evaluation must refuse the replay.
	e2.mu.Lock()
	rev := e2.semRev["p"]
	rt := e2.runtime["p"]
	rt.windows["ping_test_failed"] = []time.Time{time.Unix(1_800_000_000, 0).Add(5 * time.Second)}
	e2.mu.Unlock()
	e2.pendingMu.Lock()
	e2.pending.cooldown["p\x00ping_test_failed"] = deferredEdge{
		action:   plannedAction{policyName: "p", semRev: rev, event: "ping_test_failed"},
		evName:   "ping_test_failed",
		triggers: true,
	}
	e2.pendingMu.Unlock()
	e2.counters.pendingDeferred.Add(1)
	cur2.set(40)
	e2.drainDeferred()
	time.Sleep(200 * time.Millisecond)
	if got := e2.Stats().Committed; got != 1 {
		t.Fatalf("decayed parked edge replayed: commits=%d, want 1", got)
	}
	if got := e2.Stats().PendingDeferred; got != 0 {
		t.Fatalf("PendingDeferred=%d after drain, want 0", got)
	}
}

// (c) Control: a genuine crossing during cooldown still replays once.
// trigger on 2 with a 5s window: burst at t=40,41 crosses after the
// first commit's cooldown from t=0,1 — instead drive the canonical
// #15021 shape: no-within policy fires at t=0, a second event at t=5
// (genuine, matched) parks, and drain at t=40 commits it. This is the
// existing TestDeferredCooldownEdgeReplaysAndDirection15021 contract,
// restated here so the #15945 fix cannot silently drop it.
func TestDeferredGenuineCrossingStillReplays15945(t *testing.T) {
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

// (d) Control for the stale-policy mitigation: a parked edge whose
// policy is removed before drain must not commit (staleReason /
// drain-time revision check), and must not latch the successor.
func TestDeferredRemovedPolicyNoReplay15945(t *testing.T) {
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

	// Remove the policy before the cooldown expires.
	applyPolicies9984(e, nil)

	cur.set(40)
	e.drainDeferred()
	time.Sleep(200 * time.Millisecond)
	if got := e.Stats().Committed; got != 1 {
		t.Fatalf("removed policy replayed: commits=%d, want 1", got)
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("PendingDeferred=%d after drain, want 0", got)
	}
}

// #16848 recorded-verdict drain: an edge carrying a recorded NON-crossing
// verdict (matched=false, hasMatched=true) must NOT replay — even when the
// live window at drain time WOULD match. This guards the drain against
// falling back to the live-window re-check for real parked edges: had the
// drain called withinMatches here, count=3 >= TriggerOn=3 would replay and
// commits would reach 2.
func TestDeferredRecordedVerdictFalseNoReplay16848(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "p",
		Events:        []string{"ping_test_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: 3}},
		ThenCommands:  []string{"set system host-name recovered"},
	}
	e, cur := setupCooldown15945(t, pol)

	// Cross and fire once so the cooldown anchor is armed.
	for i := int64(0); i < 3; i++ {
		cur.set(i)
		e.HandleEvent(eventFor("ping_test_failed"))
	}
	waitCommitted15945(t, e, 1)
	waitCooldownArmed15945(t, e)

	// Park a recorded-false edge (same live revision). The window already
	// holds 3 in-window timestamps, so a live re-check would return true.
	e.mu.Lock()
	rev := e.semRev["p"]
	e.mu.Unlock()
	e.pendingMu.Lock()
	e.pending.cooldown["p\x00ping_test_failed"] = deferredEdge{
		action:     plannedAction{policyName: "p", semRev: rev, event: "ping_test_failed"},
		evName:     "ping_test_failed",
		triggers:   true,
		matched:    false,
		hasMatched: true,
	}
	e.pendingMu.Unlock()
	e.counters.pendingDeferred.Add(1)

	cur.set(40)
	e.drainDeferred()
	time.Sleep(200 * time.Millisecond)
	if got := e.Stats().Committed; got != 1 {
		t.Fatalf("recorded-false edge replayed: commits=%d, want 1 (drain must honour the parked verdict, not re-check the live window)", got)
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("PendingDeferred=%d after drain, want 0", got)
	}
}

// #16848 flap probe (R3-F16-01): a genuine `trigger on 1` crossing with a
// 10 s window (< 30 s cooldown) parked early in the cooldown must still
// replay at drain even though its window has fully decayed by then.
// fail (P commits) -> succeed (Q commits "link-up") -> re-fail inside P's
// cooldown parks P's crossing -> drain at t=31 must commit P, ending in
// "link-down-remediated". Pre-fix the drain re-checked the decayed window
// (count 0 < 1) and silently discarded the re-failure. The t=25 arm is the
// control: the parked event is still inside its 10 s window at the t=30+
// drain, so it replays both pre- and post-fix.
func TestDeferredTriggerOnShortWindowFlapReplays16848(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   int64
	}{
		{name: "re-fail early in cooldown (window decays)", at: 15},
		{name: "control re-fail late in cooldown (window live)", at: 25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			base := time.Unix(1_800_000_000, 0)
			clk := &clock15945{}
			e := New(s, nil)
			t.Cleanup(func() { e.Close() })
			e.nowFn = func() time.Time { return clk.now(base) }
			pPol := &config.EventPolicy{
				Name:          "p",
				Events:        []string{"ping_test_failed"},
				WithinClauses: []*config.EventWithin{{Seconds: 10, TriggerOn: 1}},
				ThenCommands:  []string{"set system host-name link-down-remediated"},
			}
			qPol := &config.EventPolicy{
				Name:         "q",
				Events:       []string{"ping_test_succeeded"},
				ThenCommands: []string{"set system host-name link-up"},
			}
			applyPolicies9984(e, []*config.EventPolicy{pPol, qPol})

			clk.set(0)
			e.HandleEvent(eventFor("ping_test_failed")) // P commits
			waitFor(t, "P first commit", func() bool { return e.Stats().Committed >= 1 })
			waitFor(t, "P cooldown armed", func() bool {
				e.mu.Lock()
				defer e.mu.Unlock()
				rt := e.runtime["p"]
				return rt != nil && !rt.lastTrigger().IsZero()
			})
			clk.set(5)
			e.HandleEvent(eventFor("ping_test_succeeded")) // Q commits "link-up"
			waitFor(t, "Q commit", func() bool { return e.Stats().Committed >= 2 })

			clk.set(tc.at)
			e.HandleEvent(eventFor("ping_test_failed")) // genuine re-fail crossing, parks
			if got := e.Stats().PendingDeferred; got == 0 {
				t.Fatalf("genuine re-fail was not parked: %+v", e.Stats())
			}
			clk.set(31)
			e.drainDeferred()
			waitFor(t, "P replay commit", func() bool { return e.Stats().Committed >= 3 })
			if got := s.ActiveConfig().System.HostName; got != "link-down-remediated" {
				t.Fatalf("host-name=%q, want %q (re-fail remediation must replay after cooldown)", got, "link-down-remediated")
			}
		})
	}
}

// A single policy combines a short trigger-on window with a longer
// trigger-until ceiling. The recorded crossing must survive decay of the
// short window at drain when the long window is still at its inclusive
// ceiling, but it must not replay after a parked event pushes that same
// long window over the ceiling.
func TestDeferredTriggerOnAndUntilCeilingReplay17708(t *testing.T) {
	for _, tc := range []struct {
		name        string
		overCeiling bool
		wantCommits uint64
	}{
		{name: "decayed trigger-on crossing replays at inclusive until ceiling", wantCommits: 2},
		{name: "decayed trigger-on crossing does not replay over until ceiling", overCeiling: true, wantCommits: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := &config.EventPolicy{
				Name:   "p",
				Events: []string{"ping_test_failed"},
				WithinClauses: []*config.EventWithin{
					{Seconds: 10, TriggerOn: 2},
					{Seconds: 60, TriggerUntil: 4},
				},
				ThenCommands: []string{"set system host-name recovered"},
			}
			e, cur := setupCooldown15945(t, pol)

			// The initial two-event trigger-on crossing commits at t=1.
			cur.set(0)
			e.HandleEvent(eventFor("ping_test_failed"))
			cur.set(1)
			e.HandleEvent(eventFor("ping_test_failed"))
			waitCommitted15945(t, e, 1)
			waitCooldownArmed15945(t, e)

			// The short window decays; the second event at t=21 is a fresh
			// trigger-on crossing during cooldown and parks at long-window
			// count 4 (the inclusive trigger-until ceiling).
			for _, sec := range []int64{20, 21} {
				cur.set(sec)
				e.HandleEvent(eventFor("ping_test_failed"))
			}
			if got := e.Stats().PendingDeferred; got != 1 {
				t.Fatalf("PendingDeferred=%d after recorded crossing, want 1", got)
			}
			if tc.overCeiling {
				cur.set(22)
				e.HandleEvent(eventFor("ping_test_failed")) // parked event raises long-window count to 5
			}

			cur.set(51) // after cooldown; short trigger-on window has decayed
			e.drainDeferred()
			if tc.wantCommits == 2 {
				waitCommitted15945(t, e, tc.wantCommits)
			} else {
				time.Sleep(200 * time.Millisecond)
			}
			if got := e.Stats().Committed; got != tc.wantCommits {
				t.Fatalf("commits=%d after drain, want %d (recorded trigger-on crossing must replay only at/below the live trigger-until ceiling)", got, tc.wantCommits)
			}
			if got := e.Stats().PendingDeferred; got != 0 {
				t.Fatalf("PendingDeferred=%d after drain, want 0", got)
			}
		})
	}
}
