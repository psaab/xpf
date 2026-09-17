package eventengine

import (
	"sort"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Regression tests for #2216. Both defects the issue describes were fixed by
// #2157 (prune-on-append in evaluateEvent + the single-worker action queue),
// but the package had no test that asserts the SPECIFIC #2216 invariants. These
// tests lock the fixes in by driving the real engine path (HandleEvent →
// evaluateEvent) and would FAIL if either fix were reverted to the pre-#2157
// behavior (prune gated behind the trigger-success path; per-probe
// EnterConfigure racing the config lock).

// windowLen returns the number of stored timestamps for (policy, event) under
// the engine lock — the quantity #2216 finding A says grows unbounded pre-fix.
func windowLen(e *Engine, policy, event string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	rt := e.runtime[policy]
	if rt == nil {
		return 0
	}
	return len(rt.windows[event])
}

// #2216 finding A, case 1 (no within-clause — the common case): events that
// match a no-within policy must not accumulate in the sliding window without
// bound. pruneWindow runs on every append (engine.go evaluateEvent) and bounds
// a no-within policy's window to the 60s default horizon, so feeding many events
// spread over a long simulated interval keeps only the most recent ~60s worth.
//
// FAIL-ON-REVERT: the pre-#2157 code called pruneWindows ONLY at the end of
// withinMatches, which a no-within policy reaches via the `return true` BEFORE
// that prune call — so the append at evaluate time was never pruned and the
// slice grew by one entry per event forever. Reverting prune-on-append makes
// this test observe ~1000 stored entries instead of the bounded count, failing
// the assertion below.
func TestWindow_NoWithinClauseBounded_2216A(t *testing.T) {
	pol := &config.EventPolicy{
		Name:   "no-within",
		Events: []string{"ping_probe_failed"},
		// No WithinClauses → 60s default prune horizon, never triggers a
		// within-gated path. No ThenCommands → HandleEvent classifies an empty
		// plan and enqueues nothing (no store needed); evaluateEvent still
		// records and prunes the window, which is all this test observes.
	}

	e := New(nil, nil)
	defer e.Close()

	// Deterministic clock: each event is 1 simulated second after the last.
	base := time.Unix(1_700_000_000, 0)
	var tick int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(tick) * time.Second) }
	applyPolicies9984(e, []*config.EventPolicy{pol})

	const events = 1000
	for tick = 0; tick < events; tick++ {
		e.HandleEvent(rpm.Event{Name: "ping_probe_failed", TestOwner: "o", TestName: "t"})
	}

	got := windowLen(e, "no-within", "ping_probe_failed")
	// With a 60s horizon and 1s spacing, at most ~61 entries can be within the
	// window at the final tick. Allow a small slop; the load-bearing assertion
	// is that it is bounded near the horizon, NOT proportional to `events`.
	const bound = 70
	if got > bound {
		t.Fatalf("no-within window holds %d timestamps after %d events; "+
			"prune-on-append must bound it near the 60s horizon (≤%d). "+
			"A value near %d means pruning is gated behind the trigger path (#2216A regression).",
			got, events, bound, events)
	}
	if got == 0 {
		t.Fatalf("window is empty; expected the most-recent ~60s of events to be retained")
	}
}

// #2216 finding A, case 2 (within N { trigger on M } that never reaches M):
// events below the trigger threshold must still be pruned to the configured
// window horizon, not retained forever.
//
// FAIL-ON-REVERT: pre-#2157, the trigger-on branch returned false BEFORE the
// prune call at the end of withinMatches, so a policy whose threshold is never
// met accumulated every event. Here TriggerOn=100 within a 30s window is never
// reached at 1 event/sec (only ~30 land in any 30s window), so the policy never
// triggers; prune-on-append must still bound the slice to the 30s horizon.
func TestWindow_BelowTriggerThresholdBounded_2216A(t *testing.T) {
	pol := &config.EventPolicy{
		Name:   "never-triggers",
		Events: []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{
			{Seconds: 30, TriggerOn: 100}, // 100 events in 30s — never met at 1/s
		},
		// No ThenCommands → no enqueue; we only observe the window.
	}
	e := New(nil, nil)
	defer e.Close()

	base := time.Unix(1_700_000_000, 0)
	var tick int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(tick) * time.Second) }
	applyPolicies9984(e, []*config.EventPolicy{pol})

	const events = 1000
	triggered := 0
	for tick = 0; tick < events; tick++ {
		got := e.evaluateEvent(rpm.Event{Name: "ping_probe_failed", TestOwner: "o", TestName: "t"})
		triggered += len(got)
	}
	if triggered != 0 {
		t.Fatalf("policy triggered %d times; TriggerOn=100 within 30s at 1/s must never fire", triggered)
	}

	got := windowLen(e, "never-triggers", "ping_probe_failed")
	const bound = 40 // 30s horizon + slop
	if got > bound {
		t.Fatalf("below-threshold window holds %d timestamps after %d events; "+
			"prune-on-append must bound it to the 30s horizon (≤%d), not retain "+
			"every event (#2216A regression).",
			got, events, bound)
	}
}

// #2216 finding B: a SINGLE event that matches N>1 policies must run EVERY
// matching policy's actions — none silently dropped. The issue's scenario is a
// link/probe event that trips several policies at once; pre-#2157 each matched
// policy called executeCommands directly off the (shared) caller goroutine and
// raced for the config lock, so the first to EnterConfigure committed and the
// rest hit "configuration is locked by another user" and applied nothing.
//
// Here three policies all bind to the SAME event name, each appending a DISTINCT
// additive value (system domain-search). One HandleEvent enqueues all three
// actions onto the single worker, which applies them serially; all three must
// commit and all three distinct values must be present in the final active
// config.
//
// FAIL-ON-REVERT: reverting to per-policy executeCommands-without-the-queue
// makes the three actions race the config lock from the one HandleEvent
// goroutine; only one commits and DomainSearch holds a single entry, failing the
// "all three present" assertion.
func TestConcurrent_OneEventMatchesManyPolicies_2216B(t *testing.T) {
	s := newStore(t)
	const n = 3
	want := []string{"p0.example", "p1.example", "p2.example"}
	policies := make([]*config.EventPolicy, 0, n)
	for i := 0; i < n; i++ {
		policies = append(policies, &config.EventPolicy{
			Name:         "policy" + string(rune('0'+i)),
			Events:       []string{"link_down"}, // SAME event for all three
			ThenCommands: []string{"set system domain-search " + want[i]},
		})
	}
	e := New(s, nil)
	defer e.Close()
	applyPolicies9984(e, policies)

	// One event matches all three policies.
	e.HandleEvent(rpm.Event{Name: "link_down", TestOwner: "o", TestName: "t"})

	// All three distinct actions must commit (serialized through the worker).
	waitFor(t, "all three commits", func() bool { return e.Stats().Committed >= n })
	if got := e.Stats().Committed; got != n {
		t.Fatalf("Committed=%d; one event matched %d policies and EVERY matching "+
			"policy's action must commit (#2216B: no all-but-one drop)", got, n)
	}

	got := append([]string(nil), s.ActiveConfig().System.DomainSearch...)
	sort.Strings(got)
	wantSorted := append([]string(nil), want...)
	sort.Strings(wantSorted)
	if len(got) != n {
		t.Fatalf("domain-search = %v (len %d); want all %d distinct policy actions %v "+
			"present — a dropped policy means its action never committed (#2216B regression)",
			got, len(got), n, wantSorted)
	}
	for i := range wantSorted {
		if got[i] != wantSorted[i] {
			t.Fatalf("domain-search = %v; want %v — every matching policy's distinct "+
				"action must be applied (#2216B)", got, wantSorted)
		}
	}
}
