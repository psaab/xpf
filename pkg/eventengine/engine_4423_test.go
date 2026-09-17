package eventengine

import (
	"context"
	"log/slog"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// #4423 M3: multiple `within` clauses are combined with AND — the policy fires
// only when EVERY clause passes. This locks in (and documents) the semantics.
func TestWithinMultipleClausesAreANDed(t *testing.T) {
	// Clause 1: trigger on 2 within 60s (satisfiable after 2 events).
	// Clause 2: trigger on 5 within 60s (needs 5 events).
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"e"},
		WithinClauses: []*config.EventWithin{
			{Seconds: 60, TriggerOn: 2},
			{Seconds: 60, TriggerOn: 5},
		},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})
	base := time.Unix(1_000_000, 0)
	i := 0
	e.nowFn = func() time.Time { return base.Add(time.Duration(i) * time.Second) }

	fire := func() int {
		i++
		return len(e.evaluateEvent(rpm.Event{Name: "e"}))
	}

	// Events 1..4: clause 1 satisfied at event 2, but clause 2 (needs 5) is not,
	// so the AND is unsatisfied and nothing fires.
	for n := 1; n <= 4; n++ {
		if got := fire(); got != 0 {
			t.Fatalf("event %d: fired %d; both within clauses must pass (AND)", n, got)
		}
	}
	// Event 5: now clause 2 (>=5) AND clause 1 (>=2) both pass — fires.
	if got := fire(); got != 1 {
		t.Fatalf("event 5: fired %d; want 1 once BOTH within clauses pass", got)
	}
}

// #4423 M4: the sliding window must not retain its burst high-water capacity
// forever. After a burst grows the backing array, draining the window back to a
// few entries must release the oversized backing array.
func TestPruneWindowReleasesBurstCapacity(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "p",
		Events:        []string{"e"},
		WithinClauses: []*config.EventWithin{{Seconds: 10, TriggerUntil: 1_000_000}},
	}
	e := newTestEngine(t, []*config.EventPolicy{pol})
	base := time.Unix(2_000_000, 0)
	now := base
	e.nowFn = func() time.Time { return now }
	e.mu.Lock()
	rt := e.runtime["p"]
	e.mu.Unlock()

	// Burst: 500 events in the same instant grows the window backing array.
	for n := 0; n < 500; n++ {
		e.mu.Lock()
		rt.windows["e"] = append(rt.windows["e"], now)
		e.pruneWindow(pol, "e", now)
		e.mu.Unlock()
	}
	burstCap := cap(rt.windows["e"])
	if burstCap < 64 {
		t.Fatalf("burst did not grow the window (cap=%d)", burstCap)
	}

	// Advance well past the 10s window and append one fresh event: the prune
	// drops all 500 stale timestamps, leaving a single live entry.
	now = base.Add(30 * time.Second)
	e.mu.Lock()
	rt.windows["e"] = append(rt.windows["e"], now)
	e.pruneWindow(pol, "e", now)
	drainedCap := cap(rt.windows["e"])
	live := len(rt.windows["e"])
	e.mu.Unlock()

	if live != 1 {
		t.Fatalf("window len=%d after drain; want 1", live)
	}
	if drainedCap >= burstCap {
		t.Fatalf("window cap stayed at burst high-water: burst=%d drained=%d; "+
			"burst capacity must be released on prune", burstCap, drainedCap)
	}
}

// #4423 M10: a pattern that reaches attributesMatch without an Apply-time cache
// entry must be compiled ONCE and cached, not recompiled on every event.
func TestAttributesMatchCacheBackfillOnMiss(t *testing.T) {
	pol := policyWithMatch("p", "e", "e.test-owner matches ^Comcast$")
	e := newTestEngine(t, []*config.EventPolicy{pol})

	// Simulate the legacy lenient-load miss: drop the Apply-built cache.
	e.mu.Lock()
	e.regexCache = map[string]*regexp.Regexp{}
	e.mu.Unlock()

	ev := rpm.Event{Name: "e", TestOwner: "Comcast"}
	if !e.attributesMatch(pol, ev) {
		t.Fatal("match should still succeed on a cache miss (compile on demand)")
	}

	e.mu.Lock()
	_, cached := e.regexCache["^Comcast$"]
	e.mu.Unlock()
	if !cached {
		t.Fatal("on-demand compile did not back-fill the regex cache; " +
			"the pattern would recompile on every event")
	}
}

// #4423 M11: the invalid-attributes warning throttle is PER POLICY, so a bad
// line on one policy does not swallow the FIRST warning about a distinct bad
// line on another policy.
func TestFlagAttributesInvalidPerPolicyThrottle(t *testing.T) {
	polA := policyWithMatch("A", "e", "totally-malformed-no-matches-A")
	polB := policyWithMatch("B", "e", "totally-malformed-no-matches-B")
	e := newTestEngine(t, []*config.EventPolicy{polA, polB})

	base := time.Unix(3_000_000, 0)
	now := base
	e.nowFn = func() time.Time { return now }

	var mu sync.Mutex
	warnedPolicies := map[string]bool{}
	prev := slog.Default()
	slog.SetDefault(slog.New(&capturingHandler{
		onWarn: func(policy string) {
			mu.Lock()
			warnedPolicies[policy] = true
			mu.Unlock()
		},
	}))
	defer slog.SetDefault(prev)

	// Policy A fails at t0 -> warns for A.
	if e.attributesMatch(polA, rpm.Event{Name: "e"}) {
		t.Fatal("malformed line must fail closed")
	}
	// Policy B fails 1s later (well within the 10s window) -> a GLOBAL throttle
	// would suppress this; a PER-POLICY throttle warns because B never warned.
	now = base.Add(1 * time.Second)
	if e.attributesMatch(polB, rpm.Event{Name: "e"}) {
		t.Fatal("malformed line must fail closed")
	}

	mu.Lock()
	defer mu.Unlock()
	if !warnedPolicies["A"] {
		t.Fatal("policy A never warned")
	}
	if !warnedPolicies["B"] {
		t.Fatal("policy B's distinct bad line was suppressed by A's throttle " +
			"(the #4423 M11 global-throttle bug)")
	}
}

// #4423 L4: reordering a policy's event list is NOT a semantic change — the
// event list is a set — so the semantic revision (and thus the carried-forward
// cooldown/window state) must be identical.
func TestPolicySemanticRevisionEventOrderStable(t *testing.T) {
	a := &config.EventPolicy{Name: "p", Events: []string{"x", "y", "z"}}
	b := &config.EventPolicy{Name: "p", Events: []string{"z", "y", "x"}}
	if policySemanticRevision(a) != policySemanticRevision(b) {
		t.Fatal("event-list reorder changed the semantic revision; a bare reorder " +
			"must not re-arm and wipe the live cooldown")
	}
	// A genuine event change still changes the revision.
	c := &config.EventPolicy{Name: "p", Events: []string{"x", "y"}}
	if policySemanticRevision(a) == policySemanticRevision(c) {
		t.Fatal("dropping an event must change the semantic revision")
	}
}

// #4423 L7: a matcher-only engine (New(nil, nil)) whose policy actually triggers
// must NOT nil-panic in the worker goroutine — it fails the batch permanently.
func TestApplyOnceNilStoreDoesNotPanic(t *testing.T) {
	pol := &config.EventPolicy{
		Name:         "p",
		Events:       []string{"e"},
		ThenCommands: []string{"set system host-name x"},
	}
	e := New(nil, nil) // nil store
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	// On the pre-fix code the worker goroutine nil-derefs e.store and panics,
	// crashing the test process. The guard turns it into a counted rejection.
	e.HandleEvent(rpm.Event{Name: "e"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.Stats().Rejected >= 1 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("nil-store remediation was not counted as rejected")
}

// #4423 M6: evaluateEvent routes an event only to the policies that list it, and
// a policy that lists the same event name twice is still evaluated once.
func TestEventIndexRoutingAndDedup(t *testing.T) {
	polE1 := &config.EventPolicy{Name: "only-e1", Events: []string{"e1"}}
	polE2 := &config.EventPolicy{Name: "only-e2", Events: []string{"e2"}}
	polDup := &config.EventPolicy{Name: "dup", Events: []string{"e1", "e1"}}
	e := newTestEngine(t, []*config.EventPolicy{polE1, polE2, polDup})

	// e2 must not reach the e1-only policy.
	if got := len(e.evaluateEvent(rpm.Event{Name: "e2"})); got != 1 {
		t.Fatalf("e2 fired %d policies; want only only-e2", got)
	}

	// The duplicate-event policy must record exactly one window entry per event,
	// not one per duplicate listing.
	e.mu.Lock()
	rt := e.runtime["dup"]
	base := time.Unix(4_000_000, 0)
	e.nowFn = func() time.Time { return base }
	e.mu.Unlock()
	e.evaluateEvent(rpm.Event{Name: "e1"})
	e.mu.Lock()
	n := len(rt.windows["e1"])
	e.mu.Unlock()
	if n != 1 {
		t.Fatalf("dup policy recorded %d window entries for one e1 event; want 1", n)
	}
}

// #4423 M9 (regression): a change-configuration batch whose `delete` targets a
// subtree under an ABSENT intermediate container must TOLERATE the missing
// delete (Junos semantics) and still commit the rest — not abort. This is the
// deletePath container-miss shape (the most common defensive remediation:
// `delete <subtree>` when the parent is not configured). Before the line-521
// ErrPathNotFound wrap, applyOnce's errors.Is check returned false for this
// shape and the whole batch aborted, so the trailing valid set never applied.
func TestBatchContainerMissDeleteIsTolerated(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"ping_test_failed"},
		ThenCommands: []string{
			// routing-options is not configured -> container-miss, must be tolerated.
			"delete routing-options static route 0.0.0.0/0",
			// A valid set that only commits if the batch was NOT aborted.
			"set system domain-name applied",
		},
	}
	e := New(s, nil) // nil commitFn: store.Commit path
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))

	waitFor(t, "committed counter", func() bool { return e.Stats().Committed >= 1 })

	active := s.ActiveConfig()
	if active.System.DomainName != "applied" {
		t.Fatalf("domain-name=%q; the batch must COMMIT despite the tolerated "+
			"container-miss delete (M9 regression)", active.System.DomainName)
	}
	if got := e.Stats().Rejected; got != 0 {
		t.Fatalf("Rejected=%d; a tolerated container-miss delete must not reject the batch", got)
	}
}

// capturingHandler is a minimal slog.Handler that reports the "policy" attribute
// of WARN records to a callback, for the M11 throttle test.
type capturingHandler struct {
	onWarn func(policy string)
}

func (h *capturingHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= slog.LevelWarn
}

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level < slog.LevelWarn {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "policy" {
			h.onWarn(a.Value.String())
			return false
		}
		return true
	})
	return nil
}

func (h *capturingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(_ string) slog.Handler      { return h }
