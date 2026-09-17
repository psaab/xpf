package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Regression tests for #3751 (engine defense-in-depth half). The commit-time
// gate (config.validateEventOptionsWithinAST) rejects a within/trigger numeric
// typo, but an already-persisted config an older binary silently accepted can
// still reach the engine with a within clause whose threshold was coerced to 0
// (the strconv.Atoi error was dropped). withinMatches must fail CLOSED on such
// a clause (the policy does NOT fire) rather than treating the 0 as an
// unconditional match — the original always-fire fail-open.

// feedEvents drives the real evaluate path count times on a deterministic
// clock (one simulated second per event) and returns the number of times the
// single configured policy triggered.
func feedEvents(t *testing.T, pol *config.EventPolicy, count int) int {
	t.Helper()
	e := New(nil, nil)
	defer e.Close()

	base := time.Unix(1_700_000_000, 0)
	var tick int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(tick) * time.Second) }
	applyPolicies9984(e, []*config.EventPolicy{pol})

	triggered := 0
	for tick = 0; tick < int64(count); tick++ {
		got := e.evaluateEvent(rpm.Event{Name: pol.Events[0], TestOwner: "o", TestName: "t"})
		triggered += len(got)
	}
	return triggered
}

// firstFireIndex drives count events and returns the 0-based index of the
// FIRST event at which the policy triggered, or -1 if it never did.
func firstFireIndex(t *testing.T, pol *config.EventPolicy, count int) int {
	t.Helper()
	e := New(nil, nil)
	defer e.Close()

	base := time.Unix(1_700_000_000, 0)
	var tick int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(tick) * time.Second) }
	applyPolicies9984(e, []*config.EventPolicy{pol})

	for tick = 0; tick < int64(count); tick++ {
		got := e.evaluateEvent(rpm.Event{Name: pol.Events[0], TestOwner: "o", TestName: "t"})
		if len(got) > 0 {
			return int(tick)
		}
	}
	return -1
}

// TestWithin_TriggerOnFiresOnlyAfterN_3751 proves a valid `within 30 { trigger
// on 3 }` clause fires only once the 3rd matching event lands in the window —
// NOT on the first. This is the positive control the fail-closed guard must
// not disturb.
func TestWithin_TriggerOnFiresOnlyAfterN_3751(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "on3",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 30, TriggerOn: 3}},
	}
	// Events at ticks 0,1,2 — the 3rd (index 2) reaches count 3 in a 30s
	// window at 1 event/s.
	if got := firstFireIndex(t, pol, 5); got != 2 {
		t.Fatalf("trigger on 3 first fired at event index %d; want 2 (the 3rd event)", got)
	}
}

// TestWithin_ZeroThresholdFailsClosed_3751 is the RED-on-revert core: a within
// clause that exists but carries NO usable positive threshold (both TriggerOn
// and TriggerUntil are 0 — the state a dropped strconv.Atoi error produced)
// must NEVER fire. Reverting the withinMatches fail-closed guard makes the
// clause fall through to `return true` and fire on EVERY event (the #3751
// always-fire fail-open), so `triggered` becomes 10 and this fails.
func TestWithin_ZeroThresholdFailsClosed_3751(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "coerced-zero-threshold",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 30}}, // TriggerOn/Until == 0
	}
	if got := feedEvents(t, pol, 10); got != 0 {
		t.Fatalf("within clause with a 0 threshold fired %d times; must fail CLOSED "+
			"(a coerced-typo threshold must not always-fire, #3751)", got)
	}
}

// TestWithin_ZeroWindowFailsClosed_3751 covers the fully-coerced case (the
// within seconds ALSO dropped to 0): a 0-second window with no threshold must
// likewise fail closed.
func TestWithin_ZeroWindowFailsClosed_3751(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "coerced-zero-window",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 0, TriggerOn: 0}},
	}
	if got := feedEvents(t, pol, 10); got != 0 {
		t.Fatalf("within clause with a 0 window fired %d times; must fail CLOSED (#3751)", got)
	}
}

// TestWithin_NoClausesStillFiresEveryEvent_3751 guards the boundary: a policy
// with NO within clauses at all legitimately has no temporal filter and must
// still fire on every matching event. The fail-closed guard is scoped to a
// within clause that EXISTS but gates nothing — it must not swallow the
// no-clause case.
func TestWithin_NoClausesStillFiresEveryEvent_3751(t *testing.T) {
	pol := &config.EventPolicy{
		Name:   "no-within",
		Events: []string{"ping_probe_failed"},
		// No WithinClauses.
	}
	if got := feedEvents(t, pol, 4); got != 4 {
		t.Fatalf("no-within policy fired %d/4 times; a policy with no temporal filter must "+
			"fire on every matching event", got)
	}
}
