package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// Regression tests for #3756 M1: `within { trigger on N }` is EDGE-triggered
// (fires on the threshold CROSSING) rather than LEVEL-triggered (firing on
// every above-threshold event, throttled only by the 30s cooldown). Junos
// `trigger on` re-arms only after the in-window count drops back below N.
//
// These drive the real evaluate path (evaluateEvent) on a deterministic clock.
// evaluateEvent does not arm the cooldown (that is the worker's job on a
// successful commit), so without a worker the PRE-M1 level code fires on EVERY
// above-threshold event — the "re-fire every cooldown" behavior in its most
// visible form. The edge latch fixes that regardless of the cooldown.

// feedEventsAtTicks drives one event per supplied tick (simulated seconds) and
// returns the total number of triggers.
func feedEventsAtTicks(t *testing.T, pol *config.EventPolicy, ticks []int64) int {
	t.Helper()
	e := New(nil, nil)
	defer e.Close()

	base := time.Unix(1_700_000_000, 0)
	var cur int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(cur) * time.Second) }
	applyPolicies9984(e, []*config.EventPolicy{pol})

	triggered := 0
	for _, cur = range ticks {
		triggered += len(e.evaluateEvent(rpm.Event{Name: pol.Events[0], TestOwner: "o", TestName: "t"}))
	}
	return triggered
}

// A SUSTAINED above-threshold level must fire the remediation exactly ONCE (on
// the crossing), not on every subsequent event while the level holds.
//
// RED-on-revert: the pre-M1 level code returns true for every event with
// count>=N, so all 9 post-crossing events also fire — total 9 instead of 1.
func TestEdgeTriggerOn_SustainedLevelFiresOnce_3756(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "on2",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: 2}},
	}
	// 10 events, one per second, all inside the 300s window: the count climbs
	// to 2 at tick 1 (the crossing) and stays >=2 through tick 9.
	ticks := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if got := feedEventsAtTicks(t, pol, ticks); got != 1 {
		t.Fatalf("sustained above-threshold level fired %d times; `trigger on` is "+
			"edge-triggered and must fire exactly ONCE per crossing (#3756 M1)", got)
	}
}

// After the count drops back below N the latch re-arms, so a subsequent
// crossing fires AGAIN. This proves the latch is not a one-shot.
//
// RED-on-revert: the pre-M1 level code fires on ticks 1,2,3,4 and 11 (every
// above-threshold event) — total 5 — instead of the edge total 2 (one fire per
// crossing at ticks 1 and 11).
func TestEdgeTriggerOn_ReArmsAfterDroppingBelow_3756(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "on2-rearm",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 5, TriggerOn: 2}},
	}
	// First burst 0..4 crosses at tick 1 (fire once, latched). By tick 10 the
	// 0..4 timestamps have aged out of the 5s window, so tick 10 sees count=1
	// (< 2 → re-arm), and tick 11 crosses again (fire once).
	ticks := []int64{0, 1, 2, 3, 4, 10, 11}
	if got := feedEventsAtTicks(t, pol, ticks); got != 2 {
		t.Fatalf("re-arm scenario fired %d times; want exactly 2 (one per crossing) — "+
			"edge trigger must suppress the sustained middle events yet re-fire "+
			"after the count drops below N and crosses again (#3756 M1)", got)
	}
}

// A crossing suppressed by an ACTIVE cooldown must NOT be treated as
// already-fired: the latch is set only after the cooldown check passes, so once
// the cooldown clears the still-held level fires exactly once. This guards the
// evaluateEvent ordering (latch-after-cooldown).
//
// RED-on-regression: if the latch were set before/independent of the cooldown
// check, the crossing would be consumed during suppression and NEVER fire
// (total 0). If edge were reverted to level, it would fire on every post-
// cooldown event (many). Exactly-1 is the correct edge+cooldown interaction.
func TestEdgeTriggerOn_CooldownDoesNotConsumeCrossing_3756(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "on2-cooldown",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 300, TriggerOn: 2}},
	}
	e := New(nil, nil)
	defer e.Close()

	base := time.Unix(1_700_000_000, 0)
	var cur int64
	e.nowFn = func() time.Time { return base.Add(time.Duration(cur) * time.Second) }
	applyPolicies9984(e, []*config.EventPolicy{pol})

	// Pre-arm the cooldown anchor to base (as if a commit had just occurred),
	// so the crossing at tick 1 lands inside the 30s cooldown and is suppressed.
	e.mu.Lock()
	e.runtime["on2-cooldown"].lastTrigger = base
	e.mu.Unlock()

	triggered := 0
	// Feed one event per second across the cooldown boundary (30s). The crossing
	// (tick 1) and every event through tick 29 are cooldown-suppressed; tick 31
	// is past the 30s cooldown and must fire — the crossing was NOT consumed.
	for _, cur = range []int64{0, 1, 2, 3, 4, 5, 10, 20, 29, 31, 32, 33} {
		triggered += len(e.evaluateEvent(rpm.Event{Name: "ping_probe_failed", TestOwner: "o", TestName: "t"}))
	}
	if triggered != 1 {
		t.Fatalf("edge+cooldown interaction fired %d times; a cooldown-suppressed "+
			"crossing must not be consumed — it fires exactly once when the "+
			"cooldown clears (#3756 M1)", triggered)
	}
}
