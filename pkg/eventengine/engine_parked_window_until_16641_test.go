package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// #16641: cooldown parking skipped windowing the parked direction's
// events, so `within W { trigger until N }` (N ≳ 4) never reached its
// ceiling in a sustained storm and the remediation re-ran every 30 s.
//
// Pre-fix mechanism for `within 60 { trigger until 10 }` on
// ping_probe_failed: t=0 fires and commits (cooldown armed); the t=2
// event (count 2 ≤ 10, in cooldown) parks the direction; t=4..28
// events hit the parked early-continue BEFORE the window append, so
// the window starved at ≈2-3 entries; at drain withinMatches still
// saw count ≤ 10, the parked edge replayed, the cooldown re-armed —
// and the next in-cooldown event parked again, repeating every 30 s.
//
// Post-fix every matching event is appended+pruned even while parked,
// so the window reflects the whole storm; once it passes the ceiling
// the live evaluate path refuses to re-fire. The parked edge itself
// replays once — it crossed at/inside the ceiling (#16848 recorded
// verdict, see the #15945 file) — but a sustained storm must never
// produce a further over-ceiling remediation.

// The DEFECT arm: a sustained storm (an event every 2 s) must
// contribute ZERO over-ceiling fires. Directed evaluateEvent calls
// stand in for the live path once the direction is unparked (the
// drain clears the parked direction); evaluateEvent never arms the
// cooldown, so these calls expose exactly the windowing half.
func TestParkedWindowUntilStormNoOverCeiling16641(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "p",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 60, TriggerUntil: 10}},
		ThenCommands:  []string{"set system host-name remediated"},
	}
	e, clk := setupCooldown15945(t, pol)

	clk.set(0)
	e.HandleEvent(eventFor("ping_probe_failed")) // fires, commits, cooldown armed
	waitCommitted15945(t, e, 1)
	waitCooldownArmed15945(t, e)

	clk.set(2)
	e.HandleEvent(eventFor("ping_probe_failed")) // count 2 ≤ 10, in cooldown: parks
	if got := e.Stats().PendingDeferred; got == 0 {
		t.Fatalf("t=2 crossing was not parked: %+v", e.Stats())
	}

	// Parked-direction storm events must be windowed but never fire.
	// Pre-fix they were dropped before the append, so the window below
	// would hold only the t=0 and t=2 entries (2).
	for sec := int64(4); sec <= 28; sec += 2 {
		clk.set(sec)
		if got := e.evaluateEvent(rpm.Event{Name: "ping_probe_failed", TestOwner: "owner", TestName: "tname"}); len(got) != 0 {
			t.Fatalf("parked-direction event at t=%d fired %+v; parked direction skips only the fire decision, not the windowing", sec, got)
		}
	}
	// Events 0,2,...,28 = 15 events, all inside the 60 s window.
	if got := windowLen(e, "p", "ping_probe_failed"); got != 15 {
		t.Fatalf("window=%d after parked storm, want 15 (every event windowed while parked; pre-fix starved window held 2)", got)
	}

	// Drain (past the 30 s cooldown): the single parked crossing
	// replays exactly once — the operator's first over-ceiling-adjacent
	// remediation is the recorded one, not a fresh fire.
	clk.set(40)
	e.drainDeferred()
	waitCommitted15945(t, e, 2)

	// Past the drain the direction is unparked, but the storm has been
	// windowed past the ceiling: a fresh event must NOT fire, and a
	// sustained stream after the cooldown must not re-fire either —
	// the exact pre-fix loop (a fresh park + drain replay every 30 s,
	// counted here as further commits).
	for sec := int64(42); sec <= 58; sec += 2 {
		clk.set(sec)
		e.HandleEvent(eventFor("ping_probe_failed"))
	}
	time.Sleep(200 * time.Millisecond)
	if got := e.Stats().Committed; got != 2 {
		t.Fatalf("commits=%d after sustained storm, want exactly 2 (initial fire + single parked replay; over-ceiling re-fires are the #16641 defect)", got)
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("PendingDeferred=%d, want 0 (over-ceiling events must not park a new deferred edge)", got)
	}
}

// The sparse control: few events, never over the ceiling — unchanged
// by the fix. The parked crossing still replays once at drain, and
// the windowed parked events are all retained.
func TestParkedWindowUntilSparseControlUnchanged16641(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "p",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 60, TriggerUntil: 10}},
		ThenCommands:  []string{"set system host-name remediated"},
	}
	e, clk := setupCooldown15945(t, pol)

	clk.set(0)
	e.HandleEvent(eventFor("ping_probe_failed"))
	waitCommitted15945(t, e, 1)
	waitCooldownArmed15945(t, e)

	clk.set(2)
	e.HandleEvent(eventFor("ping_probe_failed")) // parks (count 2 ≤ 10)
	if got := e.Stats().PendingDeferred; got == 0 {
		t.Fatalf("sparse crossing was not parked: %+v", e.Stats())
	}
	for _, sec := range []int64{4, 6} {
		clk.set(sec)
		e.HandleEvent(eventFor("ping_probe_failed"))
	}
	if got := windowLen(e, "p", "ping_probe_failed"); got != 4 {
		t.Fatalf("window=%d, want 4 (t=0,2,4,6 all windowed, none dropped while parked)", got)
	}
	clk.set(40)
	e.drainDeferred()
	waitCommitted15945(t, e, 2) // the parked sparse crossing replays once
}
