package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K35) — `within <seconds>` Duration overflow.
//
// The #3751 belt three lines above this defect exists for exactly one ingress:
// "a config that slipped through a TOLERANT load / peer-sync path". It checks
// `wc.Seconds <= 0`. A value large enough to overflow
// `time.Duration(Seconds) * time.Second` arrives through the SAME ingress and
// walks past that check, because the wrapped product can be small and POSITIVE.
//
// overflowWithinSeconds is the value whose residue is the smallest positive
// one — 512ns, since gcd(1e9, 2^64) = 512. It is the same fixture #6769 uses
// for the flow-export instance of this family.
const overflowWithinSeconds8597 = 20211507185753197

// TestWithinOverflowFixtureActuallyWraps_8597 is the non-vacuity guard: the
// cells below assert a policy does NOT fire, and a policy that does not fire is
// the default state of a great many mistakes. This cell proves the fixture is a
// real positive wrap, so "did not fire" is attributable to the guard.
func TestWithinOverflowFixtureActuallyWraps_8597(t *testing.T) {
	n := overflowWithinSeconds8597
	wrapped := time.Duration(n) * time.Second
	if wrapped <= 0 {
		t.Fatalf("fixture wraps to %v; these cells guard the POSITIVE wrap — the half the "+
			"#3751 `Seconds <= 0` check does NOT catch", wrapped)
	}
	if wrapped != 512*time.Nanosecond {
		t.Errorf("fixture wraps to %v, want 512ns (gcd(1e9, 2^64) = 512)", wrapped)
	}
	if n <= config.MaxEventWithinSeconds {
		t.Fatalf("fixture %d is inside the configured ceiling %d; it would be accepted and "+
			"the cells below would test nothing", n, config.MaxEventWithinSeconds)
	}
}

// TestLenientLoadKeepsAnOutOfRangeWithin_8597 is the REACHABILITY cell.
//
// It drives the two real config entry points and asserts the split the finding
// depends on: the strict typed-leaf gate REJECTS an out-of-range `within`,
// while the tolerant compile keeps the raw int. Store.compileTreeLenient's own
// comment states this split — "the typed-leaf SchemaValidate gate is STRICT
// only on the operator-driven commit / commit-check path ... Here — the
// tolerant Store.Load / Store.SyncApply ingress — a violation downgrades to a
// warning" — and this cell holds it to that, so the runtime belt below cannot
// quietly become an unreachable ornament.
func TestLenientLoadKeepsAnOutOfRangeWithin_8597(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set event-options policy p events ping_probe_failed",
		"set event-options policy p within 20211507185753197 trigger until 5",
		"set event-options policy p then change-configuration commands \"set system host-name x\"",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	// The strict gate for `within` is the AST pre-walk inside the compiler
	// (config.validateEventOptionsWithinAST), NOT the typed-leaf schema —
	// schema_system.go says so explicitly at the `within` leaf. So the strict
	// arm here is CompileConfig, and the tolerant arm is CompileConfigLenient,
	// which passes lenientEventWithinTrigger and downgrades to a warning.
	//
	// Naming the right gate matters: SchemaValidate ACCEPTS this config, so a
	// cell that used it would have reported "strict rejects" about a gate that
	// never looked.
	if _, err := config.CompileConfig(tree); err == nil {
		t.Error("strict compile accepted an out-of-range `within`; the lenient/strict " +
			"split this finding rests on no longer exists")
	}

	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not fail (#1960 no-brick), got: %v", err)
	}
	var found *config.EventWithin
	for _, pol := range cfg.EventOptions {
		if pol.Name == "p" && len(pol.WithinClauses) == 1 {
			found = pol.WithinClauses[0]
		}
	}
	if found == nil {
		t.Fatal("lenient compile produced no within clause for policy p")
	}
	if found.Seconds != overflowWithinSeconds8597 {
		t.Errorf("lenient within Seconds = %d, want the raw %d — if the tolerant ingress "+
			"now bounds this, the runtime belt is unreachable and should be re-argued "+
			"rather than silently kept", found.Seconds, overflowWithinSeconds8597)
	}
}

// TestWithinOverflowUntilOnlyFailsClosed_8597 is the RED-on-revert core, and
// the security half.
//
// `trigger until N` passes when `counts[i] <= TriggerUntil`. A wrapped window
// makes every `now.Sub(ts) <= window` comparison false, so counts land at 0,
// so `0 <= N` passes for every event — an until-only policy fires on EVERY
// event. Event-options is the SELF-MUTATING surface (a policy's action runs
// `set` and `commit`), so this is an unauthorized remediation loop throttled
// only by the 30s cooldown, not a missed alarm.
//
// Reverting withinWindow to `time.Duration(wc.Seconds) * time.Second` with no
// range check makes this fire 10/10.
func TestWithinOverflowUntilOnlyFailsClosed_8597(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "until-only-overflow",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: overflowWithinSeconds8597, TriggerUntil: 5}},
	}
	if got := feedEvents(t, pol, 10); got != 0 {
		t.Fatalf("an until-only policy with an overflowing `within` fired %d/10 times; it "+
			"must fail CLOSED — the same direction the #3751 belt chose for the same "+
			"tolerant ingress (#8597/K35)", got)
	}
}

// TestWithinOverflowTriggerOnFailsClosed_8597 is the other clause shape. The
// on-variant already failed closed by accident (counts of 0 never reach N), so
// this cell is not red-on-revert; it is here so a future fix that changes the
// direction has to change this assertion deliberately.
func TestWithinOverflowTriggerOnFailsClosed_8597(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "on-overflow",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: overflowWithinSeconds8597, TriggerOn: 3}},
	}
	if got := feedEvents(t, pol, 10); got != 0 {
		t.Fatalf("trigger-on policy with an overflowing `within` fired %d/10 times, want 0", got)
	}
}

// TestWithinOverflowInOneClauseDoesNotFireTheOthers_8597: a policy carrying a
// well-formed clause BESIDE an overflowing one must still fail closed. The
// guard is per-clause and runs in PASS 1 over every clause, so one bad clause
// disarms the policy rather than being averaged away by a good one.
func TestWithinOverflowMixedClausesFailsClosed_8597(t *testing.T) {
	pol := &config.EventPolicy{
		Name:   "mixed",
		Events: []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{
			{Seconds: 30, TriggerUntil: 5},
			{Seconds: overflowWithinSeconds8597, TriggerUntil: 5},
		},
	}
	if got := feedEvents(t, pol, 10); got != 0 {
		t.Fatalf("a policy with one overflowing clause beside a valid one fired %d/10 "+
			"times; the range check must be per-clause", got)
	}
}

// TestWithinWindowHonoursValidValues_8597 is the OVER-BROAD control. A "fix"
// that rejected everything, or clamped every window to a default, would pass
// every cell above and silently disable event-options for every real config.
// The boundary values are included because an off-by-one in the comparison is
// exactly how a bound like this gets written wrong.
func TestWithinWindowHonoursValidValues_8597(t *testing.T) {
	for _, sec := range []int{
		config.MinEventWithinSeconds,
		30,
		3600,
		config.MaxEventWithinSeconds,
	} {
		got, ok := withinWindow(sec)
		if !ok {
			t.Errorf("withinWindow(%d) rejected a value the config layer accepts", sec)
			continue
		}
		if want := time.Duration(sec) * time.Second; got != want {
			t.Errorf("withinWindow(%d) = %v, want %v", sec, got, want)
		}
	}
	for _, sec := range []int{
		config.MinEventWithinSeconds - 1,
		config.MaxEventWithinSeconds + 1,
		overflowWithinSeconds8597,
		-1,
	} {
		if _, ok := withinWindow(sec); ok {
			t.Errorf("withinWindow(%d) accepted a value outside "+
				"[%d, %d]; the runtime belt and the config gate must agree on where the "+
				"ceiling is", sec, config.MinEventWithinSeconds, config.MaxEventWithinSeconds)
		}
	}
}

// TestValidWithinStillFires_8597 is the end-to-end over-broad control: the
// #3751 positive control re-run through the new helper, so a range check that
// accidentally disarmed every policy cannot land green.
func TestValidWithinStillFires_8597(t *testing.T) {
	pol := &config.EventPolicy{
		Name:          "valid-on3",
		Events:        []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{{Seconds: 30, TriggerOn: 3}},
	}
	if got := firstFireIndex(t, pol, 5); got != 2 {
		t.Fatalf("a valid `within 30 { trigger on 3 }` first fired at index %d, want 2 — "+
			"the range check has disarmed a well-formed policy", got)
	}
}

// TestPruneWindowIgnoresAnOverflowingClause_8597 covers the SECOND consumer.
// pruneWindow runs on every append and is NOT gated by the PASS 1 belt, so it
// needs its own bound: a wrapped maxWindow would discard every timestamp for
// every event the policy watches, including the ones its well-formed clauses
// depend on. With the overflowing clause skipped, maxWindow falls through to
// the 60s default and a valid sibling clause still sees its history.
func TestPruneWindowIgnoresAnOverflowingClause_8597(t *testing.T) {
	e := New(nil, nil)
	defer e.Close()

	pol := &config.EventPolicy{
		Name:   "prune",
		Events: []string{"ping_probe_failed"},
		WithinClauses: []*config.EventWithin{
			{Seconds: overflowWithinSeconds8597, TriggerUntil: 5},
		},
	}
	applyPolicies9984(e, []*config.EventPolicy{pol})

	rt := e.runtime[pol.Name]
	if rt == nil {
		t.Fatal("no runtime for the applied policy")
	}
	base := time.Unix(1_700_000_000, 0)
	// Three timestamps inside the 60s default retention window.
	rt.windows["ping_probe_failed"] = []time.Time{
		base.Add(-30 * time.Second),
		base.Add(-20 * time.Second),
		base.Add(-10 * time.Second),
	}
	e.pruneWindow(pol, "ping_probe_failed", base)

	if got := len(rt.windows["ping_probe_failed"]); got != 3 {
		t.Fatalf("pruneWindow kept %d/3 timestamps inside the 60s default window; an "+
			"out-of-range clause must contribute nothing to maxWindow rather than "+
			"wrapping it to a sub-second value that discards everything", got)
	}
}
