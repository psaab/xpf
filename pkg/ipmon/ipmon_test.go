package ipmon

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

func testPolicyConfig() *config.IPMonitoringConfig {
	return &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", PreferredMetric: 10},
				{RoutingInstance: "ISP-B", Destination: "0.0.0.0/0", NextHop: "172.16.80.1"},
			},
		},
	}}
}

func passResults() []*rpm.ProbeResult {
	return []*rpm.ProbeResult{
		{ProbeName: "WAN", TestName: "wan-a", LastStatus: "pass"},
		{ProbeName: "WAN", TestName: "wan-b", LastStatus: "pass"},
	}
}

// fakeClock drives the engine deterministically.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestEngine(actuate func(context.Context) bool) (*Engine, *fakeClock) {
	e := New(actuate)
	clock := &fakeClock{now: time.Unix(1000000, 0)}
	e.now = clock.Now
	return e, clock
}

// transition builds an rpm.Transition with a coherent results snapshot.
func transition(probe, test, status string, results []*rpm.ProbeResult) rpm.Transition {
	for _, r := range results {
		if r.ProbeName == probe && r.TestName == test {
			r.LastStatus = status
		}
	}
	return rpm.Transition{ProbeName: probe, TestName: test, Status: status, Results: results}
}

// TestProbeFailInjectsAndRecoverWithdraws is the core state machine
// test: probe-fail → inject; probe-recover → withdraw.
func TestProbeFailInjectsAndRecoverWithdraws(t *testing.T) {
	e, clock := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())

	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v before any failure, want nil", got)
	}

	// ANY test failing flips the policy to FAIL (Junos semantics).
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	overlay := e.ActiveOverlay()
	if len(overlay) != 2 {
		t.Fatalf("overlay = %+v, want both preferred routes injected", overlay)
	}
	if overlay[0].RoutingInstance != "" || overlay[0].Destination != "0.0.0.0/0" ||
		overlay[0].NextHop != "172.16.80.1" {
		t.Fatalf("overlay[0] = %+v", overlay[0])
	}
	if overlay[1].RoutingInstance != "ISP-B" {
		t.Fatalf("overlay[1] = %+v", overlay[1])
	}

	// Recovery of the failing test (hold-down 0) withdraws immediately.
	clock.Advance(10 * time.Second)
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after recovery, want nil", got)
	}

	st := e.Status()
	if len(st) != 1 || st[0].Transitions != 2 {
		t.Fatalf("status = %+v, want one policy with 2 transitions", st)
	}
}

func TestAnyTestFailedKeepsPolicyFailed(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())

	results := passResults()
	e.HandleTransition(transition("WAN", "wan-a", "fail", results))
	e.HandleTransition(transition("WAN", "wan-b", "fail", results))
	// One of two failing tests recovers — policy stays FAIL.
	e.HandleTransition(transition("WAN", "wan-a", "pass", results))
	if got := e.ActiveOverlay(); len(got) == 0 {
		t.Fatal("overlay withdrawn while one test still FAILED")
	}
	e.HandleTransition(transition("WAN", "wan-b", "pass", results))
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after full recovery", got)
	}
}

// TestOutOfOrderSiblingSnapshotsCannotWithdrawFailure10876 models two
// concurrent RPM test goroutines: generation 2's fail callback is delivered
// before generation 1's stale pass snapshot. The stale sibling snapshot must
// not clear the newer FAIL state.
func TestOutOfOrderSiblingSnapshotsCannotWithdrawFailure10876(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())

	newer := transition("WAN", "wan-b", "fail", passResults())
	newer.Generation = 2
	older := transition("WAN", "wan-a", "pass", passResults())
	older.Generation = 1

	releaseOlder := make(chan struct{})
	olderDone := make(chan struct{})
	go func() {
		<-releaseOlder
		e.HandleTransition(older)
		close(olderDone)
	}()

	e.HandleTransition(newer)
	if got := e.ActiveOverlay(); len(got) == 0 {
		t.Fatal("newer sibling FAIL did not inject preferred routes")
	}

	close(releaseOlder)
	<-olderDone
	if got := e.ActiveOverlay(); len(got) == 0 {
		t.Fatal("stale sibling snapshot withdrew the newer FAIL overlay")
	}
	status := e.Status()
	if len(status) != 1 || !status[0].Failed ||
		len(status[0].FailingTests) != 1 || status[0].FailingTests[0] != "wan-b" {
		t.Fatalf("status after stale snapshot = %+v, want WAN/wan-b still failing", status)
	}
}

// TestRecoveryHoldDown verifies hold-down damps recovery (and ONLY
// recovery: failure re-arms instantly).
func TestRecoveryHoldDown(t *testing.T) {
	cfg := testPolicyConfig()
	cfg.Policies["wan-failover"].HoldDownSecs = 5
	e, clock := newTestEngine(nil)
	e.Apply(cfg, passResults())

	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("no overlay after failure")
	}

	// Recovery starts the hold-down; the overlay must persist.
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("overlay withdrawn before hold-down expiry")
	}
	st := e.Status()
	if st[0].PendingRecoveryAt.IsZero() {
		t.Fatal("no pending recovery deadline during hold-down")
	}

	// A re-failure during hold-down cancels the recovery.
	clock.Advance(2 * time.Second)
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if !e.Status()[0].PendingRecoveryAt.IsZero() {
		t.Fatal("pending recovery survived a re-failure")
	}
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("overlay lost on flap during hold-down")
	}

	// Recover again; advance past hold-down; evaluate withdraws.
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
	clock.Advance(6 * time.Second)
	e.mu.Lock()
	e.evaluateLocked(e.now())
	e.mu.Unlock()
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after hold-down expiry", got)
	}
}

// TestHoldDownRecomputeOnConfigChange is the #3763 regression: changing
// the hold-down value while a recovery is pending must recompute the
// pending-recovery deadline (crediting the time already elapsed), so a
// lowered hold-down shortens the pending recovery and a raised one
// extends it — without a restart. On revert (pendingRecoveryAt preserved
// verbatim) the old deadline stays in force and each scenario goes RED.
func TestHoldDownRecomputeOnConfigChange(t *testing.T) {
	enterRecovery := func(holdSecs int) (*Engine, *fakeClock) {
		cfg := testPolicyConfig()
		cfg.Policies["wan-failover"].HoldDownSecs = holdSecs
		e, clock := newTestEngine(nil)
		e.Apply(cfg, passResults())
		e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
		e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
		if e.Status()[0].PendingRecoveryAt.IsZero() {
			t.Fatalf("setup: no pending recovery under hold-down %ds", holdSecs)
		}
		return e, clock
	}
	reapply := func(e *Engine, holdSecs int) {
		cfg := testPolicyConfig()
		cfg.Policies["wan-failover"].HoldDownSecs = holdSecs
		e.Apply(cfg, passResults())
	}
	evalNow := func(e *Engine) {
		e.mu.Lock()
		e.evaluateLocked(e.now())
		e.mu.Unlock()
	}

	// Lower below elapsed time → recover immediately (the incident-
	// response scenario: 300s hold, 50s elapsed, drop to 10s).
	e, clock := enterRecovery(300)
	clock.Advance(50 * time.Second)
	reapply(e, 10)
	if e.Status()[0].Failed {
		t.Fatal("hold-down lowered below elapsed time did not recover")
	}

	// Lower to a still-future deadline → shortens but stays pending, then
	// recovers at the NEW (earlier) deadline, well before the old one.
	e, clock = enterRecovery(300)
	clock.Advance(50 * time.Second) // T0+50
	reapply(e, 100)                 // new deadline T0+100 (was T0+300)
	if !e.Status()[0].Failed {
		t.Fatal("recovered too early after shortening to a still-future deadline")
	}
	clock.Advance(51 * time.Second) // T0+101: past the new deadline, before the old
	evalNow(e)
	if e.Status()[0].Failed {
		t.Fatal("did not recover at the shortened deadline (old deadline still in force)")
	}

	// Raise extends: 10s hold, 5s elapsed, raise to 100s → stays pending
	// past the OLD 10s deadline.
	e, clock = enterRecovery(10)
	clock.Advance(5 * time.Second)
	reapply(e, 100)                 // new deadline T0+100
	clock.Advance(10 * time.Second) // T0+15: past the OLD deadline
	evalNow(e)
	if !e.Status()[0].Failed {
		t.Fatal("recovered at the OLD short deadline after hold-down was raised")
	}

	// Unchanged hold-down preserves the running deadline verbatim.
	e, _ = enterRecovery(300)
	before := e.Status()[0].PendingRecoveryAt
	reapply(e, 300)
	if got := e.Status()[0].PendingRecoveryAt; !got.Equal(before) {
		t.Fatalf("unchanged hold-down moved the deadline: %v -> %v", before, got)
	}
}

// TestWinnerResolution verifies the §4.1 corrected semantics: among
// multiple injected routes for the same prefix, lowest preferred-metric
// wins; tie-break lexicographic policy name; withdrawal of the winner
// re-exposes the loser (not the config route, which the overlay only
// shadows downstream).
func TestWinnerResolution(t *testing.T) {
	cfg := &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"b-policy": {
			Name: "b-policy", MatchRPMProbe: "P1",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "10.0.0.1", PreferredMetric: 10},
			},
		},
		"a-policy": {
			Name: "a-policy", MatchRPMProbe: "P2",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "10.0.0.2", PreferredMetric: 20},
			},
		},
		"c-policy": {
			Name: "c-policy", MatchRPMProbe: "P3",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "10.0.0.3", PreferredMetric: 10},
			},
		},
	}}
	results := []*rpm.ProbeResult{
		{ProbeName: "P1", TestName: "t", LastStatus: "pass"},
		{ProbeName: "P2", TestName: "t", LastStatus: "pass"},
		{ProbeName: "P3", TestName: "t", LastStatus: "pass"},
	}
	e, _ := newTestEngine(nil)
	e.Apply(cfg, results)

	// All three fail: lowest metric (10) wins; tie between b-policy and
	// c-policy broken lexicographically → b-policy.
	for _, r := range results {
		r.LastStatus = "fail"
	}
	e.HandleTransition(rpm.Transition{ProbeName: "P1", TestName: "t", Status: "fail", Results: results})
	overlay := e.ActiveOverlay()
	if len(overlay) != 1 {
		t.Fatalf("overlay = %+v, want single winner per prefix", overlay)
	}
	if overlay[0].NextHop != "10.0.0.1" || overlay[0].Policy != "b-policy" {
		t.Fatalf("winner = %+v, want b-policy via 10.0.0.1", overlay[0])
	}

	// Winner's probe recovers → c-policy (same metric) takes over.
	results[0].LastStatus = "pass"
	e.HandleTransition(rpm.Transition{ProbeName: "P1", TestName: "t", Status: "pass", Results: results})
	overlay = e.ActiveOverlay()
	if len(overlay) != 1 || overlay[0].Policy != "c-policy" {
		t.Fatalf("overlay = %+v, want c-policy after winner recovery", overlay)
	}

	// All recover → empty overlay.
	results[1].LastStatus = "pass"
	results[2].LastStatus = "pass"
	e.HandleTransition(rpm.Transition{ProbeName: "P2", TestName: "t", Status: "pass", Results: results})
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v, want nil", got)
	}
}

// TestActuationCountStaysBoundedUnderFlapStorm: N rapid transitions collapse
// to one actuation per throttle window (§4.3 coalescing).
//
// RENAMED FROM TestDebounceCoalescing (#8027), because that name claimed a
// property this test cannot observe. Disabling the debounce entirely —
// `now.Sub(e.dirtySince) >= e.debounce` becomes `>= 0` — leaves every
// assertion here GREEN.
//
// The reason is structural. Actuation is driven by a DIRTY FLAG: one
// actuation covers every pending transition regardless of how many arrived,
// so a storm coalesces by design. The `<= 2` bound is therefore satisfied by
// the shape of the code whatever the debounce window does, and cannot
// distinguish "coalescing works" from "multiple actuations are unreachable in
// this fixture" — which is true regardless. Both bounds here are really about
// the throttle and the dirty flag, and the second half's bound reds under a
// throttle break, which is what the name now says.
//
// The DEBOUNCE's own property is a latency lower bound, not a count, and it
// lives in TestDebounceActuallyDelaysActuation8027 — which reds, alone, when
// the debounce is disabled.
//
// This test keeps real time deliberately (#7969 stabilised it there): it is
// the end-to-end exercise of the real timer path, which the fake-clock cells
// do not cover.
func TestActuationCountStaysBoundedUnderFlapStorm(t *testing.T) {
	var actuations atomic.Int32
	e := New(func(context.Context) bool { actuations.Add(1); return true })
	e.debounce = 20 * time.Millisecond
	e.throttle = 60 * time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	// Storm: 10 fail/recover flaps in quick succession.
	results := passResults()
	for i := 0; i < 5; i++ {
		e.HandleTransition(transition("WAN", "wan-a", "fail", results))
		e.HandleTransition(transition("WAN", "wan-a", "pass", results))
	}
	// The debounce fires on its own goroutine, so WHEN the first actuation
	// lands is a scheduling outcome, not a property of the code. The old
	// `time.Sleep(40ms)` sampled at a fixed instant with only a 20ms margin
	// over the 20ms debounce, and under CPU contention that goroutine had not
	// run yet: measured 2 failures in 40 runs at GOMAXPROCS=1 pinned to a busy
	// core, both on the lower bound (#7969).
	//
	// The deadline stays INSIDE the throttle window deliberately. The upper
	// bound below is scoped to ONE window, so waiting longer would admit a
	// second legitimate actuation and break the assertion rather than
	// stabilise it. This is the case where "poll with a generous deadline" is
	// wrong: the generosity has a ceiling, and it is the throttle.
	//
	// Polling the whole window also makes the real assertion STRONGER than the
	// single sample it replaces. Coalescing is violated the moment a third
	// actuation appears, and one late read could miss a third that came and
	// went; this checks the bound continuously across the window.
	const (
		observeWindow = 50 * time.Millisecond // < throttle (60ms), > debounce (20ms)
		pollEvery     = time.Millisecond
	)
	var first int32
	sawActuation := false
	for deadline := time.Now().Add(observeWindow); ; {
		first = actuations.Load()
		if first > 2 {
			t.Fatalf("actuations = %d within one window, want coalesced (<= 2: config-apply + storm)", first)
		}
		if first >= 1 {
			sawActuation = true
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(pollEvery)
	}
	// SETUP GUARD, not the assertion. The property under test is coalescing —
	// the `> 2` bound above. This branch only establishes that anything
	// happened at all, i.e. that the observation window was long enough. Its
	// old message ("no actuation after debounce window") read as a coalescing
	// failure and sent whoever hit it looking for a defect in the engine.
	if !sawActuation {
		t.Fatalf("SETUP GUARD (not a coalescing failure): no actuation observed within %v "+
			"(debounce %v, throttle %v). The debounce goroutine did not get scheduled inside "+
			"the observation window, so the coalescing bound above was never exercised. "+
			"This means the machine was too loaded to sample, not that the engine failed to "+
			"coalesce.", observeWindow, e.debounce, e.throttle)
	}

	// Sustained flapping stays bounded: ≤ 1 actuation per throttle
	// window (plus one carry-over).
	//
	// This half is deliberately left on fixed sleeps (#7969). Its assertion is
	// an UPPER bound, and every way the machine can misbehave — slow
	// scheduling, fewer loop iterations, a late timer — produces FEWER
	// actuations, not more. A slow machine cannot make `total > 6` fire, so
	// there is no sample to stabilise here; the throttle itself bounds the
	// count regardless of timing.
	start := actuations.Load()
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		e.HandleTransition(transition("WAN", "wan-a", "fail", results))
		e.HandleTransition(transition("WAN", "wan-a", "pass", results))
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(80 * time.Millisecond)
	total := actuations.Load() - start
	// 280ms elapsed / 60ms throttle ≈ 4.6 windows; allow slack to 6.
	if total > 6 {
		t.Fatalf("sustained flap produced %d actuations in ~280ms with 60ms throttle, want bounded", total)
	}
}

// TestActuationFailureStaysDirtyUntilConverged is the #3757
// M1/H1/H2/H3 regression: when the actuator reports failure the engine
// must KEEP the state dirty and retry autonomously (throttle-paced),
// then go quiescent once the actuation converges. On revert (dirty
// cleared before/independent of the actuation result) a failing
// actuator would fire exactly once — attempts stays 1 — and this goes
// RED.
func TestActuationFailureStaysDirtyUntilConverged(t *testing.T) {
	var attempts atomic.Int32
	var succeed atomic.Bool // false ⇒ actuation fails; flipped to self-heal
	e := New(func(context.Context) bool {
		attempts.Add(1)
		return succeed.Load()
	})
	e.debounce = 5 * time.Millisecond
	e.throttle = 20 * time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	// A probe failure marks the overlay dirty and actuates — but the
	// actuator keeps failing, so the engine must retry on the next sweep.
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))

	deadline := time.Now().Add(400 * time.Millisecond)
	for attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := attempts.Load(); got < 2 {
		t.Fatalf("attempts = %d while actuation kept failing, want autonomous retry (>=2)", got)
	}

	// Let the actuation converge; the retry loop must settle once the
	// dirty bit clears.
	succeed.Store(true)
	time.Sleep(80 * time.Millisecond) // a few throttle windows to land + clear
	settled := attempts.Load()
	time.Sleep(160 * time.Millisecond) // several more windows
	if extra := attempts.Load() - settled; extra > 1 {
		t.Fatalf("actuation kept firing after convergence: +%d attempts, want quiescent", extra)
	}
}

// TestSuccessfulActuationClearsDirty: a single stable failure with a
// succeeding actuator actuates exactly once (the dirty bit clears on the
// converged actuation and the loop parks) — no retry churn.
func TestSuccessfulActuationClearsDirty(t *testing.T) {
	var attempts atomic.Int32
	e := New(func(context.Context) bool { attempts.Add(1); return true })
	e.debounce = 5 * time.Millisecond
	e.throttle = 20 * time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	time.Sleep(60 * time.Millisecond)
	first := attempts.Load()
	if first < 1 {
		t.Fatal("no actuation after a failure")
	}
	time.Sleep(200 * time.Millisecond) // ~10 throttle windows
	if extra := attempts.Load() - first; extra > 0 {
		t.Fatalf("converged actuation kept retrying: +%d attempts, want 0 (dirty cleared)", extra)
	}
}

// TestUnknownStatusNotReportedAsPass is the #3761 H7 regression: a
// configured policy with no probe result yet is UNKNOWN, not PASS.
// Reporting PASS tells an operator failover protection is active and
// healthy when no probe has run. On revert (Known absent / display
// always PASS) the display carries "Status: PASS" and the UNKNOWN
// assertion goes RED.
func TestUnknownStatusNotReportedAsPass(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), nil) // no probe results seeded yet

	st := e.Status()
	if len(st) != 1 {
		t.Fatalf("want 1 policy, got %d", len(st))
	}
	if st[0].Known {
		t.Fatal("policy reported Known before any probe result")
	}
	if st[0].Failed {
		t.Fatal("policy should not be FAILED with no probe results")
	}

	var buf bytes.Buffer
	FormatStatus(&buf, st)
	out := buf.String()
	if !strings.Contains(out, "Status: UNKNOWN") {
		t.Fatalf("no-probe-data policy not rendered UNKNOWN:\n%s", out)
	}
	if strings.Contains(out, "Status: PASS") {
		t.Fatalf("unknown-health policy rendered as PASS:\n%s", out)
	}

	// Once a passing result lands the policy is Known and PASS.
	e.HandleTransition(transition("WAN", "wan-a", "pass", passResults()))
	st = e.Status()
	if !st[0].Known {
		t.Fatal("policy still Unknown after a probe result")
	}
	buf.Reset()
	FormatStatus(&buf, st)
	if !strings.Contains(buf.String(), "Status: PASS") {
		t.Fatalf("known-passing policy not rendered PASS:\n%s", buf.String())
	}
}

// TestRoutesAppliedReflectsActuationNotDesired is the #3761 H8
// regression: xpf_ipmon_routes_applied / RoutesApplied() must reflect
// what actually converged into the FIBs, not the desired overlay. While
// the actuator keeps failing, nothing is applied even though the desired
// overlay is non-empty. On revert (RoutesApplied returns the desired
// count) the "applied == 0 while failing" assertion goes RED.
func TestRoutesAppliedReflectsActuationNotDesired(t *testing.T) {
	var succeed atomic.Bool // false ⇒ actuator fails
	e := New(func(context.Context) bool { return succeed.Load() })
	e.debounce = 5 * time.Millisecond
	e.throttle = 10 * time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if len(e.ActiveOverlay()) != 2 {
		t.Fatalf("desired overlay = %d, want 2", len(e.ActiveOverlay()))
	}

	// Actuator failing → nothing converged → nothing applied.
	time.Sleep(80 * time.Millisecond)
	if got := e.RoutesApplied(); got != 0 {
		t.Fatalf("RoutesApplied = %d while actuation failing, want 0 (applied != desired)", got)
	}
	for _, ps := range e.Status() {
		if len(ps.AppliedRoutes) != 0 {
			t.Fatalf("AppliedRoutes = %+v while actuation failing, want none", ps.AppliedRoutes)
		}
	}

	// Let it converge; applied catches up to desired.
	succeed.Store(true)
	deadline := time.Now().Add(400 * time.Millisecond)
	for e.RoutesApplied() != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := e.RoutesApplied(); got != 2 {
		t.Fatalf("RoutesApplied = %d after convergence, want 2", got)
	}
}

// TestUnresolvedAndSuppressedDetail is the #3761 M9+M10 regression:
// unresolved (no DHCP next-hop) and suppressed (lost winner resolution)
// candidates are reported distinctly and with detail, not collapsed into
// a bare "(none applied)". On revert (UnresolvedRoutes []string, no
// SuppressedRoutes) this fails to compile / the display lacks the
// distinct rows.
func TestUnresolvedAndSuppressedDetail(t *testing.T) {
	cfg := &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"a-policy": {
			Name: "a-policy", MatchRPMProbe: "P1",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "10.0.0.1", PreferredMetric: 10},
			},
		},
		"b-policy": {
			Name: "b-policy", MatchRPMProbe: "P1",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "10.0.0.2", PreferredMetric: 20},
			},
		},
		"c-policy": {
			Name: "c-policy", MatchRPMProbe: "P1",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "192.0.2.0/24", NextHopInterface: "ge-0-0-3.0", PreferredMetric: 10},
			},
		},
	}}
	e, _ := newTestEngine(nil)
	e.SetNextHopResolver(func(string) (string, bool) { return "", false }) // never resolves
	results := []*rpm.ProbeResult{{ProbeName: "P1", TestName: "t", LastStatus: "fail"}}
	e.Apply(cfg, results)

	byName := map[string]PolicyStatus{}
	for _, ps := range e.Status() {
		byName[ps.Name] = ps
	}

	// a-policy wins the default route on the lower metric.
	if len(byName["a-policy"].Routes) != 1 {
		t.Fatalf("a-policy should win the default route: %+v", byName["a-policy"])
	}
	// b-policy is suppressed by a-policy, not applied and not unresolved.
	b := byName["b-policy"]
	if len(b.Routes) != 0 {
		t.Fatalf("b-policy should not win: %+v", b.Routes)
	}
	if len(b.SuppressedRoutes) != 1 || b.SuppressedRoutes[0].WinnerPolicy != "a-policy" {
		t.Fatalf("b-policy suppressed detail wrong: %+v", b.SuppressedRoutes)
	}
	// c-policy's interface-typed candidate is unresolved with detail.
	ur := byName["c-policy"].UnresolvedRoutes
	if len(ur) != 1 || ur[0].Destination != "192.0.2.0/24" ||
		ur[0].NextHopInterface != "ge-0-0-3.0" || ur[0].Reason == "" {
		t.Fatalf("c-policy unresolved detail wrong: %+v", ur)
	}

	var buf bytes.Buffer
	FormatStatus(&buf, e.Status())
	out := buf.String()
	if !strings.Contains(out, "suppressed by policy a-policy") {
		t.Fatalf("display missing suppressed detail:\n%s", out)
	}
	if !strings.Contains(out, "192.0.2.0/24") || !strings.Contains(out, "unresolved") ||
		!strings.Contains(out, "ge-0-0-3.0") {
		t.Fatalf("display missing unresolved detail:\n%s", out)
	}
}

// TestLifecycleIdempotent is the #3762 regression: the exported engine
// lifecycle must be idempotent. A second Start must be a no-op (H9 — on
// revert it spawns a second run() goroutine whose deferred close(e.done)
// panics after Stop), and Stop must be safe before/without Start (H10 —
// on revert it blocks forever on <-e.done because no run loop exists to
// close it).
func TestLifecycleIdempotent(t *testing.T) {
	// H9: double Start does not spawn a second goroutine (no double
	// close(done) panic), and repeated Stop is safe.
	e := New(func(context.Context) bool { return true })
	e.debounce = time.Millisecond
	e.throttle = time.Millisecond
	e.Start()
	e.Start() // no-op; on revert a second run() → panic on Stop
	time.Sleep(10 * time.Millisecond)
	e.Stop()
	e.Stop() // idempotent, no panic

	// H10: Stop before Start must return promptly, not deadlock.
	e2 := New(func(context.Context) bool { return true })
	stopReturned := make(chan struct{})
	go func() {
		e2.Stop()
		close(stopReturned)
	}()
	select {
	case <-stopReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop before Start deadlocked (H10)")
	}
	// A Start after Stop must be a no-op (no run loop, no panic) and a
	// further Stop stays safe.
	e2.Start()
	e2.Stop()
}

// TestPublishGatingBaseline: standby gating returns a nil overlay
// (baseline) and re-enables on takeover.
func TestPublishGatingBaseline(t *testing.T) {
	var actuations atomic.Int32
	e := New(func(context.Context) bool { actuations.Add(1); return true })
	e.Apply(testPolicyConfig(), passResults())
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("no overlay after failure")
	}

	e.SetPublishEnabled(false)
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v on standby, want nil (baseline)", got)
	}
	// State machine still tracks underneath the gate.
	if st := e.Status(); !st[0].Failed {
		t.Fatal("policy state lost under publication gate")
	}

	e.SetPublishEnabled(true)
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("overlay not restored on takeover")
	}
}

func TestApplyPreservesFailedStateAcrossCommit(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("no overlay after failure")
	}

	// An unrelated commit re-applies the same policy config with a
	// results snapshot that still shows the failing test: FAIL state
	// (and the overlay) must survive.
	results := passResults()
	results[0].LastStatus = "fail"
	e.Apply(testPolicyConfig(), results)
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("overlay wiped by an unrelated commit (AGY r2-2 scenario)")
	}
	if !e.Status()[0].Failed {
		t.Fatal("FAIL state lost across Apply")
	}

	// Removing the policy clears everything.
	e.Apply(&config.IPMonitoringConfig{}, results)
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after policy removal", got)
	}
}

// TestApplyNilResultsPreservesFailedStateButEmptyClears verifies the
// distinction between an unavailable snapshot (nil) and an authoritative
// empty snapshot. Lost results must not silently recover a live FAILED policy.
func TestApplyNilResultsPreservesFailedStateButEmptyClears(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	if !e.Status()[0].Failed {
		t.Fatal("setup: policy not FAILED after a failing probe")
	}
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("setup: no overlay after failure")
	}

	// Missing results are not an authoritative statement that all probes
	// recovered; preserve the known failure and its failover route.
	e.Apply(testPolicyConfig(), nil)
	if !e.Status()[0].Failed {
		t.Fatal("nil results cleared the live FAILED state")
	}
	if got := e.ActiveOverlay(); len(got) == 0 {
		t.Fatal("nil results withdrew the failover overlay")
	}
	if !e.Status()[0].Known {
		t.Fatal("policy became UNKNOWN despite its preserved failed test")
	}

	// A non-nil empty slice explicitly says there are no current results,
	// so it clears the old test state and recovers the policy.
	e.Apply(testPolicyConfig(), []*rpm.ProbeResult{})
	if e.Status()[0].Failed {
		t.Fatal("authoritative empty results did not clear FAIL")
	}
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("overlay = %+v after authoritative empty results, want withdrawn", got)
	}
	if e.Status()[0].Known {
		t.Fatal("policy still reported Known after authoritative empty results")
	}
}

// TestNotifyNextHopChangeGatedOffStandby is the #4423 M4 regression:
// while publication is gated off (HA standby) a DHCP gateway change must
// NOT schedule an actuation — the published overlay is the baseline
// (nil) regardless of the lease, so recomputing/actuating is wasted
// frr-reload + snapshot churn on the standby. On revert (NotifyNextHopChange
// ignores publishEnabled) the gated-off gateway change actuates and the
// "no new actuation" assertion goes RED.
func TestNotifyNextHopChangeGatedOffStandby(t *testing.T) {
	var actuations atomic.Int32
	e := New(func(context.Context) bool { actuations.Add(1); return true })
	e.debounce = 5 * time.Millisecond
	e.throttle = 5 * time.Millisecond
	r := &fakeResolver{}
	r.set("ge-0-0-3", "198.51.100.1")
	e.SetNextHopResolver(r.resolve)
	e.Apply(dhcpPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	// Fail an interface-typed policy, then gate publication off (standby).
	failWAN(e)
	e.SetPublishEnabled(false)
	time.Sleep(50 * time.Millisecond) // let the failure + gate-off actuations settle
	base := actuations.Load()

	// A DHCP gateway change while gated off must not actuate.
	r.set("ge-0-0-3", "198.51.100.254")
	for i := 0; i < 3; i++ {
		e.NotifyNextHopChange()
	}
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got != base {
		t.Fatalf("NotifyNextHopChange actuated while publication gated off: %d -> %d (M4)", base, got)
	}

	// On takeover the overlay follows the fresh lease again.
	e.SetPublishEnabled(true)
	deadline := time.Now().Add(2 * time.Second)
	for actuations.Load() == base && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if actuations.Load() == base {
		t.Fatal("takeover did not actuate after a gated-off gateway change")
	}
}

// TestActuationTimeoutRetriesWithoutStop is the #4423 L (bounded actuator
// timeout) regression: a wedged actuation must be aborted by the bounded
// per-actuation timeout and retried WITHOUT waiting for Stop, so a stuck
// consumer cannot hold the run loop off its retry indefinitely while the
// daemon is up. On revert (actuate runs under the un-timed e.actuateCtx)
// the first actuation blocks until Stop and the second attempt never
// happens — attempts stays 1 and the retry assertion goes RED. It also
// asserts the failure counter climbs across the wedged retries.
func TestActuationTimeoutRetriesWithoutStop(t *testing.T) {
	var attempts atomic.Int32
	var unblock atomic.Bool
	e := New(func(ctx context.Context) bool {
		attempts.Add(1)
		if unblock.Load() {
			return true
		}
		<-ctx.Done() // wedged: unblocks only on the bounded timeout (or Stop)
		return false
	})
	e.debounce = 2 * time.Millisecond
	e.throttle = 5 * time.Millisecond
	e.actuateTimeout = 20 * time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()
	defer e.Stop()

	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))

	deadline := time.Now().Add(2 * time.Second)
	for attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := attempts.Load(); got < 2 {
		t.Fatalf("attempts = %d — bounded actuation timeout did not fire, no retry without Stop", got)
	}
	if e.ActuationFailures() == 0 {
		t.Fatal("ActuationFailures still 0 while actuations kept timing out")
	}

	// Convergence quiesces the loop.
	unblock.Store(true)
	time.Sleep(120 * time.Millisecond)
	settled := attempts.Load()
	time.Sleep(120 * time.Millisecond)
	if extra := attempts.Load() - settled; extra > 1 {
		t.Fatalf("kept firing after convergence: +%d attempts, want quiescent", extra)
	}
}

// TestFilterOverlayForConfig is the Codex PR #1843 HIGH-1 regression
// test: a commit that removes a policy or edits its preferred-route
// spec must not republish the stale overlay entries on the commit's
// own publish; an unrelated commit preserves the overlay.
func TestFilterOverlayForConfig(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), passResults())
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	overlay := e.ActiveOverlay()
	if len(overlay) != 2 {
		t.Fatalf("setup: overlay = %+v", overlay)
	}

	// Unrelated commit: identical policy spec → preserved verbatim.
	kept := FilterOverlayForConfig(overlay, testPolicyConfig())
	if len(kept) != 2 {
		t.Fatalf("unrelated commit dropped overlay entries: %+v", kept)
	}

	// Commit removes the policy → overlay entries absent.
	if got := FilterOverlayForConfig(overlay, &config.IPMonitoringConfig{}); got != nil {
		t.Fatalf("removed policy still riding the commit: %+v", got)
	}
	if got := FilterOverlayForConfig(overlay, nil); got != nil {
		t.Fatalf("nil ip-monitoring config still riding the commit: %+v", got)
	}

	// Commit edits the master route's next-hop → the OLD hop is
	// dropped; the untouched ISP-B entry survives.
	edited := testPolicyConfig()
	edited.Policies["wan-failover"].PreferredRoutes[0].NextHop = "172.16.80.99"
	kept = FilterOverlayForConfig(overlay, edited)
	if len(kept) != 1 || kept[0].RoutingInstance != "ISP-B" {
		t.Fatalf("edited next-hop: kept = %+v, want only the ISP-B entry", kept)
	}
	for _, entry := range kept {
		if entry.NextHop == "172.16.80.1" && entry.RoutingInstance == "" {
			t.Fatalf("stale master next-hop survived the edit: %+v", kept)
		}
	}

	// Commit edits the preferred-metric → spec changed → dropped.
	edited = testPolicyConfig()
	edited.Policies["wan-failover"].PreferredRoutes[0].PreferredMetric = 99
	kept = FilterOverlayForConfig(overlay, edited)
	if len(kept) != 1 || kept[0].RoutingInstance != "ISP-B" {
		t.Fatalf("edited metric: kept = %+v, want only the ISP-B entry", kept)
	}

	// Non-canonical but equivalent prefix spelling still matches.
	equiv := testPolicyConfig()
	equiv.Policies["wan-failover"].PreferredRoutes[0].Destination = "0.0.0.0/0"
	kept = FilterOverlayForConfig(overlay, equiv)
	if len(kept) != 2 {
		t.Fatalf("canonical-equivalent prefix dropped: %+v", kept)
	}
}

// TestApplyWithoutOverlayChangeDoesNotActuate (Codex PR #1843 MED):
// a commit with zero policies — or any commit that leaves the
// effective overlay unchanged — must not schedule a routes-only
// actuation (one spurious frr-reload per commit otherwise).
func TestApplyWithoutOverlayChangeDoesNotActuate(t *testing.T) {
	var actuations atomic.Int32
	e := New(func(context.Context) bool { actuations.Add(1); return true })
	e.debounce = 5 * time.Millisecond
	e.throttle = 5 * time.Millisecond
	e.Start()
	defer e.Stop()

	// No-policy commits: nothing to actuate.
	e.Apply(&config.IPMonitoringConfig{}, nil)
	e.Apply(nil, nil)
	// Policies present but all passing (overlay nil before and after).
	e.Apply(testPolicyConfig(), passResults())
	e.Apply(testPolicyConfig(), passResults())
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got != 0 {
		t.Fatalf("actuations = %d after overlay-neutral commits, want 0", got)
	}

	// A real failure still actuates...
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got == 0 {
		t.Fatal("real failure did not actuate")
	}

	// ...and an unrelated re-Apply with the overlay active (same
	// spec, still-failing results) stays quiet.
	before := actuations.Load()
	results := passResults()
	results[0].LastStatus = "fail"
	e.Apply(testPolicyConfig(), results)
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got != before {
		t.Fatalf("unrelated commit actuated: %d -> %d", before, got)
	}

	// A spec edit while FAILED changes the overlay → actuates (the
	// HIGH-1 re-injection path).
	edited := testPolicyConfig()
	edited.Policies["wan-failover"].PreferredRoutes[0].NextHop = "172.16.80.99"
	e.Apply(edited, results)
	time.Sleep(60 * time.Millisecond)
	if got := actuations.Load(); got == before {
		t.Fatal("overlay-changing spec edit did not actuate")
	}
}

// TestStopAbortsBlockedActuation is the #3758 regression: a shutdown
// (ipmon.Stop, via the daemon teardown) must abort an in-flight
// actuation that is blocked on a wait — the apply semaphore held by
// an unrelated apply, or a wedged FRR reload — instead of wedging the
// run loop off its stop case forever. The run loop calls the actuator
// synchronously and can only observe e.stop AFTER the actuator
// returns, so Stop cancels the actuation context BEFORE waiting on
// e.done. This test drives one actuation whose actuator blocks until
// its context is cancelled; Stop must then return promptly. On revert
// (Stop does not cancel the context, or the actuator ignores it) the
// actuation never unblocks, run() never returns, and Stop hangs on
// e.done — the watchdog timeout below fires and the test goes RED.
func TestStopAbortsBlockedActuation(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	e := New(func(ctx context.Context) bool {
		once.Do(func() { close(entered) })
		<-ctx.Done() // block until Stop cancels the actuation context
		return false // aborted: do not half-actuate
	})
	e.debounce = time.Millisecond
	e.throttle = time.Millisecond
	e.Apply(testPolicyConfig(), passResults())
	e.Start()

	// Drive one actuation and wait until the actuator is blocked inside.
	e.HandleTransition(transition("WAN", "wan-a", "fail", passResults()))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		e.Stop()
		t.Fatal("actuator was never entered")
	}

	// Stop must return promptly even though the actuation is blocked.
	done := make(chan struct{})
	go func() {
		e.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ipmon.Stop hung behind a blocked actuation (#3758 shutdown-hang regression)")
	}
}
