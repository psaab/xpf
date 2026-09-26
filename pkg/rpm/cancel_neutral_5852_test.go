// cancel_neutral_5852_test.go — #5852: a LIFECYCLE cancellation of the shared
// probe context (StopAll / config replacement / daemon shutdown) that interrupts
// an in-flight probe must be NEUTRAL to path health — no counters, no
// successive-loss advance, no ping_probe_failed / ping_test_failed event, no
// per-test transition callback — so services ip-monitoring never remediates routes during
// teardown/reconfigure. A GENUINE probe timeout/failure (the shared context NOT
// cancelled) must still count as path loss, so real remediation is unaffected.
package rpm

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func cancelNeutralTest() *config.RPMTest {
	return &config.RPMTest{Name: "t", Target: "192.0.2.10"}
}

func seedPassingResult(m *Manager) {
	m.results["WAN/t"] = &ProbeResult{
		ProbeName: "WAN", TestName: "t", ProbeType: "icmp-ping",
		Target: "192.0.2.10", LastStatus: "pass",
	}
}

// TestRunSingleTestLifecycleCancelIsNeutral5852 cancels the shared probe context
// from inside the in-flight probe (modelling StopAll's m.cancel() landing
// mid-ReadFrom) and asserts the cancelled probe leaves path health untouched:
// no counters, no events, no transition.
//
// Fail-on-revert: remove the `ctx.Err() != nil` neutral check and the cancelled
// probe is counted as a failure — TotalSent/SuccFail advance, ping_probe_failed
// fires, and (threshold 1, probeCount 1) the loss threshold trips → status flips
// pass→fail → ping_test_failed + the transition callback (route remediation at teardown).
func TestRunSingleTestLifecycleCancelIsNeutral5852(t *testing.T) {
	m := New()

	var transitions, events atomic.Int32
	m.SetTransitionCallback(func(Transition) { transitions.Add(1) })
	m.SetEventCallback(func(Event) { events.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The probe is interrupted by a lifecycle stop: cancel the shared context
	// and return its error, exactly as icmp.go does when ctx.Err() != nil.
	m.probeFn = func(pctx context.Context, _ *config.RPMTest, _ string) (time.Duration, error) {
		cancel()
		return 0, pctx.Err()
	}

	seedPassingResult(m)
	// probeCount 1, threshold 1: a mis-counted cancel would immediately trip a
	// pass→fail transition, so the neutral behavior is unambiguous.
	m.runSingleTest(ctx, "WAN", cancelNeutralTest(), "WAN/t", 1, 0, 1)

	r := m.results["WAN/t"]
	if r.TotalSent != 0 || r.TotalRecv != 0 || r.SuccFail != 0 {
		t.Fatalf("lifecycle cancel advanced counters: %+v", r)
	}
	if r.LastStatus != "pass" || !r.LastProbeAt.IsZero() {
		t.Fatalf("lifecycle cancel mutated path state: LastStatus=%q LastProbeAt=%v", r.LastStatus, r.LastProbeAt)
	}
	if transitions.Load() != 0 {
		t.Fatalf("lifecycle cancel fired %d transitions (route remediation during teardown), want 0", transitions.Load())
	}
	if events.Load() != 0 {
		t.Fatalf("lifecycle cancel fired %d events (ping_probe_failed/ping_test_failed), want 0", events.Load())
	}
}

// TestRunSingleTestGenuineFailureStillCounts5852 proves the fix does NOT
// over-neutralize: a real probe timeout — a per-probe socket-deadline error
// while the shared context stays LIVE (the target is actually unreachable) —
// still counts as path loss and fires the fail transition.
func TestRunSingleTestGenuineFailureStillCounts5852(t *testing.T) {
	m := New()

	var transitions int32
	statusCh := make(chan string, 4)
	m.SetTransitionCallback(func(tr Transition) { atomic.AddInt32(&transitions, 1); statusCh <- tr.Status })
	var events int32
	m.SetEventCallback(func(Event) { atomic.AddInt32(&events, 1) })

	// A genuine probe timeout: a net-timeout-shaped error (icmp.go's
	// "icmp echo ... timed out: <i/o timeout>"). The shared context is NEVER
	// cancelled, so this is real path loss, not a lifecycle stop.
	m.probeFn = func(_ context.Context, _ *config.RPMTest, _ string) (time.Duration, error) {
		return 0, fmt.Errorf("icmp echo to 192.0.2.10 timed out: i/o timeout")
	}

	seedPassingResult(m)
	m.runSingleTest(context.Background(), "WAN", cancelNeutralTest(), "WAN/t", 1, 0, 1)

	r := m.results["WAN/t"]
	if r.TotalSent != 1 || r.SuccFail != 1 || r.LastStatus != "fail" {
		t.Fatalf("genuine failure was not counted as path loss: %+v", r)
	}
	if atomic.LoadInt32(&transitions) != 1 {
		t.Fatalf("genuine failure fired %d transitions, want 1", atomic.LoadInt32(&transitions))
	}
	if atomic.LoadInt32(&events) != 2 {
		t.Fatalf("genuine failure fired %d events, want 2 (ping_probe_failed + ping_test_failed)", atomic.LoadInt32(&events))
	}
	select {
	case st := <-statusCh:
		if st != "fail" {
			t.Fatalf("genuine failure transition status = %q, want fail", st)
		}
	default:
		t.Fatal("expected a fail transition from a genuine probe failure")
	}
}

// TestRunSingleTestProbeDeadlineWithLiveCtxCounts5852 pins the timeout-vs-cancel
// distinction precisely: a probe that surfaces context.DeadlineExceeded from its
// OWN timeout while the SHARED context is NOT cancelled MUST still count as a
// failure. The neutral classification keys off the shared ctx.Err(), NOT the
// returned error type, so a probe-owned DeadlineExceeded is never mistaken for a
// lifecycle stop (over-neutralization guard).
func TestRunSingleTestProbeDeadlineWithLiveCtxCounts5852(t *testing.T) {
	m := New()
	var events int32
	m.SetEventCallback(func(Event) { atomic.AddInt32(&events, 1) })

	m.probeFn = func(_ context.Context, _ *config.RPMTest, _ string) (time.Duration, error) {
		// Probe-owned deadline (NOT the shared context's) — real path loss.
		return 0, fmt.Errorf("probe timed out: %w", context.DeadlineExceeded)
	}

	seedPassingResult(m)
	// Shared context stays live (never cancelled).
	m.runSingleTest(context.Background(), "WAN", cancelNeutralTest(), "WAN/t", 1, 0, 1)

	if r := m.results["WAN/t"]; r.TotalSent != 1 || r.SuccFail != 1 || r.LastStatus != "fail" {
		t.Fatalf("a probe-owned DeadlineExceeded (live shared ctx) must count as path loss: %+v", r)
	}
	if got := atomic.LoadInt32(&events); got != 2 {
		t.Fatalf("probe-owned deadline fired %d events, want 2 (probe_failed + test_failed)", got)
	}
	// Sanity: the shared context really was never cancelled.
	if errors.Is(context.Background().Err(), context.Canceled) {
		t.Fatal("test bug: background ctx should not be cancelled")
	}
}
