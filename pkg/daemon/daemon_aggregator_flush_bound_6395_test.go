package daemon

// daemon_aggregator_flush_bound_6395_test.go — #6395 regression coverage.
//
// stopAggregator's cancel triggers SessionAggregator.Run's #5313 ctx.Done final
// flush, which forwards the pending report through `er.ForwardLogMsg`. Before
// #16083 the syslog branch was synchronous (up to defaultWriteTimeout ~4s per
// line against a stalled collector); it now queues on the bounded writer, and
// the synchronous local-writer branch remains. stopAggregator runs in
// runShutdownSequence BEFORE the HA takeover fence, so before #6395 the plain
// `d.aggWg.Wait()` join was UNBOUNDED: a stalled sink could delay the fence
// long enough to blow the systemd 20s TimeoutStopSec and get the process
// SIGKILLed before the peer takeover ran.
//
// The join is now bounded by aggregatorFlushJoinTimeout. These tests prove the
// bound fires on a stalled flush (RED-on-revert: reverting to a plain
// d.aggWg.Wait() blocks forever, so the stop never returns and the generous
// in-test timeout trips a clean t.Fatal) and that the happy path — a fast flush
// — is not penalized by the bound.

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// armBlockableAggregator arms an aggregator on d the way applyAggregator does
// (published pointer + cancel + tracked flush goroutine) but with a caller-
// supplied logFn, and seeds one SESSION_CLOSE so the #5313 final flush actually
// emits a line (an empty window flushes as a no-op and would never exercise the
// forward). Returns nothing; the caller drives d.stopAggregator().
func armBlockableAggregator(t *testing.T, d *Daemon, logFn func(int, string)) {
	t.Helper()
	agg := logging.NewSessionAggregator(time.Hour, 10)
	agg.SetLogFunc(logFn)
	agg.Add(logging.EventRecord{
		Type:         "SESSION_CLOSE",
		SrcAddr:      "10.0.1.5:443",
		DstAddr:      "10.0.2.5:80",
		SessionBytes: 4096,
	})

	ctx, cancel := context.WithCancel(context.Background())
	d.aggregatorPtr.Store(agg)
	d.aggCancel = cancel
	d.aggWg.Add(1)
	go func() {
		defer d.aggWg.Done()
		agg.Run(ctx)
	}()
}

// TestStopAggregatorBoundsStalledFinalFlush proves stopAggregator RETURNS within
// its bound even when the final flush's forward is wedged (a stalled syslog
// sink), so the shutdown fence downstream is never starved.
//
// RED-on-revert: replacing the bounded select with a plain `d.aggWg.Wait()`
// makes stopAggregator block on the parked flush forever, the `done` channel
// below never closes, and the generous select trips t.Fatal.
func TestStopAggregatorBoundsStalledFinalFlush(t *testing.T) {
	d := &Daemon{}

	// A wedged sink: the final flush's logFn parks until the test tears down,
	// modeling a stalled/unreachable stream-syslog collector. `entered` proves
	// the flush genuinely reached the blocking forward (so the bound, not an
	// empty flush, is what let stopAggregator return).
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	entered := make(chan struct{}, 1)
	armBlockableAggregator(t, d, func(int, string) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	})

	// Drive stopAggregator off the test goroutine so a reverted (unbounded) join
	// surfaces as a clean timeout rather than hanging the whole suite.
	done := make(chan struct{})
	start := time.Now()
	go func() {
		d.stopAggregator()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		// The bound must have fired: the sink is still wedged (release is only
		// closed in cleanup, after this returns), so a return here can only mean
		// the aggregatorFlushJoinTimeout select proceeded past the stalled join.
		if elapsed < aggregatorFlushJoinTimeout {
			t.Fatalf("stopAggregator returned in %s, before the %s bound — the "+
				"stalled flush was not actually exercised", elapsed, aggregatorFlushJoinTimeout)
		}
	case <-time.After(aggregatorFlushJoinTimeout + 5*time.Second):
		t.Fatal("stopAggregator did not return — the final-flush join is UNBOUNDED; " +
			"a stalled syslog sink blocks shutdown BEFORE the HA takeover fence and " +
			"can blow the systemd 20s stop budget (#6395)")
	}

	select {
	case <-entered:
	default:
		t.Fatal("the #5313 final flush never reached the log forward — the bound " +
			"passed trivially instead of over a genuinely stalled flush")
	}

	// The stall bound still clears the published handles + latches aggStopped
	// exactly as the unbounded path did.
	if d.aggCancel != nil {
		t.Error("stopAggregator must clear aggCancel even on a bounded (timed-out) join")
	}
	if d.aggregatorPtr.Load() != nil {
		t.Error("stopAggregator must nil the published aggregator pointer even on a bounded join")
	}
	if !d.aggStopped {
		t.Error("stopAggregator must latch aggStopped even on a bounded join")
	}
}

// TestStopAggregatorFastFlushNotPenalized proves the bound does not slow the
// normal case: a flush whose forward returns promptly joins in well under the
// budget (the select takes the `done` branch, not `time.After`).
func TestStopAggregatorFastFlushNotPenalized(t *testing.T) {
	d := &Daemon{}
	armBlockableAggregator(t, d, func(int, string) { /* returns immediately */ })

	done := make(chan struct{})
	start := time.Now()
	go func() {
		d.stopAggregator()
		close(done)
	}()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed >= aggregatorFlushJoinTimeout {
			t.Fatalf("stopAggregator took %s for a fast flush — the bound must not "+
				"delay the happy path (budget %s)", elapsed, aggregatorFlushJoinTimeout)
		}
	case <-time.After(aggregatorFlushJoinTimeout):
		t.Fatal("stopAggregator did not join a fast (non-blocking) flush before the bound")
	}
}
