package daemon

// daemon_goroutine_shutdown_5523_test.go — #5523 C179-093 regression coverage.
//
// Two more daemon background goroutines were NOT covered by the run WaitGroup
// and leaked at shutdown, so a late tick could run against a torn-down
// subsystem and (for the aggregator) the #5313 final flush was skipped:
//
//   - the session-aggregation flush goroutine (applyAggregator → agg.Run),
//     which binds to context.Background() and was cancelled only via aggCancel
//     on a config replace/disable — never at shutdown; and
//   - the IPsec DHCP-rebind retry loop (ipsecRebindRetryLoop), which bound
//     directly to d.daemonCtx (the raw background ctx, never cancelled in
//     production, #5807), so a 30s rebind tick could race teardown.
//
// The shutdown sequence now cancels + JOINS both (stopAggregator /
// stopIPsecRebindLoop) BEFORE the dependent subsystems are torn down, mirroring
// the #5308 stopPolicySchedulerLoop / stopPinRetryLoop. The stop helpers are
// exercised via joinWithin (defined in daemon_goroutine_shutdown_5308_test.go)
// so a revert turns the resulting hang into a fast t.Fatal (RED).

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// TestStopAggregatorCancelsAndJoins proves the session-aggregation flush
// goroutine is cancelled + joined at shutdown even though it binds to
// context.Background() (never cancelled by the run WaitGroup or the signal ctx).
//
// RED-on-revert: dropping the cancel from stopAggregator leaves agg.Run parked
// on its 5-min flush ticker with an uncancelled context, so aggWg.Wait blocks
// and joinWithin trips its 3s bound.
func TestStopAggregatorCancelsAndJoins(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Security.Log.Report = true

	d.applyAggregator(er, cfg)
	if d.aggCancel == nil {
		t.Fatal("enabling reporting must arm the aggregator (aggCancel set)")
	}
	if d.aggregatorPtr.Load() == nil {
		t.Fatal("enabling reporting must publish a live aggregator")
	}

	joinWithin(t, 3*time.Second, d.stopAggregator,
		"stopAggregator did not cancel+join the aggregator flush goroutine — "+
			"leaked / bound to the never-cancelled context.Background (C179-093)")

	if d.aggCancel != nil {
		t.Error("stopAggregator must clear aggCancel")
	}
	if d.aggregatorPtr.Load() != nil {
		t.Error("stopAggregator must nil the published aggregator pointer")
	}

	// aggStopped must latch: a late report-enabled apply must NOT start a new
	// generation (which would race aggWg.Wait).
	d.applyAggregator(er, cfg)
	if d.aggCancel != nil || d.aggregatorPtr.Load() != nil {
		t.Error("applyAggregator after stopAggregator must be a no-op (aggStopped latch)")
	}
}

// TestStopIPsecRebindLoopCancelsJoinsNoLateApply proves the IPsec DHCP-rebind
// retry loop is cancelled + joined at shutdown and runs NO swanctl reapply past
// the join, even though its parent d.daemonCtx is never cancelled in production.
//
// RED-on-revert: rebinding armIPsecRebind's goroutine to d.daemonCtx (the
// pre-fix `go d.ipsecRebindRetryLoop(d.daemonCtx)`, untracked) leaves the loop
// listening on a context that never fires and untracked by ipsecRebindWg, so the
// loop keeps ticking after the "join" and the post-join call-count assertion
// trips; dropping the cancel makes joinWithin's 3s bound trip instead.
func TestStopIPsecRebindLoopCancelsJoinsNoLateApply(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	joined := false // set true only after the join returns (teardown marker)
	callsAfterJoin := 0

	d, cancel := newIPsecRebindDaemon(t, func(*config.Config) error {
		mu.Lock()
		calls++
		if joined {
			callsAfterJoin++
		}
		mu.Unlock()
		// Keep failing so the loop never self-converges — only the shutdown
		// cancel may stop it.
		return errors.New("swanctl --load-all: charon down")
	})
	t.Cleanup(cancel)

	// Arm the loop via a failed lease-change rebind on the live path.
	d.managementOnlyLeaseRefresh()
	d.ipsecRebindMu.Lock()
	active := d.ipsecRebindRetryActive
	d.ipsecRebindMu.Unlock()
	if !active {
		t.Fatal("rebind retry loop did not start after a failed lease-change rebind")
	}

	// Confirm the loop is genuinely ticking (not just the synchronous first
	// attempt from the lease callback).
	waitFor(t, 3*time.Second, "rebind retry loop to tick past the initial attempt",
		func() bool {
			mu.Lock()
			defer mu.Unlock()
			return calls >= 3
		})

	// Shutdown cancel + join, bounded so a revert fails fast.
	joinWithin(t, 3*time.Second, d.stopIPsecRebindLoop,
		"stopIPsecRebindLoop did not cancel+join the loop — leaked / bound to the "+
			"never-cancelled daemonCtx (C179-093)")

	// Mark the teardown boundary: no swanctl reapply may run past here.
	mu.Lock()
	joined = true
	mu.Unlock()

	// Several retry intervals (2ms cadence) must elapse with ZERO further calls.
	time.Sleep(40 * time.Millisecond)
	mu.Lock()
	after := callsAfterJoin
	mu.Unlock()
	if after != 0 {
		t.Fatalf("rebind retry loop ran %d swanctl reapply(s) AFTER shutdown cancel+join "+
			"(loop leaked / not joined)", after)
	}

	// ipsecRebindStopped must latch: a late arm cannot restart the loop (which
	// would race ipsecRebindWg.Wait).
	d.armIPsecRebind()
	d.ipsecRebindMu.Lock()
	restarted := d.ipsecRebindRetryActive
	d.ipsecRebindMu.Unlock()
	if restarted {
		t.Fatal("rebind retry loop restarted after shutdown — ipsecRebindStopped did not latch")
	}
}

// TestStopAggregatorAndIPsecRebindIdempotentNilSafe proves both new stop helpers
// are safe on a daemon whose loops were never started (feature disabled), and
// safe to call twice (the shutdown sequence runs them, then Run's defers run
// them again).
func TestStopAggregatorAndIPsecRebindIdempotentNilSafe(t *testing.T) {
	d := &Daemon{}
	joinWithin(t, time.Second, d.stopAggregator, "stopAggregator blocked with no aggregator running")
	joinWithin(t, time.Second, d.stopIPsecRebindLoop, "stopIPsecRebindLoop blocked with no loop running")
	joinWithin(t, time.Second, d.stopAggregator, "second stopAggregator blocked")
	joinWithin(t, time.Second, d.stopIPsecRebindLoop, "second stopIPsecRebindLoop blocked")
}
