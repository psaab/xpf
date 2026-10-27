package daemon

// daemon_shutdown_wiring_5523_test.go — #5523 C179-093 WIRING regression.
//
// The existing #5523 coverage (daemon_goroutine_shutdown_5523_test.go) calls
// d.stopAggregator() / d.stopIPsecRebindLoop() DIRECTLY, so it binds the helper
// MECHANICS but not the CALL SITES. Deleting the wiring — the two stop calls in
// runShutdownSequence (daemon_run_shutdown.go) AND the matching Run() defers
// (daemon_run.go) — fully reintroduces the bug the PR fixes (a leaked
// aggregator flush goroutine + a skipped #5313 final flush + a leaked IPsec
// DHCP-rebind loop) while that direct-method suite stays GREEN.
//
// This test DRIVES runShutdownSequence itself (never the stop helpers directly)
// with an armed aggregator + an actively ticking IPsec rebind loop, and asserts
// the OBSERVABLE post-shutdown state that only the wiring produces.

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/logging"
)

// TestRunShutdownSequenceStopsAggregatorAndIPsecRebind proves the #5523 fix is
// WIRED into the real teardown path: runShutdownSequence must cancel + join the
// session-aggregation flush goroutine and the IPsec DHCP-rebind retry loop, both
// of which live OUTSIDE the run WaitGroup (the aggregator binds to
// context.Background, cancelled only via aggCancel; the rebind loop binds to a
// child of d.daemonCtx, never cancelled in production).
//
// RED-on-revert: commenting out the d.stopAggregator() / d.stopIPsecRebindLoop()
// calls in runShutdownSequence (and the matching defers in Run) leaves aggCancel
// and aggregatorPtr non-nil and the rebind loop active + still ticking swanctl
// reapplies after the sequence returns, so every assertion below fires with a
// clean message. The pre-existing direct-method tests are unaffected either way.
func TestRunShutdownSequenceStopsAggregatorAndIPsecRebind(t *testing.T) {
	// A real (empty) store so runShutdownSequence's d.store.ActiveConfig() does
	// not nil-panic. A fresh store's ActiveConfig() is nil — the standalone,
	// non-HA case — which drives the hitless teardown branch with d.dp == nil.
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}

	// daemonCtx is the parent the rebind loop binds a cancellable child to; it
	// is never cancelled by the shutdown sequence itself (only stopIPsecRebindLoop
	// cancels the child), so a REVERTED wiring genuinely keeps the loop alive.
	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	t.Cleanup(cancelDaemon)

	var mu sync.Mutex
	calls := 0
	sequenceReturned := false // set true only after runShutdownSequence returns
	callsAfterSequence := 0

	d := &Daemon{
		store:                 store,
		applySem:              semaphore.NewWeighted(1),
		daemonCtx:             daemonCtx,
		ipsec:                 ipsec.New(),
		ipsecRebindActiveCfg:  func() *config.Config { return dhcpBoundIPsecConfig() },
		ipsecRebindRetryEvery: 2 * time.Millisecond,
	}
	d.ipsecApply = func(*config.Config) error {
		mu.Lock()
		calls++
		if sequenceReturned {
			callsAfterSequence++
		}
		mu.Unlock()
		// Keep failing so the loop never self-converges: only the shutdown
		// wiring may stop it.
		return errors.New("swanctl --load-all: charon down")
	}

	// Arm the session-aggregation flush goroutine (applyAggregator -> agg.Run),
	// which binds to context.Background() and is cancelled only via aggCancel.
	er := logging.NewEventReader(nil, nil)
	repCfg := &config.Config{}
	repCfg.Security.Log.Report = true
	d.applyAggregator(er, repCfg)
	if d.aggCancel == nil || d.aggregatorPtr.Load() == nil {
		t.Fatal("precondition: enabling reporting must arm + publish the aggregator")
	}

	// Arm the IPsec DHCP-rebind retry loop via a failing lease-change
	// rebind, driven under a test-held applySem as
	// managementOnlyLeaseRefresh does in production (#17071).
	func() {
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatalf("acquire applySem: %v", err)
		}
		defer d.applySem.Release(1)
		d.reapplyIPsecLocked(dhcpBoundIPsecConfig())
	}()
	d.ipsecRebindMu.Lock()
	active := d.ipsecRebindRetryActive
	d.ipsecRebindMu.Unlock()
	if !active {
		t.Fatal("precondition: a failed lease-change rebind must arm the retry loop")
	}
	// Confirm the loop is genuinely ticking (not just the synchronous first
	// lease-callback attempt) before we drive shutdown, so the RED case has a
	// live goroutine to keep ticking past the sequence.
	waitFor(t, 3*time.Second, "rebind retry loop to tick past the initial attempt",
		func() bool {
			mu.Lock()
			defer mu.Unlock()
			return calls >= 3
		})

	// Drive the ACTUAL production teardown path. runShutdownSequence — NOT the
	// stop helpers — is where the #5523 fix wired the two stops in. Run the
	// sequence in a goroutine bounded by a generous timeout: a reverted wiring
	// does not itself hang the sequence (the loops just keep running), so this
	// bound is only a safety net; the real signal is the post-return state.
	var wg sync.WaitGroup // empty: this harness starts no run-WaitGroup goroutines
	_, stopRun := context.WithCancel(context.Background())
	sentinel := errors.New("run-error-passthrough")

	done := make(chan error, 1)
	go func() { done <- d.runShutdownSequence(context.Background(), &wg, stopRun, sentinel) }()

	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runShutdownSequence did not return within 10s")
	}

	// Mark the teardown boundary: with the wiring intact the loop is already
	// joined (dead) here, so no swanctl reapply may run past this point.
	mu.Lock()
	sequenceReturned = true
	mu.Unlock()

	if runErr != sentinel {
		t.Errorf("runShutdownSequence must pass runErr through unchanged: got %v, want %v",
			runErr, sentinel)
	}

	// Aggregator wiring: d.stopAggregator() inside runShutdownSequence must have
	// cancelled the flush goroutine (triggering its #5313 ctx.Done final flush)
	// and nilled the published pointer.
	if d.aggCancel != nil {
		t.Error("runShutdownSequence left aggCancel non-nil — the stopAggregator " +
			"call site was dropped, re-leaking the aggregator flush goroutine and " +
			"skipping its #5313 final flush (#5523 C179-093 wiring regression)")
	}
	if d.aggregatorPtr.Load() != nil {
		t.Error("runShutdownSequence left aggregatorPtr non-nil — the stopAggregator " +
			"call site was dropped (#5523 C179-093 wiring regression)")
	}

	// IPsec rebind wiring: d.stopIPsecRebindLoop() inside runShutdownSequence
	// must have disarmed AND joined the loop.
	d.ipsecRebindMu.Lock()
	stillActive := d.ipsecRebindRetryActive
	d.ipsecRebindMu.Unlock()
	if stillActive {
		t.Error("runShutdownSequence left ipsecRebindRetryActive true — the " +
			"stopIPsecRebindLoop call site was dropped, re-leaking the daemonCtx-bound " +
			"retry loop (#5523 C179-093 wiring regression)")
	}

	// Joined, not merely flagged: several retry intervals (2ms cadence) must
	// elapse with ZERO further swanctl reapplies. A reverted wiring leaves the
	// loop ticking, so callsAfterSequence climbs.
	time.Sleep(40 * time.Millisecond)
	mu.Lock()
	after := callsAfterSequence
	mu.Unlock()
	if after != 0 {
		t.Errorf("IPsec rebind loop ran %d swanctl reapply(s) AFTER runShutdownSequence "+
			"returned — the loop was not joined by the shutdown wiring", after)
	}
}
