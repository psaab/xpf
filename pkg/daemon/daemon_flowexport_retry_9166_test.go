package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9166: `reconcileFlowExporters` runs only from the apply tail and the boot
// block, so before this the retry cadence for a failed exporter build was "the
// next commit" — which on a stable box is never. Meanwhile the two faults that
// actually cause a build failure (a collector hostname unresolvable at boot, a
// pinned source-address bind attempted before the interface is up) both clear
// on their own minutes later.

// The three-state snapshot the metrics surface reads.
func TestBuildStatesDistinguishTheThreeCases9166(t *testing.T) {
	cases := []struct {
		name           string
		configured     int64
		err            error
		wantConfigured int
		wantFailed     bool
	}{
		{"not configured", 0, nil, 0, false},
		{"configured and healthy", 2, nil, 2, false},
		{"configured and build failed", 2, errors.New("dial: no such host"), 2, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &Daemon{}
			d.v9Family().configured.Store(c.configured)
			d.v9Family().err = c.err

			var v9 *struct {
				groups int
				failed bool
			}
			for _, st := range d.FlowExportBuildStates() {
				if st.Family == "netflow-v9" {
					v9 = &struct {
						groups int
						failed bool
					}{st.ConfiguredGroups, st.BuildFailed}
				}
			}
			if v9 == nil {
				t.Fatal("no netflow-v9 row: the family must be reported even at zero, " +
					"or not-configured is indistinguishable from a scrape that never ran")
			}
			if v9.groups != c.wantConfigured || v9.failed != c.wantFailed {
				t.Errorf("got configured=%d failed=%v, want %d/%v",
					v9.groups, v9.failed, c.wantConfigured, c.wantFailed)
			}
		})
	}
}

// Both families are always present, so a healthy IPFIX cannot be read off a
// failed NetFlow row or vice versa.
func TestBothFamiliesAreAlwaysReported9166(t *testing.T) {
	seen := map[string]bool{}
	for _, st := range (&Daemon{}).FlowExportBuildStates() {
		seen[st.Family] = true
	}
	for _, f := range []string{"netflow-v9", "ipfix"} {
		if !seen[f] {
			t.Errorf("family %q absent from the snapshot", f)
		}
	}
}

// THE RETRY, DRIVEN THROUGH THE REAL RECONCILE. This is the cell that binds
// the WIRING: `reconcileFlowExporters` must arm the loop. A cell that only
// drives `tryFlowExportRetry`/`armFlowExportRetry` leaves the arm call site
// severable — a mutation deleting it fails nothing, and the retry exists on
// paper only.
//
// `flowSamplingConfigSrc` pins an unassignable collector source-address, so
// `dialCollectors` fails its bind deterministically — the same fault class the
// issue names ("a pinned source-address bind attempted before the interface is
// up").
func TestAFailedReconcileArmsTheRetry9166(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopFlowExportRetryLoop)

	d.reconcileFlowExporters(flowSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100))

	if !d.v9Family().buildFailed() {
		t.Fatal("fixture: the build did not fail, so this cell is not measuring " +
			"what it claims")
	}
	d.flowRetry.mu.Lock()
	pending, active := d.flowRetry.pending, d.flowRetry.active
	d.flowRetry.mu.Unlock()
	if !pending || !active {
		t.Fatalf("a failed reconcile did not arm the retry (pending=%v active=%v); "+
			"the build failure waits for the NEXT COMMIT, which on a stable box "+
			"is never (#9166)", pending, active)
	}
}

// CONTROL — a reconcile that SUCCEEDS must not arm the loop. Without this row,
// "arm unconditionally" satisfies the cell above and every healthy box runs a
// pointless 30s reconcile forever.
func TestASuccessfulReconcileDoesNotArmTheRetry9166(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopFlowExportRetryLoop)

	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("fixture: the healthy reconcile reported no change")
	}
	if d.v9Family().buildFailed() {
		t.Fatal("fixture: the healthy reconcile failed to build")
	}
	d.flowRetry.mu.Lock()
	pending, active := d.flowRetry.pending, d.flowRetry.active
	d.flowRetry.mu.Unlock()
	if pending || active {
		t.Errorf("a healthy reconcile armed the retry (pending=%v active=%v)", pending, active)
	}
}

// And the build-state gauges must follow the real reconcile too, not just a
// hand-set field: configured>0 with failed=1 is the observation that separates
// a dead exporter from an unconfigured box.
func TestAFailedReconcileReportsConfiguredAndFailed9166(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopFlowExportRetryLoop)

	d.reconcileFlowExporters(flowSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100))

	for _, st := range d.FlowExportBuildStates() {
		if st.Family != "netflow-v9" {
			continue
		}
		if st.ConfiguredGroups == 0 {
			t.Error("a failed build reports configured=0, which is the " +
				"NOT-CONFIGURED reading — the two states are still identical")
		}
		if !st.BuildFailed {
			t.Error("a failed build reports failed=0")
		}
		return
	}
	t.Fatal("no netflow-v9 row")
}

// The retry converges once the fault clears, without a commit.
func TestABuildFailureRetriesWithoutACommit9166(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopFlowExportRetryLoop)

	d.reconcileFlowExporters(flowSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100))
	if !d.v9Family().buildFailed() {
		t.Fatal("fixture: the build did not fail")
	}

	// The tick reconciles against the LIVE active config, so a commit that
	// removes flow export converges the loop instead of resurrecting deleted
	// config. Here the seam simulates the fault clearing, as an unresolvable
	// name or an interface coming up does minutes later.
	healthy := flowSamplingConfig("127.0.0.1", 100)
	d.flowRetryActiveCfg = func() *config.Config { return healthy }

	// Drive one tick directly rather than waiting out flowExportRetryInterval:
	// a 30s sleep in a unit test is a hang waiting to be scored as a pass.
	if converged := d.tryFlowExportRetry(); !converged {
		t.Fatal("the retry did not converge after the fault cleared, so a box " +
			"whose collector bind came back stays without flow export until the " +
			"next commit (#9166)")
	}
	if d.v9Family().buildFailed() {
		t.Error("converged while the build was still failing")
	}
}

// The loop must NOT declare convergence while a failure is still outstanding —
// otherwise it disarms on its first tick and the retry is decorative.
func TestTheRetryStaysArmedWhileTheFailurePersists9166(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopFlowExportRetryLoop)

	failing := flowSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100)
	d.reconcileFlowExporters(failing)
	d.flowRetryActiveCfg = func() *config.Config { return failing }

	if d.tryFlowExportRetry() {
		t.Fatal("the retry disarmed while the build was still failing")
	}
}

// An IPFIX-only failure must keep the loop armed: a decision reading NetFlow
// alone would abandon a failed IPFIX build, and the two reconcile
// independently.
func TestAnIPFIXOnlyFailureKeepsTheRetryArmed9166(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	t.Cleanup(d.stopFlowExportRetryLoop)

	// Per-COLLECTOR source-address (#2605): the family-level field would pin
	// both families' collectors and fail v9 too, which is exactly what this
	// cell must not do — it has to isolate IPFIX.
	cfg := ipfixSamplingConfig("127.0.0.1", 100)
	for _, fs := range cfg.ForwardingOptions.Sampling.Instances["s"].FamilyInet.FlowServers {
		if fs.Version == config.FlowServerVersionIPFIX {
			fs.SourceAddress = "192.0.2.250"
		}
	}
	d.reconcileFlowExporters(cfg)

	if d.v9Family().buildFailed() {
		t.Fatal("fixture: NetFlow v9 also failed, so this cell cannot isolate IPFIX")
	}
	if !d.ipfixFamily().buildFailed() {
		t.Fatal("fixture: the IPFIX build did not fail")
	}
	d.flowRetry.mu.Lock()
	active := d.flowRetry.active
	d.flowRetry.mu.Unlock()
	if !active {
		t.Fatal("an IPFIX-only build failure did not arm the retry")
	}
	d.flowRetryActiveCfg = func() *config.Config { return cfg }
	if d.tryFlowExportRetry() {
		t.Fatal("the retry disarmed on an outstanding IPFIX failure")
	}
}

// Arming is single-flight. A box whose collector bind keeps failing reconciles
// on EVERY commit must not accumulate a loop per commit: each extra loop
// overwrites flowRetry.cancel, so the earlier ones survive shutdown's cancel
// and are only reaped by the bounded wg.Wait — a leak that surfaces as a 3s
// stall in the stop sequence rather than as anything visible at the time.
//
// This drives the REAL reconcile, not armFlowExportRetry: the guard that the
// mutation matrix found unexercised is the one in noteFlowExportBuildResult,
// which is the path a commit takes.
func TestRepeatedFailingReconcilesStartOneLoop9166(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopFlowExportRetryLoop)

	failing := flowSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100)
	for i := 0; i < 5; i++ {
		d.reconcileFlowExporters(failing)
		if !d.v9Family().buildFailed() {
			t.Fatalf("fixture: reconcile %d built cleanly", i)
		}
	}
	if got := d.flowRetry.loopStarts.Load(); got != 1 {
		t.Errorf("five failing reconciles started %d retry loops, want 1; each "+
			"extra loop overwrites flowRetry.cancel and outlives the shutdown "+
			"cancel that should have joined it", got)
	}
}

// The direct arm is single-flight too — it is reachable from anywhere that
// notices a failure, and the two guards are separate code.
func TestArmingIsSingleFlight9166(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Daemon{daemonCtx: ctx}
	d.v9Family().err = errors.New("failing")

	for i := 0; i < 5; i++ {
		d.armFlowExportRetry()
	}
	if got := d.flowRetry.loopStarts.Load(); got != 1 {
		t.Errorf("five arms started %d loops, want 1", got)
	}
	d.flowRetry.mu.Lock()
	active := d.flowRetry.active
	d.flowRetry.mu.Unlock()
	if !active {
		t.Fatal("arming did not start a loop")
	}

	cancel()
	d.stopFlowExportRetryLoop() // joins
	d.flowRetry.mu.Lock()
	still := d.flowRetry.active
	d.flowRetry.mu.Unlock()
	if still {
		t.Error("the loop is still active after the shutdown join")
	}
}

// Shutdown must be idempotent and nil-safe: a box that never had a build
// failure never armed a loop, and the stop runs unconditionally.
func TestStopIsNilSafeAndIdempotent9166(t *testing.T) {
	(*Daemon)(nil).stopFlowExportRetryLoop()
	d := &Daemon{}
	d.stopFlowExportRetryLoop()
	d.stopFlowExportRetryLoop()
}

// After the join, a late arm must not resurrect the loop — a reconcile can
// still be in flight when shutdown latches.
func TestArmAfterShutdownDoesNotStartALoop9166(t *testing.T) {
	d := &Daemon{daemonCtx: context.Background()}
	d.stopFlowExportRetryLoop()
	d.v9Family().err = errors.New("late failure")
	d.armFlowExportRetry()

	d.flowRetry.mu.Lock()
	active := d.flowRetry.active
	d.flowRetry.mu.Unlock()
	if active {
		t.Fatal("a post-shutdown arm started a loop that can reconcile against " +
			"a torn-down subsystem")
	}
}

// The join is BOUNDED, so a pathological tick cannot push the stop sequence
// past the systemd TimeoutStopSec and get the process SIGKILLed before the HA
// takeover fence runs.
func TestTheShutdownJoinIsBounded9166(t *testing.T) {
	if flowExportRetryJoinTimeout <= 0 || flowExportRetryJoinTimeout > 5*time.Second {
		t.Fatalf("join timeout %v is not a usable bound", flowExportRetryJoinTimeout)
	}
}
