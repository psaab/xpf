package daemon

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/flowexport"
)

// FlowExportBuildStates snapshots both families' build health for the metrics
// collector. Returned unconditionally for both families — including at zero —
// so the three states are three distinguishable observations:
//
//	configured=0, failed=0  ->  not configured
//	configured>0, failed=0  ->  configured and healthy
//	configured>0, failed=1  ->  configured and the build FAILED
//
// Emitting only the failure would leave the first two indistinguishable from a
// scrape that never reached this code.
func (d *Daemon) FlowExportBuildStates() []flowexport.BuildState {
	if d == nil {
		return nil
	}
	return []flowexport.BuildState{
		{
			Family:              "netflow-v9",
			ConfiguredGroups:    int(d.flowConfiguredGroups.Load()),
			BuildFailed:         d.flowExportBuildFailed(),
			ExcludedFlowServers: int(d.flowExcludedFlowServers.Load()),
		},
		{
			Family:              "ipfix",
			ConfiguredGroups:    int(d.ipfixConfiguredGroups.Load()),
			BuildFailed:         d.ipfixExportBuildFailed(),
			ExcludedFlowServers: int(d.ipfixExcludedFlowServers.Load()),
		},
	}
}

// flowExportBuildFailed reports whether the last NetFlow v9 reconcile failed to
// build its exporters. Takes flowReconMu, which the reconcile holds for the
// duration of a swap, so a scrape never observes a half-applied reconcile.
func (d *Daemon) flowExportBuildFailed() bool {
	d.flowReconMu.Lock()
	defer d.flowReconMu.Unlock()
	return d.flowExportErr != nil
}

// ipfixExportBuildFailed is the IPFIX sibling of flowExportBuildFailed.
func (d *Daemon) ipfixExportBuildFailed() bool {
	d.ipfixReconMu.Lock()
	defer d.ipfixReconMu.Unlock()
	return d.ipfixExportErr != nil
}

// flowExportRetryInterval is the cadence of the autonomous retry of a failed
// flow-exporter build (#9166). It mirrors ipsecRebindRetryInterval (#4899) and
// probePinRetryInterval (#1895): control-plane cost only (a dial of the
// configured collectors), and the loop runs ONLY while a build failure is
// outstanding, so a healthy box never pays for it.
const flowExportRetryInterval = 30 * time.Second

// flowExportRetryJoinTimeout bounds the shutdown join. Unlike the IPsec rebind
// loop — whose swanctl shell-out runs under a background context the cancel
// cannot interrupt — a retry tick here is a reconcile whose dials are bounded
// by the exporter's own dial timeouts, so this join returns promptly. The bound
// exists so a pathological dial can never push the stop sequence past the
// systemd TimeoutStopSec and get the process SIGKILLed before the HA takeover
// fence runs.
const flowExportRetryJoinTimeout = 3 * time.Second

// flowExportRetryState is the single-flight lifecycle of the retry loop.
type flowExportRetryState struct {
	mu sync.Mutex
	// pending is "the last reconcile left a family unbuilt", updated by every
	// reconcile under mu. The loop disarms on this flag rather than
	// re-deriving it, so a commit-path failure landing between a tick's
	// reconcile and its disarm cannot be lost.
	pending bool
	active  bool
	stopped bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	// loopStarts counts goroutine launches, so the single-flight guard is
	// EXERCISABLE. Without it, "one loop" and "one loop per failing commit"
	// are the same observation from outside: every extra loop overwrites
	// `cancel`, so the earlier ones survive shutdown's cancel and are only
	// joined by the bounded wg.Wait — a leak that shows up as a 3s stall at
	// shutdown rather than as anything a cell can assert directly.
	loopStarts atomic.Int64
}

// armFlowExportRetry starts the retry loop if a build failure is outstanding
// and no loop is already running.
//
// This is what makes the failure RECOVERABLE. `reconcileFlowExporters` runs
// only from the apply tail and the boot block, so before this the retry cadence
// was "the next commit" — which on a stable box is never. The two faults that
// actually cause a build failure (unresolvable collector DNS, a source-address
// bind before the interface is up) both clear on their own minutes later, and
// nothing was there to notice.
//
// Safe to call from a reconcile and from the loop itself; a live loop is not
// duplicated. Callers must NOT hold flowReconMu — the loop's tick re-enters
// reconcileFlowExporters, which takes it.
func (d *Daemon) armFlowExportRetry() {
	d.flowRetry.mu.Lock()
	d.flowRetry.pending = true
	start := !d.flowRetry.stopped && !d.flowRetry.active
	if start {
		d.flowRetry.active = true
	}
	d.flowRetry.mu.Unlock()
	if start {
		d.startFlowExportRetryLoop()
	}
}

// startFlowExportRetryLoop launches the loop goroutine. The caller has already
// claimed the single-flight slot under flowRetry.mu; the ctx/cancel/wg are set
// up here, outside that lock, because a daemon with no daemonCtx (a unit
// fixture) must not leave `active` latched with no loop to clear it.
func (d *Daemon) startFlowExportRetryLoop() {
	d.flowRetry.loopStarts.Add(1)
	if d.daemonCtx == nil {
		d.flowRetry.mu.Lock()
		d.flowRetry.active = false
		d.flowRetry.mu.Unlock()
		return
	}
	// Derive from daemonCtx (never cancelled in production) so the loop is
	// joinable at shutdown.
	ctx, cancel := context.WithCancel(d.daemonCtx)
	d.flowRetry.mu.Lock()
	d.flowRetry.cancel = cancel
	d.flowRetry.wg.Add(1)
	d.flowRetry.mu.Unlock()

	slog.Warn("flow exporter build failed; retrying autonomously",
		"interval", flowExportRetryInterval)
	go func() {
		defer d.flowRetry.wg.Done()
		d.flowExportRetryLoop(ctx)
	}()
}

// flowExportRetryLoop re-runs the reconcile against the LIVE active config
// until both families build cleanly, then disarms.
//
// Reading the live config (not the config captured when the failure occurred)
// means a commit that REMOVES flow export converges the loop instead of
// resurrecting deleted config — the same reason activeConfigForRebind exists
// (#4899).
func (d *Daemon) flowExportRetryLoop(ctx context.Context) {
	t := time.NewTicker(flowExportRetryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.flowRetry.mu.Lock()
			d.flowRetry.active = false
			d.flowRetry.mu.Unlock()
			return
		case <-t.C:
			if d.tryFlowExportRetry() {
				return
			}
		}
	}
}

// tryFlowExportRetry runs one retry tick. Returns true when the loop should
// exit, having converged.
//
// The disarm decision reads `pending`, which every reconcile updates while
// holding flowRetry.mu (noteFlowExportBuildResult). Re-deriving it here from
// the error fields instead would be a race with the commit path: a reconcile
// that failed between this tick's reconcile and its disarm would set the error
// and then find the loop already `active`, so its arm would be a no-op — and
// the loop would exit with a failure outstanding and nothing left to retry it.
// One mutex, one flag, one decision.
func (d *Daemon) tryFlowExportRetry() bool {
	if cfg := d.activeConfigForFlowRetry(); cfg != nil {
		d.reconcileFlowExporters(cfg)
	}
	d.flowRetry.mu.Lock()
	defer d.flowRetry.mu.Unlock()
	if d.flowRetry.pending {
		return false
	}
	d.flowRetry.active = false
	slog.Info("flow exporter build recovered; export reconciled")
	return true
}

// noteFlowExportBuildResult records whether the reconcile that just finished
// left either family unbuilt, and arms the retry loop when it did.
//
// BOTH families are consulted. Reading only NetFlow v9 would abandon a failed
// IPFIX build — the two reconcile independently and either can fail alone.
//
// Called with NEITHER reconcile mutex held: the loop this may start re-enters
// reconcileFlowExporters, which takes them.
func (d *Daemon) noteFlowExportBuildResult() {
	failed := d.flowExportBuildFailed() || d.ipfixExportBuildFailed()

	d.flowRetry.mu.Lock()
	d.flowRetry.pending = failed
	start := failed && !d.flowRetry.stopped && !d.flowRetry.active
	if start {
		d.flowRetry.active = true
	}
	d.flowRetry.mu.Unlock()

	if start {
		d.startFlowExportRetryLoop()
	}
}

// activeConfigForFlowRetry returns the config the retry reconciles against.
// Tests override the source so the loop can be driven without seeding the
// configstore.
func (d *Daemon) activeConfigForFlowRetry() *config.Config {
	if d.flowRetryActiveCfg != nil {
		return d.flowRetryActiveCfg()
	}
	if d.store == nil {
		return nil
	}
	return d.store.ActiveConfig()
}

// stopFlowExportRetryLoop cancels and JOINS the retry loop at shutdown, so a
// late tick can never reconcile against a torn-down subsystem. It latches
// stopped so a late armFlowExportRetry cannot start a new loop after the join.
// Idempotent and nil-safe: a loop that was never armed joins cleanly.
//
// The mutex is released BEFORE the join: the loop takes it on both its
// ctx.Done and converged branches, so holding it across the join would
// deadlock. Mirrors stopIPsecRebindLoop (#6397).
func (d *Daemon) stopFlowExportRetryLoop() {
	if d == nil {
		return
	}
	d.flowRetry.mu.Lock()
	d.flowRetry.stopped = true
	cancel := d.flowRetry.cancel
	d.flowRetry.cancel = nil
	d.flowRetry.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		d.flowRetry.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(flowExportRetryJoinTimeout):
		slog.Warn("shutdown: timed out joining flow-export retry loop; proceeding to teardown",
			"timeout", flowExportRetryJoinTimeout)
	}
}
