package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// Routing reconcile retry owner (#9693).
//
// Every config apply reconciles the kernel policy-routing rules (next-table,
// rib-group and firewall-filter PBR) and then republishes the userspace route
// snapshot from that kernel state. #5844 and #5696 made both failures visible as
// deferred commit errors, but nothing retried them. A transient failure left
// stale or missing cross-VRF rules in the kernel, and a userspace FIB rebuilt
// from that partial state, until some later unrelated apply re-ran the
// reconcile. On applies nobody waits on (boot, DHCP lease callback, feed,
// config-poll) the joined error was only logged at Warn.
//
// This is the pattern the repo settled on for "a failure has no retry owner"
// (proxyARPReassertLoop #4001, fabricIPVLANReassertLoop #6791,
// serviceReloadDebtReassertLoop #6800): a persistent debt latched by the apply
// and an always-on re-assert loop that re-runs the idempotent reconcile until it
// succeeds. The retry re-runs the owed policy-routing and route-leak
// reconciles, and it reasserts the VRF miss-terminator desired state
// (#10421/#10458) on every eligible tick, including ticks with no debt;
// bootstrap mode suppresses that takeover write. It never runs the FRR apply,
// whose manager owns its own degraded retry.

// routingReconcileReassertInterval paces the retry owner, matching its sibling
// re-assert loops.
var routingReconcileReassertInterval = 30 * time.Second

// routingPolicyReconcileFn, routeLeakReconcileFn, and
// vrfMissTerminatorReconcileFn are the retry owner's reconciles, overridable in
// tests: policy-routing and route-leak writes use concrete routing/dataplane
// managers, while the VRF callback restores the #10421 post-networkd invariant.
var (
	routingPolicyReconcileFn = func(d *Daemon, cfg *config.Config) error {
		return d.applyPolicyRoutingRules(cfg)
	}
	routeLeakReconcileFn = func(d *Daemon, cfg *config.Config, overlay []config.RouteOverlayEntry) error {
		return d.reconcileRouteLeakSnapshot(cfg, overlay)
	}
	vrfMissTerminatorReconcileFn = func(d *Daemon) error {
		if d.routing == nil || d.store == nil {
			return nil
		}
		cfg := d.store.ActiveConfig()
		if !d.shouldReassertVRFMissTerminator(cfg) {
			return nil
		}
		return d.routing.ReassertVRFMissTerminator()
	}
)

// routingReconcileDebt records that the routing reconcile is owed. The zero
// value owes nothing, so a Daemon built as a struct literal needs no setup.
type routingReconcileDebt struct {
	mu   sync.Mutex
	owed bool
	// failures counts every failed attempt, the apply's and the retry owner's. A
	// climbing count means the owner is running and failing, and a flat count
	// with owed set means it is not running.
	failures uint64
	lastErr  string
}

// noteRoutingReconcileResult latches the debt when any of errs is non-nil and
// discharges it when all are nil.
func (d *Daemon) noteRoutingReconcileResult(errs ...error) {
	err := errors.Join(errs...)
	d.routingDebt.mu.Lock()
	defer d.routingDebt.mu.Unlock()
	if err == nil {
		if d.routingDebt.owed {
			slog.Info("routing reconcile converged; routing reconcile debt discharged", "issue", "#9693")
		}
		d.routingDebt.owed = false
		d.routingDebt.lastErr = ""
		return
	}
	if !d.routingDebt.owed {
		slog.Warn("routing reconcile failed; the retry owner will re-run it until it succeeds",
			"err", err, "issue", "#9693")
	}
	d.routingDebt.owed = true
	d.routingDebt.failures++
	d.routingDebt.lastErr = err.Error()
}

// RoutingReconcileDebt reports whether the routing reconcile is owed, how many
// attempts have failed, and the last error.
func (d *Daemon) RoutingReconcileDebt() (owed bool, failures uint64, lastErr string) {
	d.routingDebt.mu.Lock()
	defer d.routingDebt.mu.Unlock()
	return d.routingDebt.owed, d.routingDebt.failures, d.routingDebt.lastErr
}

func (d *Daemon) routingReconcileOwed() bool {
	d.routingDebt.mu.Lock()
	defer d.routingDebt.mu.Unlock()
	return d.routingDebt.owed
}

// routingReconcileReassertLoop is the always-on retry owner started from Run.
func (d *Daemon) routingReconcileReassertLoop(ctx context.Context) {
	t := time.NewTicker(routingReconcileReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertRoutingReconcileOnce(ctx)
		}
	}
}

// reassertRoutingReconcileOnce gives the VRF miss terminator an always-on
// day-2 tail, while keeping policy and route-leak reconciliation debt-gated.
//
// It takes applySem BEFORE reading the active config, for the reason #4001 gave
// the proxy-ARP loop: a config read outside the semaphore could capture a
// pre-commit snapshot and re-assert rules a concurrent commit has just removed.
// A canceled tick returns before any semaphore acquisition; bootstrap ticks
// retain debt-gated policy/route-leak retries but skip VRF takeover writes.
// A no-debt tick uses TryAcquire so it does not queue behind a commit that has
// nothing for the policy/route-leak retry owner to do; once it owns the
// semaphore it still reasserts the VRF terminator. The owed check is repeated
// inside because a commit that lands in between runs the same reconcile and
// discharges the debt itself.
func (d *Daemon) reassertRoutingReconcileOnce(ctx context.Context) {
	if d.store == nil || ctx.Err() != nil {
		return
	}
	if d.routingReconcileOwed() {
		if err := d.applySem.Acquire(ctx, 1); err != nil {
			return // ctx cancelled (daemon shutdown)
		}
	} else if !d.applySem.TryAcquire(1) {
		return // an active commit owns the semaphore; the next tick retries
	}
	defer d.applySem.Release(1)

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// The VRF terminator is always checked once the tick owns applySem, except
	// in bootstrap mode where takeover writes remain suppressed. This closes
	// the post-success async-delete window from #10458. The callback re-checks
	// config-aware ownership, so an empty configuration remains a no-op.
	var vrfErr error
	if !d.inBootstrap() {
		vrfErr = vrfMissTerminatorReconcileFn(d)
	}

	// A debt may have been discharged by the commit that held applySem while
	// this tick waited. In that case, preserve the no-duplicate policy/route
	// behavior while still retaining the always-on VRF check.
	if !d.routingReconcileOwed() {
		d.noteRoutingReconcileResult(vrfErr)
		if vrfErr != nil {
			slog.Warn("VRF miss terminator day-2 re-assert failed; will retry",
				"err", vrfErr, "issue", "#10458")
		}
		return
	}

	err := errors.Join(
		routingPolicyReconcileFn(d, cfg),
		routeLeakReconcileFn(d, cfg, d.commitOverlayForConfig(cfg)),
		vrfErr,
	)
	d.noteRoutingReconcileResult(err)
	if err != nil {
		slog.Warn("routing reconcile re-assert failed; will retry", "err", err, "issue", "#9693")
	}
}
