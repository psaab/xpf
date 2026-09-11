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
// succeeds. The retry re-runs ONLY the ip-rule reconciles and the route-leak
// republish, never the FRR apply, whose manager owns its own degraded retry.

// routingReconcileReassertInterval paces the retry owner, matching its sibling
// re-assert loops.
var routingReconcileReassertInterval = 30 * time.Second

// routingPolicyReconcileFn and routeLeakReconcileFn are the retry owner's two
// reconciles, overridable in tests: the policy-routing reconcile writes the
// kernel through a concrete *routing.Manager, so without a seam the retry could
// only be observed with real ip rules.
var (
	routingPolicyReconcileFn = func(d *Daemon, cfg *config.Config) error {
		return d.applyPolicyRoutingRules(cfg)
	}
	routeLeakReconcileFn = func(d *Daemon, cfg *config.Config, overlay []config.RouteOverlayEntry) error {
		return d.reconcileRouteLeakSnapshot(cfg, overlay)
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

// reassertRoutingReconcileOnce re-runs the owed reconcile once.
//
// It takes applySem BEFORE reading the active config, for the reason #4001 gave
// the proxy-ARP loop: a config read outside the semaphore could capture a
// pre-commit snapshot and re-assert rules a concurrent commit has just removed.
// The owed check is repeated inside, because a commit that lands in between runs
// the same reconcile and discharges the debt itself.
func (d *Daemon) reassertRoutingReconcileOnce(ctx context.Context) {
	if d.store == nil || !d.routingReconcileOwed() {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return // ctx cancelled (daemon shutdown)
	}
	defer d.applySem.Release(1)
	if !d.routingReconcileOwed() {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	err := errors.Join(
		routingPolicyReconcileFn(d, cfg),
		routeLeakReconcileFn(d, cfg, d.commitOverlayForConfig(cfg)),
	)
	d.noteRoutingReconcileResult(err)
	if err != nil {
		slog.Warn("routing reconcile re-assert failed; will retry", "err", err, "issue", "#9693")
	}
}
