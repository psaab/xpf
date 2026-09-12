package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Config-apply retry owner for the caller-less auto-rollback path (#9811).
//
// When a `commit confirmed` times out, executeConfirmedRollback promotes the
// rollback target (C1) in the STORE first and then re-applies it, because the
// store has already moved and the dataplane must be brought into agreement
// unconditionally. If that apply fails, the failure was only logged.
//
// That leaves a divergence, not merely a stale rule: under the #5679 contract a
// failed full apply keeps the OLD compiled policy live, so the node keeps
// ENFORCING the abandoned configuration C2 while the store, `show
// configuration`, the peer resync and /health all report C1. On the ordinary
// commit path an operator sees the error and re-commits; this is a background
// timer callback with no caller to report to, so nothing retried it and the
// divergence persisted until some later unrelated apply happened to succeed.
//
// This is the pattern the repo settled on for "a failure has no retry owner"
// (proxyARPReassertLoop #4001, fabricIPVLANReassertLoop #6791,
// serviceReloadDebtReassertLoop #6800, routingReconcileReassertLoop #9693): a
// persistent debt latched by the failure and an always-on re-assert loop that
// re-runs the idempotent operation until it succeeds.
//
// SCOPE, stated because the general gap is wider than this fix. Every apply
// with no caller — boot load, the DHCP lease callback, a feed refresh, the
// config poll — has the same shape, and #9693 already owns the ROUTING tail for
// all of them. This debt covers the auto-rollback path only, which is the one
// where the store has ALREADY advanced, so the reported configuration and the
// enforced one disagree. On the other caller-less paths the store has not moved
// and the reported configuration is still the enforced one; widening to them is
// a separate decision with a different consequence, and bundling it here would
// make this change's blast radius the whole apply path.

// configApplyReassertInterval paces the retry owner, matching its sibling
// re-assert loops.
var configApplyReassertInterval = 30 * time.Second

// configApplyReassertFn is the retry owner's operation, overridable in tests.
// Without a seam the retry could only be observed by breaking a real dataplane
// publish, and the cell this issue asks for injects the failure.
var configApplyReassertFn = func(d *Daemon) error {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return nil
	}
	return d.applyConfigLocked(context.Background(), cfg)
}

// configApplyDebt records that the ACTIVE configuration is not the one the
// dataplane is enforcing. The zero value owes nothing, so a Daemon built as a
// struct literal needs no setup.
type configApplyDebt struct {
	mu   sync.Mutex
	owed bool
	// failures counts every failed attempt, the rollback's and the retry
	// owner's. A climbing count means the owner is running and failing; a flat
	// count with owed set means it is not running.
	failures uint64
	lastErr  string
}

// noteConfigApplyResult latches the debt when err is non-nil and discharges it
// when err is nil.
func (d *Daemon) noteConfigApplyResult(err error) {
	d.configDebt.mu.Lock()
	defer d.configDebt.mu.Unlock()
	if err == nil {
		if d.configDebt.owed {
			slog.Info("config apply converged; the dataplane now enforces the active configuration",
				"issue", "#9811")
		}
		d.configDebt.owed = false
		d.configDebt.lastErr = ""
		return
	}
	if !d.configDebt.owed {
		slog.Warn("config apply failed with no caller to report to; the node is ENFORCING a "+
			"configuration it does not report, and the retry owner will re-apply until it succeeds",
			"err", err, "issue", "#9811")
	}
	d.configDebt.owed = true
	d.configDebt.failures++
	d.configDebt.lastErr = err.Error()
}

// ConfigApplyDebt reports whether the dataplane is known to be enforcing
// something other than the active configuration, how many attempts have failed,
// and the last error.
func (d *Daemon) ConfigApplyDebt() (owed bool, failures uint64, lastErr string) {
	d.configDebt.mu.Lock()
	defer d.configDebt.mu.Unlock()
	return d.configDebt.owed, d.configDebt.failures, d.configDebt.lastErr
}

func (d *Daemon) configApplyOwed() bool {
	d.configDebt.mu.Lock()
	defer d.configDebt.mu.Unlock()
	return d.configDebt.owed
}

// configApplyReassertLoop is the always-on retry owner started from Run.
func (d *Daemon) configApplyReassertLoop(ctx context.Context) {
	t := time.NewTicker(configApplyReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertConfigApplyOnce(ctx)
		}
	}
}

// reassertConfigApplyOnce re-applies the ACTIVE configuration once, if owed.
//
// It re-reads the active config rather than replaying the config that failed,
// and that is deliberate. A commit landing between the failure and this tick
// makes the promoted target stale; replaying it would UNDO the operator's newer
// commit, turning a convergence mechanism into a config regression. Re-applying
// whatever is active converges on the same invariant — "the dataplane enforces
// what the store reports" — and is what discharges the debt after an unrelated
// successful commit, which would otherwise leave a permanent false degraded.
//
// It takes applySem BEFORE reading the config, for the reason #4001 gave the
// proxy-ARP loop: a read outside the semaphore could capture a pre-commit
// snapshot. The owed check is repeated inside, because a commit that lands in
// between applies the same config and discharges the debt itself.
func (d *Daemon) reassertConfigApplyOnce(ctx context.Context) {
	if d.store == nil || !d.configApplyOwed() {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return // ctx cancelled (daemon shutdown)
	}
	defer d.applySem.Release(1)
	if !d.configApplyOwed() {
		return
	}
	err := configApplyReassertFn(d)
	d.noteConfigApplyResult(err)
	if err != nil {
		slog.Warn("config apply re-assert failed; will retry", "err", err, "issue", "#9811")
	}
}
