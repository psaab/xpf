package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/sysservices"
)

// mgmt_listener_reassert.go — #6803.
//
// An unexpected management-listener serve exit was OBSERVABLE and never
// RECONCILED. Observable: the leg is marked dead, EffectiveHTTPAddr stops
// reporting it, and `show system services` renders the HTTP listener Failed.
// Never reconciled: the only caller of reconcileWebManagement is
// applyConfigLocked (daemon_apply.go), so the endpoint came back only when an
// operator happened to commit — on a box whose management API had just died,
// which is the box they can no longer reach to commit from.
//
// Two separate gaps had to close for a re-bind to be possible at all, both of
// them asymmetries with the HTTPS leg that #6827 round 6 had already fixed:
//
//   - api.Server.ReconcileHTTP short-circuited on a same-address leg WITHOUT
//     asking whether it was still serving, so even a forced re-drive returned
//     nil having done nothing. ReconcileHTTPS asks.
//   - managementReconciler.reconcileTo gated the HTTP rebind on the converged
//     FINGERPRINT alone. The fingerprint records what the last successful
//     reconcile bound; it is not evidence the socket is up.
//
// This file adds the third piece: an owner that notices. It mirrors
// proxyARPReassertLoop / raDeadSenderReassertLoop (#6793) /
// fabricIPVLANReassertLoop (#6791) / hostInboundConntrackReassertLoop (#6802) —
// started unconditionally in Run, cheap gate, applySem before acting.

// mgmtListenerReassertInterval is the cadence of the #6803 owner. A dead
// management listener is how an operator gets back IN, so recovery wants to be
// prompt; but the re-drive is a full management reconcile (a bind, and possibly
// a TLS load), so it must not run at the 2s cadence of the cluster reconcile.
// 30s matches the other always-on self-heal loops.
var mgmtListenerReassertInterval = 30 * time.Second

// mgmtReassertApply is the reconcile seam for the #6803 owner, in the same
// spirit as conntrackDeleteFilters and nftApplyPayload: a package var so a test
// can observe WHETHER the owner re-drove a reconcile, not merely what the
// listener ended up as. Production code must never mutate it.
//
// It exists because the re-drive is IDEMPOTENT. Asking "was the listener rebound"
// cannot distinguish an owner that correctly skipped a redundant reconcile from
// one that ran a full reconcile for nothing — a reconcile against an
// already-healthy leg changes no listener, so the #4001 inside-the-semaphore
// re-check was invisible to an outcome-shaped assertion and survived its
// mutation cell. The call itself is the observable.
var mgmtReassertApply = func(d *Daemon, cfg *config.Config) error {
	return d.reconcileWebManagement(cfg)
}

// mgmtListenerReassertLoop re-drives the management reconcile while a listener
// the configuration asked for is not serving.
//
// Always-on and mode-agnostic. The gate is a state read on the reconciler, so it
// is free on a node whose listeners are healthy, and a complete no-op on a node
// with no management reconciler at all (--api-addr empty).
func (d *Daemon) mgmtListenerReassertLoop(ctx context.Context) {
	t := time.NewTicker(mgmtListenerReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// #6863: observe the kernel host name on this tick.
			//
			// Deliberately OUTSIDE reassertMgmtListenersOnce and NOT behind its
			// `mgmtListenerDown()` gate: an external rename can happen while
			// every listener is healthy, which is the common case. Gating it on
			// a down listener would mean the diagnostic only ever fired on a box
			// that already had a second problem.
			//
			// This loop is the right host rather than a new one — it is
			// always-on, mode-agnostic, low frequency (30s), and already in the
			// management plane whose certificate is the thing at stake. A rename
			// is a rare, operator-driven event, so the tick interval is the
			// latency and that is acceptable for a LOW diagnostic. It reads
			// os.Hostname through the seam and takes staleCertMu briefly; it
			// runs on no per-packet or per-poll path.
			d.watchExternalHostRenameOnce()
			d.reassertMgmtListenersOnce(ctx)
		}
	}
}

// mgmtBindStaleLegs re-resolves the desired endpoint from the CURRENT
// committed configuration (committedDesired → resolveAPIBinds → the kernel
// seam — the same derivation the reconcile uses) and reports, per leg,
// whether the converged fingerprint no longer matches it (#14582): the leg
// is on the loopback fallback (degraded) or on an interface address that
// has since been replaced/vanished. It takes m.mu only briefly for the
// fingerprint read and never while resolving, so it cannot deadlock
// against reconcileTo. ok=false means there is nothing to judge (no
// reconciler/store/active config, or nothing converged yet — that state
// is Failed/Disabled's job, not Stale's).
func (d *Daemon) mgmtBindStaleLegs() (httpStale, httpsStale, ok bool) {
	mgmt := d.mgmt.Load()
	if mgmt == nil || d.store == nil {
		return false, false, false
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return false, false, false
	}
	want := endpointOf(mgmt.committedDesired(cfg))
	mgmt.mu.Lock()
	cur, curSet := mgmt.cur, mgmt.curSet
	mgmt.mu.Unlock()
	if !curSet {
		return false, false, false
	}
	if cur.tls && want.tls {
		httpsStale = want.httpsDegraded || cur.httpsDegraded || cur.httpsAddr != want.httpsAddr
	}
	if cur.addr != "" && want.addr != "" {
		httpStale = want.httpDegraded || cur.httpDegraded || cur.addr != want.addr
	}
	return httpStale, httpsStale, true
}

// mgmtBindStaleHTTPS / mgmtBindStaleHTTP are the per-leg forms used by
// Daemon.effectiveListeners to promote a Listening leg to StateStale.
func (d *Daemon) mgmtBindStaleHTTPS() bool {
	_, httpsStale, ok := d.mgmtBindStaleLegs()
	return ok && httpsStale
}

func (d *Daemon) mgmtBindStaleHTTP() bool {
	httpStale, _, ok := d.mgmtBindStaleLegs()
	return ok && httpStale
}

// mgmtBindStale reports whether ANY serving leg is stale (see above).
func (d *Daemon) mgmtBindStale() bool {
	h, s, ok := d.mgmtBindStaleLegs()
	return ok && (h || s)
}

// mgmtListenerDown reports whether a management listener the configuration asked
// for is not currently serving AT THE ADDRESS IT CURRENTLY RESOLVES TO.
//
// It asks the SAME question `show system services` answers, deliberately: the
// operator-visible state and the retry trigger must not be able to disagree,
// or the box reports a dead listener that nothing is retrying (or retries one
// it reports healthy). StateFailed covers both a boot bind that never
// converged and a converged leg whose serve loop exited; StateStale (#14582)
// covers a leg serving on the loopback fallback or a vanished interface
// address. Because Daemon.effectiveListeners folds mgmtBindStale into the
// snapshot (see daemon_run_servers.go), the gate below — Failed || Stale on
// the daemon-level snapshot — IS the operator view, not a parallel one.
func (d *Daemon) mgmtListenerDown() bool {
	mgmt := d.mgmt.Load()
	if mgmt == nil {
		return false
	}
	// #8597 K86: ask BOTH legs. This asked only HTTP, so an HTTPS leg that died
	// to an unexpected serve exit was never re-driven by this always-on owner —
	// the repair waited for the operator's next commit, which is the one event a
	// broken management plane makes hard to deliver. The commit path already
	// asked the right question (`next.TLS && !m.srv.HTTPSServing()`); this is
	// that question asked by the loop whose entire job is to notice.
	ls := d.effectiveListeners()
	if ls.HTTP.State == sysservices.StateFailed || ls.HTTP.State == sysservices.StateStale {
		return true
	}
	return ls.HTTPS.State == sysservices.StateFailed || ls.HTTPS.State == sysservices.StateStale
}

// reassertMgmtListenersOnce re-drives one management reconcile if a listener is
// down.
//
// It takes applySem before acting, for the #4001 reason the sibling loops give:
// an apply may be mid-flight, and reconciling the management listener against a
// half-applied configuration could bind an endpoint the in-flight apply is about
// to move. The gate is re-checked INSIDE the semaphore because the commit this
// tick queued behind may have rebound the listener already — re-driving then is
// a redundant bind on a healthy socket.
//
// The reconcile is driven from the ACTIVE config, not a snapshot taken before
// the wait, so a tick that blocked behind a commit converges on what that commit
// committed rather than on what was live when the tick started. reconcileTo's
// own committedDesired fence (#5561 round 14) makes that the same answer, and
// passing the active config keeps the two agreeing rather than relying on it.
func (d *Daemon) reassertMgmtListenersOnce(ctx context.Context) {
	if !d.mgmtListenerDown() {
		return
	}
	if d.applySem == nil {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)
	if !d.mgmtListenerDown() {
		return
	}
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	// TRANSITION at Warn, TICKS at Debug. A node whose management bind can never
	// succeed — the address permanently taken by another process, say — is a
	// PERMANENT down condition, and this owner re-drives it every 30s for the
	// life of the daemon. Logging the same Warn on every tick would put ~2900
	// identical lines a day into the journal and drown the real diagnostics,
	// which is the failure mode the project's logging rules were written after.
	// The first tick of a down-streak is the event worth seeing.
	if d.mgmtReassertNoticed.CompareAndSwap(false, true) {
		slog.Warn("management listener is not serving; re-driving the management " +
			"reconcile (#6803) — an unexpected serve exit used to stay down until " +
			"an operator committed, on a box whose management API had just died")
	} else {
		slog.Debug("management listener still not serving; re-driving the reconcile")
	}
	if err := mgmtReassertApply(d, cfg); err != nil {
		// Retained-listener fail-safe: a failed rebind keeps whatever is still
		// live. Log and let the next tick retry — that IS the retry owner.
		slog.Error("management listener re-assert failed; will retry", "err", err)
		return
	}
	// Converged: re-arm the transition log so a LATER death is reported again
	// rather than silently swallowed by the streak flag. Re-armed only on a
	// reconcile that actually brought the listener back — a reconcile that
	// returned nil while the listener is still down is not a recovery.
	if !d.mgmtListenerDown() {
		if d.mgmtReassertNoticed.Swap(false) {
			slog.Info("management listener re-bound at its configured endpoint (#6803)")
		}
	}
}
