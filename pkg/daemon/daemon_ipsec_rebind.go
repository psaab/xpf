package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
)

// ipsecRebindRetryInterval is the cadence of the autonomous retry of a
// failed DHCP-lease-change IPsec rebind (#4899). Control-plane cost only (a
// swanctl re-render + --load-all), and the loop runs ONLY while a rebind is
// pending, so a healthy box never pays for it. It mirrors the slow periodic
// probe-pin retry (#1895, probePinRetryInterval).
const ipsecRebindRetryInterval = 30 * time.Second

// ipsecApplyForLeaseChange performs the swanctl re-render + reload for the
// DHCP-lease-change rebind path. Production re-renders local_addrs from the
// interface's CURRENT kernel address (resolved inside PrepareConfig at apply
// time), so re-applying the same config picks up the new lease. Tests inject a
// seam so the retry lifecycle can be driven without shelling out to swanctl.
func (d *Daemon) ipsecApplyForLeaseChange(cfg *config.Config) error {
	// #5281: the DHCP-lease-change rebind re-renders /etc/swanctl/conf.d/xpf.conf
	// (IKE PSKs) from the still-resident in-memory ActiveConfig. Both callers
	// (reapplyIPsecForLeaseChange, tryIPsecRebindRetry) run under applySem, but a
	// factory reset that already erased that snippet must not have it recreated
	// in the wipe→stop window — short-circuit once the terminal reset generation
	// is entered.
	if d.isResetting() {
		return errDaemonResetting
	}
	if d.ipsecApply != nil {
		return d.ipsecApply(cfg)
	}
	return d.applyIPsecTracked(cfg)
}

// activeConfigForRebind returns the config the retry loop re-renders against —
// the LIVE active config in production, not the config captured when the
// failure occurred. Reading the live config means a commit that removes the
// VPN (or the DHCP binding) converges the loop instead of resurrecting deleted
// config. Tests override the source so the loop has a config without seeding
// the configstore.
func (d *Daemon) activeConfigForRebind() *config.Config {
	if d.ipsecRebindActiveCfg != nil {
		return d.ipsecRebindActiveCfg()
	}
	if d.store == nil {
		return nil
	}
	return d.store.ActiveConfig()
}

// IPsecRebindPending reports whether the last DHCP-lease-change IPsec rebind
// failed and has not yet reconverged — swanctl local_addrs are bound to a
// stale lease address while set. Backs the xpf_ipsec_rebind_pending gauge
// (0/1, no labels). Read lock-free by the metrics collector (#4899).
func (d *Daemon) IPsecRebindPending() bool {
	return d.ipsecRebindPending.Load()
}

// armIPsecRebind marks a lease-change rebind as pending (raising the health
// signal) and ensures the single-flight retry loop is running. Safe to call
// from the lease callback and from the retry loop itself; a live loop is not
// duplicated. Callers hold applySem, so the pending flag always reflects the
// last completed apply attempt.
func (d *Daemon) armIPsecRebind() {
	d.ipsecRebindMu.Lock()
	defer d.ipsecRebindMu.Unlock()
	d.ipsecRebindPending.Store(true)
	// #5523 C179-093: do not (re)start the loop once shutdown has stopped it —
	// a late Add would race stopIPsecRebindLoop's Wait. Mirrors pinRetryStopped.
	if d.daemonCtx == nil || d.ipsecRebindRetryActive || d.ipsecRebindStopped {
		return
	}
	d.ipsecRebindRetryActive = true
	// Bind the loop to a CANCELLABLE child of d.daemonCtx (not d.daemonCtx
	// itself, which is never cancelled in production, #5807) and track it on
	// ipsecRebindWg so stopIPsecRebindLoop can cancel + join it at shutdown.
	ctx, cancel := context.WithCancel(d.daemonCtx)
	d.ipsecRebindCancel = cancel
	d.ipsecRebindWg.Add(1)
	go func() {
		defer d.ipsecRebindWg.Done()
		d.ipsecRebindRetryLoop(ctx)
	}()
}

// ipsecRebindJoinTimeout bounds how long stopIPsecRebindLoop waits to JOIN the
// retry loop at shutdown before proceeding to teardown (#6397). The loop's
// ctx.Done and applySem.Acquire branches ARE ctx-cancellable, so a loop parked
// on the ticker or blocked waiting for applySem unwinds immediately on cancel.
// But once a tick has ACQUIRED applySem and entered tryIPsecRebindRetry's apply,
// the swanctl re-render+reload shells out under
// context.WithTimeout(context.Background(), swanctlTimeout=15s)
// (pkg/ipsec/manager.go runSwanctl) — a BACKGROUND context that the loop's
// cancel does NOT interrupt — plus a 5s WaitDelay, so a rebind that is mid-apply
// when shutdown fires can block a plain ipsecRebindWg.Wait() for up to ~20s.
// stopIPsecRebindLoop runs in runShutdownSequence BEFORE the HA takeover fence,
// so an unbounded join could push the whole stop past the systemd 20s
// TimeoutStopSec (test/incus/xpfd.service) and get the process SIGKILLed before
// the fence runs — the same fence-starvation class the #6395 aggregator join
// bound fixed. 3s mirrors aggregatorFlushJoinTimeout and leaves the fence the
// bulk of the 20s stop budget.
const ipsecRebindJoinTimeout = 3 * time.Second

// stopIPsecRebindLoop cancels the ipsecRebindRetryLoop goroutine and JOINS it at
// shutdown, so a late 30s rebind tick can never run a swanctl reapply against a
// torn-down subsystem (#5523 C179-093). It latches ipsecRebindStopped so a late
// armIPsecRebind cannot start a new loop after the join. Idempotent / nil-safe:
// a loop that was never armed (no lease-change rebind failure) joins cleanly.
//
// The join is BOUNDED by ipsecRebindJoinTimeout (#6397): the loop's cancel is
// ctx-observed only at its ticker/ctx.Done select and the applySem.Acquire —
// NOT inside a swanctl apply already in flight, which runs under a background
// context (runSwanctl). A rebind that is mid-apply when shutdown fires would
// otherwise block this join for up to ~20s, and since it precedes the HA
// takeover fence, an unbounded wait can blow the systemd stop budget and get the
// process SIGKILLed before the fence runs. On the happy path the loop is parked
// on the ticker / ctx.Done and the cancel + join returns in microseconds; on a
// stalled mid-apply we log a warning and PROCEED to teardown, letting the
// in-flight swanctl shell-out finish in the background as the process exits
// (harmless — nothing downstream reads its result).
//
// ipsecRebindMu is held only to latch the flag and read+clear the cancel, then
// RELEASED before the join: the loop takes ipsecRebindMu on both its ctx.Done
// (disarmIPsecRebindOnShutdown) and ticker branches, so holding it across the
// join would deadlock. Mirrors the #5308 stopPinRetryLoop, plus the #6395
// aggregator's bounded-join shape.
func (d *Daemon) stopIPsecRebindLoop() {
	d.ipsecRebindMu.Lock()
	d.ipsecRebindStopped = true
	cancel := d.ipsecRebindCancel
	d.ipsecRebindCancel = nil
	d.ipsecRebindMu.Unlock()
	if cancel != nil {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		d.ipsecRebindWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(ipsecRebindJoinTimeout):
		slog.Warn("shutdown: timed out joining IPsec DHCP-rebind retry loop; "+
			"proceeding to teardown (a mid-apply swanctl shell-out runs under a "+
			"background context and finishes as the process exits)",
			"timeout", ipsecRebindJoinTimeout)
	}
}

// clearIPsecRebindPending drops the health signal after a successful reapply,
// logging the recovery exactly once (only when a rebind was actually pending —
// the common healthy path is silent).
func (d *Daemon) clearIPsecRebindPending() {
	d.ipsecRebindMu.Lock()
	recovered := d.ipsecRebindPending.Load()
	d.ipsecRebindPending.Store(false)
	d.ipsecRebindMu.Unlock()
	if recovered {
		slog.Info("IPsec rebind after DHCP address change recovered; swanctl local_addrs reconverged")
	}
}

// disarmIPsecRebindIfConverged clears the retry-active flag (stopping the
// loop) ONLY if no rebind is pending, re-checking pending under ipsecRebindMu
// so a failure that re-armed pending between the loop's apply and this check
// keeps the loop alive. Returns true when the loop was disarmed and should
// exit.
func (d *Daemon) disarmIPsecRebindIfConverged() bool {
	d.ipsecRebindMu.Lock()
	defer d.ipsecRebindMu.Unlock()
	if d.ipsecRebindPending.Load() {
		return false
	}
	d.ipsecRebindRetryActive = false
	return true
}

// disarmIPsecRebindOnShutdown unconditionally clears the retry-active flag when
// the daemon context is cancelled. The pending flag is left as-is; the boot
// apply re-renders IPsec on the next start.
func (d *Daemon) disarmIPsecRebindOnShutdown() {
	d.ipsecRebindMu.Lock()
	d.ipsecRebindRetryActive = false
	d.ipsecRebindMu.Unlock()
}

// ipsecRebindRetryLoop is the slow autonomous retry of a failed
// DHCP-lease-change IPsec rebind (#4899). It re-attempts the swanctl
// re-render+reload against the live active config until it converges, the
// rebind target disappears (VPN/DHCP binding removed by a commit), or the
// daemon shuts down. armIPsecRebind restarts it if a later lease change fails
// again. Mirrors probePinRetryLoop (#1895).
func (d *Daemon) ipsecRebindRetryLoop(ctx context.Context) {
	interval := d.ipsecRebindRetryEvery
	if interval <= 0 {
		interval = ipsecRebindRetryInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.disarmIPsecRebindOnShutdown()
			return
		case <-ticker.C:
			if d.tryIPsecRebindRetry(ctx) {
				return
			}
		}
	}
}

// tryIPsecRebindRetry runs one retry attempt under applySem and returns
// stop=true when the loop has been disarmed and should exit. Holding applySem
// across the apply AND the pending/active state update keeps every attempt
// atomic with the lease callback's own apply+record, so the final pending
// state always reflects the last completed apply (no lost-failure race).
func (d *Daemon) tryIPsecRebindRetry(ctx context.Context) (stop bool) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		// Context cancelled (shutdown). Disarm and stop; the loop's ctx.Done
		// branch would otherwise never run because we return here.
		d.disarmIPsecRebindOnShutdown()
		return true
	}
	defer d.applySem.Release(1)

	// Re-check convergence under applySem: a concurrent lease-change apply may
	// have already reconverged while this tick waited for the lock.
	if d.disarmIPsecRebindIfConverged() {
		return true
	}

	cfg := d.activeConfigForRebind()
	if cfg == nil || d.ipsec == nil || !ipsec.HasDHCPBoundGateway(cfg) {
		// The rebind target is gone (VPN deleted / interface no longer
		// DHCP-bound). Clear pending and stop; a future lease change re-arms.
		d.clearIPsecRebindPending()
		return d.disarmIPsecRebindIfConverged()
	}

	if err := d.ipsecApplyForLeaseChange(cfg); err != nil {
		slog.Warn("IPsec rebind retry after DHCP address change failed; "+
			"local_addrs still stale, will retry", "err", err)
		d.armIPsecRebind() // pending stays set; the loop is already active
		return false
	}
	d.clearIPsecRebindPending()
	return d.disarmIPsecRebindIfConverged()
}
