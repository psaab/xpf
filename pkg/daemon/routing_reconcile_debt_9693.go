package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

// #16804 adds the flush arm: systemd-networkd's default foreign-rule
// cleanup (ManageForeignRoutingPolicyRules=yes) deletes every xpf rule
// band on `networkctl reconfigure` and on networkd restart. The shipped
// drop-in disables that cleanup, but on a host without it (or after any
// external flush) this owner is the no-commit healer. The always-on
// terminator re-assert above runs first in the tick; its RuleList
// readback (terminatorFlushed16804) then decides whether the tick
// escalates to re-run the policy bands, the route-leak republish and
// the mgmt-DNS steering reconcile, latching any failure as ordinary
// routing debt. Post-#16804 ordering invariant: the terminator
// re-assert precedes the mgmt-DNS re-assert, because tenant-VRF DNS
// lookups at prefs 2500-2503 rely on the pref-2000 l3mdev miss
// terminator ahead of them; installing steering first would open a
// window where a VRF-context lookup that should terminate instead
// follows the fresh steering rule.

// vrfMissTerminatorPriority16804 is the pref-2000 #9819 terminator
// priority (pkg/routing's vrfMissTerminatorPriority, unexported). The
// flush probe matches it in the live rule table.
const vrfMissTerminatorPriority16804 = 2000

// terminatorFlushRuleListFn reads the live policy-rule table for the
// #16804 flush probe. Production uses netlink; tests substitute a fake
// so no privileged handle is needed.
var terminatorFlushRuleListFn = func(family int) ([]int, error) {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return nil, err
	}
	prio := make([]int, 0, len(rules))
	for _, r := range rules {
		prio = append(prio, r.Priority)
	}
	return prio, nil
}

// terminatorFlushed16804 reports whether the VRF miss terminator is
// desired but missing from the live kernel rule table — the canary for
// a networkd foreign-rule flush (#16804). The probe compares the
// desired state (shouldReassertVRFMissTerminator) against a fresh
// RuleList readback in both families. A missing terminator means
// networkd (or another foreign writer) deleted xpf's rules, and every
// other band went with it.
func terminatorFlushed16804(d *Daemon) (bool, error) {
	if d.routing == nil || d.store == nil {
		return false, nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || !d.shouldReassertVRFMissTerminator(cfg) {
		return false, nil
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		prios, err := terminatorFlushRuleListFn(family)
		if err != nil {
			return false, err
		}
		found := false
		for _, p := range prios {
			if p == vrfMissTerminatorPriority16804 {
				found = true
				break
			}
		}
		if !found {
			return true, nil
		}
	}
	return false, nil
}

// routingReconcileReassertInterval paces the retry owner, matching its sibling
// re-assert loops.
var routingReconcileReassertInterval = 30 * time.Second

// routingPolicyReconcileFn, routeLeakReconcileFn,
// vrfMissTerminatorReconcileFn and mgmtDNSRulesReconcileFn are the retry
// owner's reconciles, overridable in tests: policy-routing and route-leak
// writes use concrete routing/dataplane managers, the VRF callback
// restores the #10421 post-networkd invariant, and the DNS callback
// restores the #16804 mgmt-DNS steering pairs.
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
	mgmtDNSRulesReconcileFn = func(d *Daemon) error {
		return d.applyMgmtDNSRules()
	}
)

// mgmtVRFRouteReconcileFn is the management-VRF route reconcile rerun by the
// routing debt owner. Tests inject a transient failure without opening netlink.
var mgmtVRFRouteReconcileFn = func(d *Daemon) error {
	return d.applyMgmtVRFRoutes()
}

// routingReconcileDebt records routing work that is owed. The zero value
// owes nothing, so a Daemon built as a struct literal needs no setup.
type routingReconcileDebt struct {
	mu   sync.Mutex
	owed bool
	// failures counts every failed generic routing attempt (apply + retry).
	failures uint64
	// routingLastErr holds the error for the generic routing debt.
	routingLastErr string
	// lastErr is the newest error among currently owed domains.
	lastErr string
	// Management-VRF DHCP routes share the owner but retain a separate debt so
	// retrying them does not rewrite unrelated policy-routing state.
	mgmtRoutesOwed     bool
	mgmtRoutesFailures uint64
	mgmtRoutesLastErr  string
}

// noteRoutingReconcileResult latches the generic routing debt when any of errs
// is non-nil and discharges it when all are nil.
func (d *Daemon) noteRoutingReconcileResult(errs ...error) {
	err := errors.Join(errs...)
	d.routingDebt.mu.Lock()
	defer d.routingDebt.mu.Unlock()
	if err == nil {
		if d.routingDebt.owed {
			slog.Info("routing reconcile converged; routing reconcile debt discharged", "issue", "#9693")
		}
		d.routingDebt.owed = false
		d.routingDebt.routingLastErr = ""
		if d.routingDebt.mgmtRoutesOwed {
			d.routingDebt.lastErr = d.routingDebt.mgmtRoutesLastErr
		} else {
			d.routingDebt.lastErr = ""
		}
		return
	}
	if !d.routingDebt.owed {
		slog.Warn("routing reconcile failed; the retry owner will re-run it until it succeeds",
			"err", err, "issue", "#9693")
	}
	d.routingDebt.owed = true
	d.routingDebt.failures++
	d.routingDebt.routingLastErr = err.Error()
	d.routingDebt.lastErr = err.Error()
}

// noteMgmtRouteReconcileResult latches or discharges the DHCP management-route
// debt independently from policy-routing work.
func (d *Daemon) noteMgmtRouteReconcileResult(err error) {
	d.routingDebt.mu.Lock()
	defer d.routingDebt.mu.Unlock()
	if err == nil {
		if d.routingDebt.mgmtRoutesOwed {
			slog.Info("management-VRF route reconcile converged; routing debt discharged",
				"issue", "#11450")
		}
		d.routingDebt.mgmtRoutesOwed = false
		d.routingDebt.mgmtRoutesLastErr = ""
		if d.routingDebt.owed {
			d.routingDebt.lastErr = d.routingDebt.routingLastErr
		} else {
			d.routingDebt.lastErr = ""
		}
		return
	}
	if !d.routingDebt.mgmtRoutesOwed {
		slog.Warn("management-VRF route reconcile failed; the retry owner will re-run it until it succeeds",
			"err", err, "issue", "#11450")
	}
	d.routingDebt.mgmtRoutesOwed = true
	d.routingDebt.mgmtRoutesFailures++
	d.routingDebt.mgmtRoutesLastErr = err.Error()
	d.routingDebt.lastErr = err.Error()
}

// RoutingReconcileDebt reports whether any routing reconcile is owed, how many
// attempts have failed, and the most recent outstanding error.
func (d *Daemon) RoutingReconcileDebt() (owed bool, failures uint64, lastErr string) {
	d.routingDebt.mu.Lock()
	defer d.routingDebt.mu.Unlock()
	owed = d.routingDebt.owed || d.routingDebt.mgmtRoutesOwed
	failures = d.routingDebt.failures + d.routingDebt.mgmtRoutesFailures
	lastErr = d.routingDebt.lastErr
	return owed, failures, lastErr
}

func (d *Daemon) routingReconcileOwed() bool {
	d.routingDebt.mu.Lock()
	defer d.routingDebt.mu.Unlock()
	return d.routingDebt.owed || d.routingDebt.mgmtRoutesOwed
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

// reassertRoutingReconcileOnce retries only the routing domains that owe work.
// Management-VRF DHCP routes have their own bit within routing debt, so a
// failed route refresh does not rewrite unrelated policy-routing state.
//
// It takes applySem BEFORE reading the active config, for the reason #4001 gave
// the proxy-ARP loop: a config read outside the semaphore could capture a
// pre-commit snapshot and re-assert rules a concurrent commit has just removed.
// A canceled tick returns before any semaphore acquisition; bootstrap ticks
// retain debt-gated policy/route-leak retries but skip VRF takeover writes. A
// no-debt tick uses TryAcquire so it does not queue behind a commit that has
// nothing for the retry owner to do; once it owns the semaphore it still
// reasserts the VRF miss terminator.
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

	var vrfErr error
	if !d.inBootstrap() {
		vrfErr = vrfMissTerminatorReconcileFn(d)
	}

	d.routingDebt.mu.Lock()
	routingOwed := d.routingDebt.owed
	mgmtRoutesOwed := d.routingDebt.mgmtRoutesOwed
	d.routingDebt.mu.Unlock()

	// #16804: detect external networkd foreign-rule cleanup (a networkd
	// restart on a host without the shipped drop-in, or any flush between
	// commits). The terminator above is the canary: when the always-on
	// re-assert finds kernel rules missing — the terminator had to be
	// (re)installed — every other xpf band was flushed too, so the tick
	// escalates to a full re-assert of the policy bands, the route-leak
	// snapshot and the mgmt-DNS steering pairs, then latches the outcome
	// as routing debt so a failure keeps retrying. RuleList/readback
	// counts as detection: the terminator reconcile reads live state on
	// every tick. Nothing is written on a healthy no-flush tick beyond
	// the terminator's existing check.
	flushed := false
	if !d.inBootstrap() {
		f, ferr := terminatorFlushed16804(d)
		if ferr != nil {
			slog.Warn("networkd foreign-rule flush probe failed; will retry",
				"err", ferr, "issue", "#16804")
		}
		flushed = f
	}

	if !routingOwed && !flushed {
		// The VRF miss terminator remains an always-on day-2 check, independent
		// of whether policy-routing or management routes are owed.
		d.noteRoutingReconcileResult(vrfErr)
		if vrfErr != nil {
			slog.Warn("VRF miss terminator day-2 re-assert failed; will retry",
				"err", vrfErr, "issue", "#10458")
		}
	} else {
		err := errors.Join(
			routingPolicyReconcileFn(d, cfg),
			routeLeakReconcileFn(d, cfg, d.commitOverlayForConfig(cfg)),
			vrfErr,
			mgmtDNSRulesReconcileFn(d),
		)
		d.noteRoutingReconcileResult(err)
		if err != nil {
			slog.Warn("routing reconcile re-assert failed; will retry", "err", err, "issue", "#9693")
		}
	}

	if mgmtRoutesOwed {
		err := mgmtVRFRouteReconcileFn(d)
		d.noteMgmtRouteReconcileResult(err)
		if err != nil {
			slog.Warn("management-VRF route re-assert failed; will retry",
				"err", err, "issue", "#11450")
		}
	}
}
