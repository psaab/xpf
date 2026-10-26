// Daemon-side wiring for #801 Phase-B Step-0 host tunables.
//
// This file owns the state machine for the B1 opt-in gate and the B2
// restore-on-disable path. The pure capture/restore logic lives in
// host_tunables.go — here we route calls through the Daemon struct's
// priorTunables field so the same snapshot survives startup → commit →
// disable → shutdown.
//
// # Scope split (Codex round-2 fix)
//
// Two separate blast radii travel through this file:
//
//  1. Host-scope knobs (cpu-governor, netdev_budget): these touch
//     system-wide kernel state that every other workload on the host
//     shares. They MUST stay behind the `claim-host-tunables` opt-in
//     gate per the B1 finding — flipping the CPU governor or raising
//     netdev_budget silently would violate D3's "only touch what xpfd
//     owns" invariant.
//
//  2. Per-interface coalescence (ethtool -C adaptive / rx-usecs /
//     tx-usecs): this is interface-scoped — same blast radius as D3's
//     RSS indirection rewrite. The #801 Step-0 win (REV CoV
//     7.68%→1.5% on mlx5 adaptive-off) lives entirely in this knob.
//     It runs regardless of `claim-host-tunables` because the mlx5
//     interface is already inside xpfd's zone model, identified via
//     the same `UserspaceBoundLinuxInterfaces` allowlist D3 uses.
//
// Transition matrix for the host-scope knobs (opt_in = claim-host-tunables):
//
//	prior      new        action
//	-------    -------    ----------------------------------------------
//	false      false      no-op (never claimed)
//	false      true       capture + write
//	true       true       capture-if-not-already + write (reconcile)
//	true       false      restore (B2); drop restored captures, RETAIN
//	                      any whose write failed + stay active to retry
//	                      the debt next reconcile (#5114)
//	(shutdown) *          restore (if active) on daemon Stop
//
// Coalescence (interface-scoped) runs on every apply with the same
// allowlist, capturing its own pre-xpfd state for restore on explicit
// adaptive re-enable or daemon shutdown.
package daemon

import (
	"context"
	"log/slog"
	"sort"
	"time"
)

// applyStep0Tunables is the single wire point for #801 Step-0 host
// tunables. Called from Run() at startup and from applyConfig() on
// every commit. Handles three responsibilities:
//
//  1. Opt-in gate (B1): host-scope knobs + adaptive flip are only
//     applied when claim_host_tunables is true.
//  2. Snapshot + write (B2): on every apply while claimed, the
//     pre-xpfd value is captured before the first write so restore can
//     revert to the exact pre-xpfd string.
//  3. Restore-on-disable (B2): when claim flips true → false, every
//     captured value is written back. A field is dropped from the
//     snapshot only after its restore write SUCCEEDS; a failed write
//     retains the capture + keeps priorTunablesActive true so the next
//     reconcile retries it (#5114 retry-debt invariant).
//
// Never returns an error — any failure logs and continues. Tunable
// regressions must not block commit or daemon start.
func (d *Daemon) applyStep0Tunables(userspaceDP, claimHostTunables bool,
	governor string, netdevBudget int,
	coalesceExplicit, coalesceEnable bool, coalesceRX, coalesceTX int,
	rssAllowed []string) {
	d.applyStep0TunablesWith(userspaceDP, claimHostTunables, governor, netdevBudget,
		coalesceExplicit, coalesceEnable, coalesceRX, coalesceTX, rssAllowed,
		realHostTunableFS{}, realRSSExecutor{})
}

// applyStep0TunablesWith is the injectable variant used by unit tests.
// Production callers go through applyStep0Tunables (which pins the FS
// + executor to the real implementations).
//
// The function runs two independent pipelines, deliberately NOT a
// shared gate (Codex round-2 BLOCKER fix):
//
//   - Coalescence (interface-scoped): always runs for userspace-dp
//     mlx5 interfaces on the `rssAllowed` allowlist, regardless of
//     `claimHostTunables`. The mlx5 adaptive-off win is the headline
//     #801 result and defaulting it off behind an opt-in gate would
//     disable it for everyone who doesn't also opt into the
//     host-scope knobs. Coalescence captures its own pre-xpfd state
//     into `d.priorTunables.mlx5Adaptive` so shutdown-restore still
//     reverts the interfaces xpfd touched.
//
//   - Host-scope knobs (cpu-governor, netdev_budget): gated by
//     `claimHostTunables` per the B1 finding. Same state machine as
//     before — capture/write on first claim, restore-on-disable when
//     the opt-in flips back off.
func (d *Daemon) applyStep0TunablesWith(userspaceDP, claimHostTunables bool,
	governor string, netdevBudget int,
	coalesceExplicit, coalesceEnable bool, coalesceRX, coalesceTX int,
	rssAllowed []string,
	fs hostTunableFS, execer rssExecutor) {

	d.priorTunablesMu.Lock()
	prior := d.priorTunables
	active := d.priorTunablesActive
	d.priorTunablesMu.Unlock()

	// Ensure a snapshot exists for coalescence capture even when the
	// host-scope opt-in is off. The snapshot is the same struct used
	// by the host-scope path; only the governors/budget sub-fields
	// remain empty until (and unless) the operator opts in. This
	// keeps shutdown-restore honest: interfaces xpfd touched are
	// reverted even when cpu-governor/netdev_budget were never set.
	if prior == nil {
		prior = newPriorHostTunables()
	}

	// #6801: hand back every NIC that LEFT the userspace-dp allowlist
	// before re-applying anything to the set xpfd retains. Both
	// reconcilers below (and reapplyRSSIndirection on the commit path)
	// iterate only the CURRENT allowlist, so without this pass a NIC
	// dropped from the binding set — or the whole set, when userspace-dp
	// is disabled at runtime and rssAllowed goes empty — kept xpfd's
	// concentrated RSS table and adaptive-off/pinned-usecs coalescence
	// until the daemon exited.
	//
	// Ordering: released and retained are disjoint by construction
	// (released = owned - current), so placing this before the claim and
	// the re-apply is the device_map managed->unmapped precedent — hand
	// the NIC back first — not a correctness dependency.
	//
	// An empty allowlist is NOT a withdrawal while userspace-dp is still
	// enabled; only the config signal is. See releaseUnboundNICTunables.
	releaseUnboundNICTunables(prior, rssAllowed, userspaceDP, execer)

	// Coalescence always runs for userspace-dp deploys. Empty
	// allowlist = no-op inside applyCoalescence. The allowlist is
	// D3-scoped (UserspaceBoundLinuxInterfaces) so we never touch an
	// mlx5 interface outside xpfd's zone model.
	if userspaceDP {
		// #6801: claim the current allowlist's mlx5 members before the
		// writes below. Ownership is what the released-NIC teardown
		// consumes on a later reconcile; a NIC xpfd tunes but never
		// records is a NIC it can never hand back.
		claimNICTunableOwnership(prior, rssAllowed, execer)
		applyCoalescence(coalesceEnable, coalesceRX, coalesceTX, rssAllowed, execer, prior)
		// #1636 option B: lower the kernel neighbor retrans_time_ms so a
		// dropped ARP/NDP solicit is re-driven ~4× sooner. NOT gated on
		// claim-host-tunables — it is a neighbor-resolution timing knob,
		// strictly beneficial for forwarding, captured + restored on stop.
		applyNeighRetransTime(fs, prior)
	} else if len(prior.neighRetrans) > 0 {
		// #1636 (Codex r1 / AGY r1 #3): userspace-dp was disabled at
		// runtime (without a daemon stop). Restore the neighbor
		// retrans_time_ms values we previously lowered and discard the
		// captures so a later re-enable re-captures cleanly. Without this
		// the lowered values would persist for the daemon lifetime even
		// though the dataplane that wanted them is gone.
		//
		// #5114: drop only the paths whose restore write SUCCEEDED;
		// restoreNeighRetransTime returns the failed captures, which we
		// keep as retry debt so the next reconcile (this same branch
		// re-fires while userspace-dp stays disabled and captures remain)
		// retries them. A transient /proc write failure must not strand
		// the host at the lowered 250ms.
		prior.neighRetrans = restoreNeighRetransTime(prior, fs)
	}

	// Host-scope restore path: previously claimed, now gated off.
	// Restore only the host-scope fields (governors + budget); leave
	// the mlx5Adaptive captures in place because coalescence is still
	// active and those are the snapshots shutdown-restore relies on.
	if active && (!userspaceDP || !claimHostTunables) {
		slog.Info("linksetup: claim-host-tunables disabled, restoring pre-xpfd host-scope values")
		res := restoreHostScopeTunables(prior, fs)
		d.priorTunablesMu.Lock()
		// Keep the snapshot object alive if coalescence just
		// captured new mlx5 state; only touch host-scope fields.
		//
		// #5114: ownership is released only after a SUCCESSFUL restore.
		// Retain the captures whose kernel write FAILED (drop the ones
		// that restored) and, if any remain, keep priorTunablesActive
		// true so this same restore path re-fires on the next reconcile
		// and retries the debt — a transient sysfs/proc write failure
		// must not leave the host pinned at xpfd's governor /
		// netdev_budget after the operator withdrew consent.
		prior.governors = res.failedGovernors
		if res.budgetFailed {
			prior.budget = res.budgetValue
		} else {
			prior.budget = ""
		}
		d.priorTunables = prior
		if res.allRestored() {
			// Claim is now off and every host-scope knob reverted;
			// release ownership so the restore path stops firing.
			d.priorTunablesActive = false
		} else {
			slog.Warn("linksetup: host-scope tunable restore incomplete, retaining capture for retry",
				"failed_governors", len(res.failedGovernors),
				"budget_failed", res.budgetFailed)
		}
		d.priorTunablesMu.Unlock()
		return
	}

	// No-op host-scope path: never claimed, nothing to do there.
	// Coalescence writes (if any) already happened above.
	if !userspaceDP || !claimHostTunables {
		slog.Debug("linksetup: step0 host-scope tunables skip (claim-host-tunables not set)",
			"userspace_dp", userspaceDP, "claim", claimHostTunables)
		// Persist the snapshot so coalescence captures survive across
		// reconciles even when the operator never opts in.
		d.priorTunablesMu.Lock()
		d.priorTunables = prior
		d.priorTunablesMu.Unlock()
		return
	}

	// Claim path: snapshot + host-scope write. Host-scope snapshot
	// fields may already be captured from a previous claimed apply;
	// applyHostTunables's capture*() helpers are first-apply-wins so
	// the reconcile case is safe.
	gov, budget := resolvedHostTunables(governor, netdevBudget, true)
	applyHostTunables(gov, budget, fs, prior)

	d.priorTunablesMu.Lock()
	d.priorTunables = prior
	d.priorTunablesActive = true
	d.priorTunablesMu.Unlock()
}

// restoreStep0TunablesOnShutdown is called from the daemon's shutdown
// path. It restores every captured tunable so the host reverts to its
// pre-xpfd state when xpfd exits — matching D3's cleanup contract and
// preventing operators from being left with performance governor +
// netdev_budget=600 after stopping the daemon.
//
// Covers both pipelines from applyStep0TunablesWith:
//   - Host-scope (governor + netdev_budget): captured only when the
//     claim-host-tunables opt-in was active. `active` flag tells us.
//   - Per-interface coalescence (mlx5Adaptive map): captured any time
//     coalescence ran, which is any userspace-dp start regardless of
//     the opt-in gate (Codex round-2 fix).
//
// NOT covered: the #6801 rssOwned claim. Restoring the default RSS
// indirection table on daemon stop is a separate lifecycle question from
// the allowlist-shrink teardown this file implements — it would add a
// second bounded `ethtool` round-trip per owned NIC to a shutdown path
// already capped by the unit's TimeoutStopSec=20, and it changes the
// restart profile (default table on stop, re-concentrated on the next
// boot). #6801 deliberately scopes itself to interfaces that leave xpf's
// ownership while the daemon keeps running.
//
// Best-effort: never returns an error. Safe to call when no tunable
// was ever captured (no-op).
func (d *Daemon) restoreStep0TunablesOnShutdown() {
	ctx, cancel := newShutdownApplyContext()
	defer cancel()
	d.restoreStep0TunablesOnShutdownWithContext(ctx)
}

func (d *Daemon) restoreStep0TunablesOnShutdownWithContext(ctx context.Context) {
	// Serialize against an un-drained apply (#4691). applyStep0TunablesWith
	// mutates the shared priorTunables snapshot's maps (governors, budget,
	// mlx5Adaptive, neighRetrans) OUTSIDE priorTunablesMu — the mutex only
	// guards the pointer read/write, while applyCoalescence /
	// applyHostTunables / applyNeighRetransTime write the maps after the
	// mutex is dropped. A DHCP lease apply can still be in flight when
	// shutdown fires; it runs under d.applySem (via applyConfig), so acquiring
	// applySem here serializes this restore's snapshot handoff + map iteration
	// against that apply, matching the lock the apply path already holds.
	//
	// The acquire uses the shared shutdown deadline. Unlike the drain and
	// scheduler stop, this path cannot safely proceed without the permit: it
	// iterates and mutates the apply-owned snapshot maps. If the lock remains
	// unavailable, preserve the snapshot and skip restore rather than race.
	if d.applySem != nil {
		waitBudget := time.Duration(0)
		if deadline, ok := ctx.Deadline(); ok {
			waitBudget = time.Until(deadline)
			if waitBudget < 0 {
				waitBudget = 0
			}
		}
		if acquired, err := d.acquireApplySemForShutdownContext(ctx); acquired {
			defer d.applySem.Release(1)
		} else {
			slog.Warn("shutdown: host tunables restore skipped because the apply lock "+
				"was unavailable; captured state preserved without an unsafe restore",
				"err", err, "wait_budget", waitBudget, "issue", "#17014")
			return
		}
	}

	d.priorTunablesMu.Lock()
	prior := d.priorTunables
	active := d.priorTunablesActive
	d.priorTunables = nil
	d.priorTunablesActive = false
	d.priorTunablesMu.Unlock()

	if prior == nil {
		slog.Debug("shutdown: host tunables restore skip (no captures)")
		return
	}
	restoreStep0Captures(prior, active, realHostTunableFS{}, realRSSExecutor{})
}

// restoreStep0Captures puts every captured tunable back. Split from
// restoreStep0TunablesOnShutdown, which owns the snapshot handoff (apply-lock,
// priorTunablesMu, one-shot clear), so the restore ITSELF is reachable from a
// test with injected backends. Without that split a test can only call the leaf
// restores directly, which leaves the calls FROM here — the wiring, the thing
// that was actually missing in #7619 — unbound.
func restoreStep0Captures(prior *priorHostTunables, active bool,
	fs hostTunableFS, execer rssExecutor) {
	if prior == nil {
		return
	}
	// Scope the log message to what we actually restore so operators
	// can tell a coalescence-only revert from a full host-scope revert.
	hasHostScope := step0HasHostScope(prior, active)
	if !step0RestoreHasCaptures(prior, active) {
		slog.Debug("shutdown: host tunables restore skip (empty captures)")
		return
	}
	slog.Info("shutdown: restoring tunables to pre-xpfd values",
		"host_scope", hasHostScope, "coalesce_ifaces", len(prior.mlx5Adaptive),
		"neigh_retrans", len(prior.neighRetrans) > 0, "rss_ifaces", len(prior.rssOwned))
	// Host-scope restore is gated on `active`: if the opt-in was
	// already flipped off during runtime, we already restored those
	// fields in applyStep0TunablesWith; running the write again would
	// be a no-op but the map may also have been cleared on that path.
	if active {
		restoreHostScopeTunables(prior, fs)
	}
	// Coalescence restore always runs when captures exist.
	for iface, s := range prior.mlx5Adaptive {
		restoreMlx5Coalesce(iface, s, execer)
	}
	// #1636: neigh retrans_time_ms restore runs unconditionally (the
	// apply was never gated on claim-host-tunables) so a co-tenant's
	// tuned value is put back when xpfd exits.
	restoreNeighRetransTime(prior, fs)
	// #7619: and the RSS indirection table, which this path did not restore.
	restoreOwnedRSSOnShutdown(prior, execer, rssShutdownRestoreBudget)
}

// step0HasHostScope reports whether the host-SCOPE captures (governors, the
// NAPI budget) are ours to put back. Gated on `active` because an opt-in
// flipped off at runtime already restored those fields in
// applyStep0TunablesWith, which may also have cleared the map.
func step0HasHostScope(prior *priorHostTunables, active bool) bool {
	if prior == nil {
		return false
	}
	return active && (len(prior.governors) > 0 || prior.budget != "")
}

// step0RestoreHasCaptures reports whether the shutdown restore has any owned
// state to put back. Extracted from restoreStep0TunablesOnShutdown so the
// empty-captures early return is testable without a live Daemon.
//
// #7619: a NIC whose RSS indirection table xpf concentrated onto the
// userspace-dp queue set is owned state too, so `rssOwned` belongs in this
// predicate. The subtlest way to get that fix wrong is to append the RSS
// restore at the bottom of the caller while leaving this guard unaware of the
// map — a NIC with ONLY rss ownership (no host-scope opt-in, no coalescence
// capture, no neigh retrans) then takes the early return and the defect
// survives its own fix. Adding a capture kind below without adding it here is
// the same bug again.
func step0RestoreHasCaptures(prior *priorHostTunables, active bool) bool {
	if prior == nil {
		return false
	}
	return step0HasHostScope(prior, active) ||
		len(prior.mlx5Adaptive) > 0 ||
		len(prior.neighRetrans) > 0 ||
		len(prior.rssOwned) > 0
}

// rssShutdownRestoreBudget bounds the TOTAL wall-clock time the #7619
// restore-on-stop may spend, mirroring hostAuthCloseoutBudget (#5874).
//
// This runs on the shutdown path, which the unit caps at TimeoutStopSec=20, and
// it adds an `ethtool` round-trip per owned NIC. A hung ethtool must cost a
// logged timeout, not a SIGKILLed daemon — so the budget is well under the
// unit's, leaving room for the restores that already run above it. A var so a
// test can shrink it and observe its own timeout rather than waiting.
var rssShutdownRestoreBudget = 5 * time.Second

// restoreOwnedRSSOnShutdown reverts every NIC whose RSS indirection table xpf
// concentrated onto the userspace-dp queue set (#7619).
//
// WHY ON EVERY STOP, INCLUDING A RESTART'S. The issue asks whether a stop that
// is part of a `systemctl restart` should be exempt, and notes it may not be
// distinguishable. It is not: systemd delivers an ordinary SIGTERM either way
// and exposes nothing at stop time that separates them. So "restore only on a
// real stop" is not implementable, and the choice is restore-always or
// restore-never.
//
// Restore-always is right, and the churn it adds to a restart — default the
// table, then re-concentrate on the next start — is bounded at two ethtool
// calls per owned NIC across a window in which the daemon is not forwarding
// anyway. Restore-never is today's defect: the kernel stack runs on a table
// shaped for a dataplane that is not there until the next boot or a manual
// `ethtool -X <if> default`.
//
// THE RETRY DEBT IS DIFFERENT FROM #6801's, DELIBERATELY. That path drops
// ownership only after a successful restore, so a later tick can retry. A stop
// has no later tick, so a failure here is logged and left: the process is
// exiting and the in-memory ownership map goes with it. The reconciliation is
// the next boot's claim, which re-captures and re-applies. A NIC left
// concentrated by a failed restore-on-stop is therefore only stranded if xpfd
// never starts again — a case no shutdown path can fix.
func restoreOwnedRSSOnShutdown(prior *priorHostTunables, execer rssExecutor, budget time.Duration) {
	if prior == nil || len(prior.rssOwned) == 0 {
		return
	}
	// Sorted so a timeout truncates a deterministic prefix rather than a random
	// one — an operator comparing two shutdowns can otherwise not tell a
	// different failure from a different map order.
	ifaces := make([]string, 0, len(prior.rssOwned))
	for iface := range prior.rssOwned {
		ifaces = append(ifaces, iface)
	}
	sort.Strings(ifaces)

	deadline := time.Now().Add(budget)
	restored, failed, skipped := 0, 0, 0
	for _, iface := range ifaces {
		if !time.Now().Before(deadline) {
			skipped = len(ifaces) - restored - failed
			slog.Warn("shutdown: rss indirection restore budget exhausted, "+
				"remaining interfaces keep the xpf-concentrated table until the next "+
				"boot re-applies or `ethtool -X <if> default` is run by hand (#7619)",
				"budget", budget, "restored", restored, "failed", failed,
				"not_attempted", skipped)
			break
		}
		if err := restoreDefaultRSSIndirectionOne(iface, execer); err != nil {
			failed++
			slog.Warn("shutdown: rss indirection restore failed; this NIC keeps the "+
				"xpf-concentrated table until the next boot's claim reconciles it (#7619)",
				"iface", iface, "err", err)
			continue
		}
		restored++
	}
	slog.Info("shutdown: rss indirection restore complete",
		"restored", restored, "failed", failed, "not_attempted", skipped)
}
