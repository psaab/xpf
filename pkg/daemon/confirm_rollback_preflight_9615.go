package daemon

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9615: the #6707/#9588 rollback-target pre-flight ran only when a
// `commit confirmed` window was ARMED in this process. A window Store.Load
// re-arms at boot was never checked, and the timeout path applied its target
// unconditionally. Two ways a recovered target becomes one the helper refuses:
// an upgrade inside the window whose new refusal classes cover the old config,
// and a dynamic-address feed the target binds that has not installed a snapshot
// yet after the restart.
//
// Refusing to re-arm is not the answer: that would make the unconfirmed commit
// permanent. So the check happens twice, and never un-arms:
//   - at boot, an alarm naming the reasons and the deadline, while the operator
//     can still confirm or re-commit (checkRecoveredConfirmTarget);
//   - when the timer fires, BEFORE PromoteRollback, where deferring or choosing
//     the safe state creates no store/dataplane mismatch
//     (confirmRollbackTargetHandledAtFire).

// confirmRollbackFeedRetryInterval is the spacing of deferred rollback attempts
// while the target waits on a feed. A var so tests can keep the re-armed timer
// from firing after the cell returns.
var confirmRollbackFeedRetryInterval = 5 * time.Second

// confirmRollbackFeedRetryMax bounds the deferral: 24 x 5 s is two minutes past
// the deadline, after which a still-unready feed is treated as a refusal.
const confirmRollbackFeedRetryMax = 24

// rollbackTargetRefusedOnlyForFeeds reports whether target's whole-snapshot
// refusal goes away once every dynamic-address binding resolves, i.e. the only
// reason is a feed with no installed snapshot (#5645 fails that closed).
func rollbackTargetRefusedOnlyForFeeds(target *config.Config) bool {
	if target == nil {
		return false
	}
	bindings := target.Security.DynamicAddress.AddressBindings
	if len(bindings) == 0 {
		return false
	}
	overlay := make(map[string][]string, len(bindings))
	for name := range bindings {
		overlay[name] = []string{"192.0.2.0/24", "2001:db8::/64"}
	}
	return len(dpuserspace.PolicyContentRejectionReasons(target, overlay)) == 0
}

// rollbackTargetFeedProducersAbsent reports whether any feed named by
// target's dynamic-address bindings has no running producer in d.feeds
// (#16661). A missing producer means the abandoned config's apply cancelled
// it (feed removed/renamed by C2); no fetch will ever install its snapshot
// while C2 stays enforced, so deferring on it cannot converge. A producer
// that exists but has not fetched yet is the #9615 late-feed case and is NOT
// absent. Returns false when there is no feed manager / no bindings to
// inspect (cannot prove absence — keep the existing deferral semantics).
func (d *Daemon) rollbackTargetFeedProducersAbsent(target *config.Config) bool {
	if d == nil || d.feeds == nil || target == nil {
		return false
	}
	bindings := target.Security.DynamicAddress.AddressBindings
	if len(bindings) == 0 {
		return false
	}
	live := d.feeds.AllFeeds()
	for _, b := range bindings {
		if b == nil {
			continue
		}
		for _, feedName := range b.FeedNames {
			if _, ok := live[feedName]; !ok {
				return true
			}
		}
	}
	return false
}

// rollbackTargetRefusedOnlyForDNS reports whether target's refusal is
// attributable to dns-name entries whose resolution failed or had not yet
// run when the target was compiled at Store.Load (#16612/#17782). It
// re-resolves a private clone with current DNS. A refreshed target that no
// longer refuses is DNS-only when the frozen target had an unavailable name.
// If the refreshed clone still refuses while DNS remains unavailable, the
// refusal is DNS-only only when making unavailable entries usable clears every
// rejection. A refusal that persists after that causal probe is not DNS-only,
// so a target with an unrelated static refusal is not smuggled past the gate.
func rollbackTargetRefusedOnlyForDNS(target *config.Config) bool {
	if target == nil || !targetHasUnavailableDNSResolution(target) {
		return false
	}
	return rollbackTargetRefusedOnlyForDNSRefreshed(target, config.RefreshDNSForPreflight(target))
}

// rollbackTargetRefusedOnlyForDNSRefreshed classifies a frozen refusal against
// an already-refreshed private clone. Timer-fire callers prepare this clone
// before taking applySem so DNS cannot block another transaction's apply.
func rollbackTargetRefusedOnlyForDNSRefreshed(target, refreshed *config.Config) bool {
	if target == nil || !targetHasUnavailableDNSResolution(target) || refreshed == nil {
		return false
	}
	if len(dpuserspace.PolicyContentRejectionReasons(refreshed, nil)) == 0 {
		return true
	}
	// Still refused after refresh. Establish causality by re-checking a second
	// private clone with each unavailable, empty dns-name entry made usable.
	// DNS is the sole cause only when this removes every refusal; any static
	// policy/snapshot refusal remains and takes the refused-target safe state.
	// Leave refreshed untouched because the fire path may use it for apply.
	dnsNeutralized := rollbackTargetWithDNSFailuresNeutralized(refreshed)
	return dnsNeutralized != nil &&
		len(dpuserspace.PolicyContentRejectionReasons(dnsNeutralized, nil)) == 0
}

// rollbackTargetWithDNSFailuresNeutralized returns a private clone where
// unavailable dns-name entries with no stale answer are given valid
// documentation-only prefixes. It is a causal-probe input for the
// DNS-only rollback classifier, never an apply target.
func rollbackTargetWithDNSFailuresNeutralized(cfg *config.Config) *config.Config {
	if cfg == nil {
		return nil
	}
	clone := cfg.CloneForDNSRefresh()
	if clone == nil {
		return nil
	}
	makeAvailable := func(book *config.AddressBook) {
		if book == nil {
			return
		}
		for _, addr := range book.Addresses {
			if addr == nil || addr.DNSName == "" ||
				(!addr.DNSLookupFailed && !addr.DNSUnresolved) ||
				len(addr.DNSAddresses) != 0 {
				continue
			}
			switch addr.DNSFamily {
			case "ipv4-only":
				addr.DNSAddresses = []string{"192.0.2.1/32"}
			case "ipv6-only":
				addr.DNSAddresses = []string{"2001:db8::1/128"}
			default:
				addr.DNSAddresses = []string{"192.0.2.1/32", "2001:db8::1/128"}
			}
			addr.DNSLookupFailed = false
			addr.DNSUnresolved = false
		}
	}
	makeAvailable(clone.Security.AddressBook)
	for _, named := range clone.Security.NamedAddressBooks {
		if named != nil {
			makeAvailable(&named.AddressBook)
		}
	}
	for _, zone := range clone.Security.Zones {
		if zone != nil {
			makeAvailable(zone.AddressBook)
		}
	}
	return clone
}

// targetHasUnavailableDNSResolution reports whether cfg carries a dns-name
// entry whose latest attempt failed or whose cache had not yet been populated.
func targetHasUnavailableDNSResolution(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	found := false
	scan := func(b *config.AddressBook) {
		if b == nil {
			return
		}
		for _, a := range b.Addresses {
			if a != nil && a.DNSName != "" && (a.DNSLookupFailed || a.DNSUnresolved) {
				found = true
			}
		}
	}
	scan(cfg.Security.AddressBook)
	for _, nb := range cfg.Security.NamedAddressBooks {
		if nb != nil {
			scan(&nb.AddressBook)
		}
	}
	for _, z := range cfg.Security.Zones {
		if z != nil {
			scan(z.AddressBook)
		}
	}
	return found
}

// confirmRollbackTargetHandledAtFire runs the appliability pre-flight on the
// pending rollback target before anything is promoted. It returns false when the
// normal rollback should proceed (the target is appliable, or there is no
// non-nil target to check). It returns true when it handled the fire itself:
//   - a target refused only because a dns-name lookup failed or was still
//     unresolved at load (#16612/#17782) is refreshed before applySem is
//     acquired. If the refreshed clone is healthy, rollback proceeds with that
//     clone; if DNS is still failing it is deferred up to
//     confirmRollbackFeedRetryMax attempts, then proceeds with the current
//     fail-closed answers;
//   - a target that waits only on a feed is deferred, up to
//     confirmRollbackFeedRetryMax attempts, without promoting. At the feed
//     cap the safe state is taken — EXCEPT when the target's feed producer is
//     absent because the abandoned config removed/renamed it (#16661): the
//     producers are then reconciled FOR THE TARGET and the deferral restarts,
//     so bootstrap is never reached for a refusal whose producer nobody was
//     running;
//   - any other refusal, or a feed still unready at the cap (with its
//     producer running), promotes the store to the target (persisted as
//     committed, as #6538 does for a recovered target that no longer
//     compiles) and enters the bootstrap/lifeline safe state instead of
//     applying a target the dataplane refuses.
//
// #15056 (A32-03): the refused branch is also a rollback for #3868 purposes.
// The standby holds the abandoned unconfirmed config (C2) as its permanent
// active (config-sync SyncApply arms no confirm timer there), so the promoted
// target must be re-synced to the peer BEFORE enterBootstrapMode
// relinquishes the cluster (#6742 resigns every RG and stops comms — after
// that no push is possible, and the #5863 reconciler is gated on RG0
// authority and live comms too). The peer-snapshot authorization is captured
// before the push so a multi-zone target is still refused for an incapable
// peer at the queue boundary rather than silently narrowed there.
//
// Caller holds applySem. DNS was refreshed into refreshedTarget before the
// caller acquired it; this function performs no network I/O.
func (d *Daemon) confirmRollbackTargetHandledAtFire(
	gen uint64,
	sampledTarget, refreshedTarget *config.Config,
) bool {
	target, _, ok := d.store.PendingRollbackTarget(gen)
	if !ok || target == nil {
		return false
	}
	if target != sampledTarget {
		// The generation was superseded between DNS sampling and applySem
		// acquisition. Do not classify a different target from stale answers.
		refreshedTarget = nil
	}
	rerr := rollbackTargetAppliablePreflight(target, d.feedSnapshotsForConfig(target))
	if rerr == nil {
		delete(d.confirmFeedDeferrals, gen)
		return false
	}
	feedOnly := rollbackTargetRefusedOnlyForFeeds(target)
	dnsOnly := !feedOnly && rollbackTargetRefusedOnlyForDNSRefreshed(target, refreshedTarget)
	if dnsOnly && len(dpuserspace.PolicyContentRejectionReasons(refreshedTarget, nil)) == 0 {
		// DNS is healthy now. The frozen compiled target is stale, but the
		// refreshed clone is appliable; proceed with rollback immediately
		// and use this same clone for the apply.
		delete(d.confirmFeedDeferrals, gen)
		return false
	}
	if feedOnly && d.rollbackTargetFeedProducersAbsent(target) {
		// #16661: the abandoned config's apply cancelled the target's feed
		// producer (feed removed or renamed by C2). Deferring would wait
		// forever on a producer only this rollback's own apply would restart,
		// then enter bootstrap at the cap. Reconcile the producers FOR THE
		// TARGET (as a normal apply of the target would) so its feed fetch
		// starts now; then defer this fire — the restarted fetch installs
		// asynchronously and its onUpdate / the next deferred fire re-checks
		// the pre-flight with a live producer. Never reach bootstrap for a
		// feed-only refusal whose producer was absent. The deferral counter
		// is reset: the restarted producer gets its own bounded window, so a
		// feed that never installs (server down) still converges to the
		// #9615 safe state two minutes after its producer restarts rather
		// than having burned the whole budget while no producer existed.
		d.reconcileFeeds(target)
		slog.Warn("commit confirmed timed out and its rollback target binds a dynamic-address "+
			"feed whose producer the abandoned config removed; reconciled the feed producers "+
			"for the rollback target so its fetch can install before the rollback is decided",
			"err", rerr, "issue", "#16661")
		delete(d.confirmFeedDeferrals, gen)
	}
	if (feedOnly || dnsOnly) && d.confirmFeedDeferrals[gen] < confirmRollbackFeedRetryMax {
		if d.store.DeferConfirmTimer(gen, confirmRollbackFeedRetryInterval) {
			if d.confirmFeedDeferrals == nil {
				d.confirmFeedDeferrals = make(map[uint64]int)
			}
			d.confirmFeedDeferrals[gen]++
			if dnsOnly {
				slog.Warn("commit confirmed timed out, but its rollback target's dns-name "+
					"resolution failed when the target was compiled at load; deferring the "+
					"rollback so it is not refused on a frozen answer",
					"attempt", d.confirmFeedDeferrals[gen], "max", confirmRollbackFeedRetryMax,
					"retry_in", confirmRollbackFeedRetryInterval.String(), "err", rerr, "issue", "#16612")
			} else {
				slog.Warn("commit confirmed timed out, but its rollback target binds a dynamic-address "+
					"feed that has not installed a snapshot yet; deferring the rollback so it is not "+
					"applied to a refused snapshot",
					"attempt", d.confirmFeedDeferrals[gen], "max", confirmRollbackFeedRetryMax,
					"retry_in", confirmRollbackFeedRetryInterval.String(), "err", rerr, "issue", "#9615")
			}
			return true
		}
	}
	if dnsOnly {
		// #16612: bounded DNS deferral exhausted and DNS still has not
		// produced a passing target. Do NOT enter bootstrap on the frozen
		// Load-time answer: proceed with the normal rollback. PromoteRollback
		// returns the target object, and executeConfirmedRollback resolves
		// its dns-name entries into a private clone before the apply
		// (#16687), so a recovered resolver yields the fresh answer and a
		// still-down resolver yields the per-entry fail-closed rendering
		// (#16595).
		slog.Warn("commit confirmed timed out and its rollback target is still refused only "+
			"because dns-name resolution failed at load; proceeding with the rollback — the "+
			"apply path re-resolves dns-name entries — rather than entering bootstrap on a "+
			"frozen answer", "err", rerr, "issue", "#16612")
		delete(d.confirmFeedDeferrals, gen)
		return false
	}
	delete(d.confirmFeedDeferrals, gen)
	d.pendingRenameMu.Lock()
	_, ok = d.store.PromoteRollback(gen)
	d.pendingRenameMu.Unlock()
	if !ok {
		// Superseded between the check and the promotion; nothing to do.
		return true
	}
	// #16665: record the provenance so the commit gates can distinguish
	// this already-committed safe state (plain commit allowed; #6707
	// gate skipped) from a generic first-takeover bootstrap.
	// enterBootstrapModeWithLifeline clears the flag on generic entry,
	// so this branch re-sets it after enterBootstrapMode below.
	slog.Error("commit confirmed timed out and its rollback target is refused by the dataplane; "+
		"NOT applying it. The configuration store is reverted to the target and persisted as "+
		"committed, and the daemon enters the bootstrap/lifeline safe state; fix the "+
		"configuration from the CLI with a plain `commit` of a corrected candidate "+
		"(or `commit confirmed`; its rollback target is this same safe state)", "err", rerr, "issue", "#9615")
	// #15056: re-sync the promoted target to the peer BEFORE the bootstrap
	// entry below relinquishes the cluster. Capture the peer-snapshot
	// authorization first — the same fresh token the ordinary #3868 re-sync
	// obtains inside pushCommittedConfigToPeer — so the push is gated on the
	// peer's current capability, and surface a refusal instead of dropping
	// it silently: after bootstrap there is no channel left to retry on.
	activeTarget := d.store.ActiveConfig()
	peerAuth, authErr := d.peerSnapshotProtocolAuthorizationForConfig(activeTarget)
	if authErr != nil {
		slog.Error("commit-confirmed refused-target rollback could not authorize the "+
			"peer re-sync; the peer may keep the abandoned unconfirmed config until "+
			"it is re-synced", "err", authErr, "issue", "#15056")
	} else if pushErr := d.pushCommittedConfigToPeer(peerAuth); pushErr != nil {
		slog.Error("commit-confirmed refused-target rollback peer re-sync did not "+
			"complete; the peer may keep the abandoned unconfirmed config until "+
			"it is re-synced", "err", pushErr, "issue", "#15056")
	}
	if err := d.enterBootstrapMode(); err != nil {
		slog.Error("commit-confirmed rollback to the bootstrap safe state is DEGRADED: teardown "+
			"did not fully converge", "err", err, "issue", "#9615")
	}
	// Set after enterBootstrapMode (which clears it for generic entry);
	// stays set even on degraded teardown — the box is still in the
	// refused-target safe state and still needs the commit exit.
	d.bootstrapFromRefusedRollback.Store(true)
	d.reconcileManagementAfterPromotion(d.store.ActiveConfig(),
		"commit confirmed timeout: rollback target refused by the dataplane")
	return true
}

// checkRecoveredConfirmTarget raises an operator alarm when Load re-armed a
// window whose rollback target this build's dataplane refuses. It never refuses
// to keep the window armed: that would make the unconfirmed commit permanent.
func (d *Daemon) checkRecoveredConfirmTarget() {
	if d == nil || d.store == nil {
		return
	}
	target, first, deadline, ok := d.store.RecoveredConfirmWindow()
	if !ok || first || target == nil {
		return
	}
	rerr := rollbackTargetAppliablePreflight(target, d.feedSnapshotsForConfig(target))
	if rerr == nil {
		return
	}
	state := "refused by this build's dataplane"
	if rollbackTargetRefusedOnlyForFeeds(target) {
		state = "waiting on a dynamic-address feed that has not installed a snapshot"
	} else if rollbackTargetRefusedOnlyForDNS(target) {
		state = "waiting on dns-name resolution that failed when the target was compiled at load"
	}
	msg := fmt.Sprintf("recovered commit-confirmed window, deadline %s: the rollback target is %s (%v); "+
		"confirm with `commit` or re-commit before the deadline", deadline.Format(time.RFC3339), state, rerr)
	slog.Error(msg, "issue", "#9615")
	d.store.NoteConfirmTargetAlarm(msg)
}
