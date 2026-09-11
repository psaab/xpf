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

// confirmRollbackTargetHandledAtFire runs the appliability pre-flight on the
// pending rollback target before anything is promoted. It returns false when the
// normal rollback should proceed (the target is appliable, or there is no
// non-nil target to check). It returns true when it handled the fire itself:
//   - a target that waits only on a feed is deferred, up to
//     confirmRollbackFeedRetryMax attempts, without promoting;
//   - any other refusal, or a feed still unready at the cap, promotes the store
//     to the target (persisted as committed, as #6538 does for a recovered
//     target that no longer compiles) and enters the bootstrap/lifeline safe
//     state instead of applying a target the dataplane refuses.
//
// Caller holds applySem.
func (d *Daemon) confirmRollbackTargetHandledAtFire(gen uint64) bool {
	target, _, ok := d.store.PendingRollbackTarget(gen)
	if !ok || target == nil {
		return false
	}
	rerr := rollbackTargetAppliablePreflight(target, d.feedSnapshotsForConfig(target))
	if rerr == nil {
		delete(d.confirmFeedDeferrals, gen)
		return false
	}
	if rollbackTargetRefusedOnlyForFeeds(target) && d.confirmFeedDeferrals[gen] < confirmRollbackFeedRetryMax {
		if d.store.DeferConfirmTimer(gen, confirmRollbackFeedRetryInterval) {
			if d.confirmFeedDeferrals == nil {
				d.confirmFeedDeferrals = make(map[uint64]int)
			}
			d.confirmFeedDeferrals[gen]++
			slog.Warn("commit confirmed timed out, but its rollback target binds a dynamic-address "+
				"feed that has not installed a snapshot yet; deferring the rollback so it is not "+
				"applied to a refused snapshot",
				"attempt", d.confirmFeedDeferrals[gen], "max", confirmRollbackFeedRetryMax,
				"retry_in", confirmRollbackFeedRetryInterval.String(), "err", rerr, "issue", "#9615")
			return true
		}
	}
	delete(d.confirmFeedDeferrals, gen)
	if _, ok := d.store.PromoteRollback(gen); !ok {
		// Superseded between the check and the promotion; nothing to do.
		return true
	}
	slog.Error("commit confirmed timed out and its rollback target is refused by the dataplane; "+
		"NOT applying it. The configuration store is reverted to the target and persisted as "+
		"committed, and the daemon enters the bootstrap/lifeline safe state; fix the "+
		"configuration from the CLI", "err", rerr, "issue", "#9615")
	if err := d.enterBootstrapMode(); err != nil {
		slog.Error("commit-confirmed rollback to the bootstrap safe state is DEGRADED: teardown "+
			"did not fully converge", "err", err, "issue", "#9615")
	}
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
	}
	msg := fmt.Sprintf("recovered commit-confirmed window, deadline %s: the rollback target is %s (%v); "+
		"confirm with `commit` or re-commit before the deadline", deadline.Format(time.RFC3339), state, rerr)
	slog.Error(msg, "issue", "#9615")
	d.store.NoteConfirmTargetAlarm(msg)
}
