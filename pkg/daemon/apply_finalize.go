package daemon

import (
	"context"
	"errors"
	"log/slog"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #17025 (R4-Q31-04): the post-promotion
// arm/apply/classify/surface/discharge/stamp/push sequence used to be
// hand-copied in the commit, peer-sync and confirm-timeout-rollback
// drivers. Nine commits had to edit two or more copies, and the
// #12072 unpublished-capture surfacing landed in the commit copy
// only. finalizePromotedApplyLocked is the ONE implementation of
// that sequence; the drivers keep only preflight/promotion, peer-push
// policy and result shaping.
//
// Ordering semantics preserved (the invariants the copies encoded,
// now stated once):
//
//   - The caller MUST hold d.applySem. The stamp helpers are
//     …UnderSem precisely because stamping outside the semaphore lets
//     a competing promotion inherit this apply's success (#6296).
//   - DNS network resolution happens BEFORE the driver acquires applySem.
//     Finalization only consumes an already-resolved private clone or
//     clones the promoted config and populates it from the DNS cache; no
//     resolver call can extend the commit/sync/rollback critical section.
//     The applied pointer still keys the plan and dataplane publication
//     (#16687).
//   - #6948: the session-invalidation plan is armed BEFORE the apply.
//     Only the caller holds the pre-commit active config — the store
//     promoted the new one upstream — and the invalidation's
//     candidate set has to be READ while the live rows still carry
//     the OLD policy numbering it is derived from.
//     applyConfigLocked takes that capture at the publication
//     boundary; without the plan it falls back to the pre-#6948
//     post-apply scan, which sweeps the sessions of whichever policy
//     inherited a deleted policy's id.
//   - #12072: an unpublished attempt still surfaces its incomplete
//     capture ONCE (surfacingIncompleteCapture), on every driver.
//     The debt survives for a later complete scan; settled retries do
//     not replay the error (capture.enumerateErr is once-only).
//   - Fatal classification (applyErrSkipsPeerSync) is driver-specific:
//     commit classifies the surfaced apply + capture error, matching
//     the original join-before-classify order; peer-sync classifies the
//     bare apply error before returning the surfaced error. Fatal commit
//     and peer-sync outcomes skip discharge; commit also skips peer push
//     and stamp. The rollback driver is the deliberate exception
//     (pre-consolidation it had NO fatal classification): it discharges
//     whenever publication landed — see finalizePromotedApplyLocked.
//     A non-fatal error leaves the config active + armed on every driver,
//     so the discharge still runs (#4234/#4342/#5578: a PARTIAL
//     invalidation is surfaced, never swallowed).
//   - The stamp is gated on the JOINED local outcome (apply +
//     discharge), never on the peer-push result: a peer failure must
//     not erase local applied proof (#4957).
//
// The legitimately-different parts stay parameters, not copies:
//
//   - applyCtx: commit/peer-sync pass d.applyCancelCtx() (daemon-stop
//     abortable, #2926); the confirm-timeout rollback passes
//     context.Background() because the store has already been
//     promoted to the target and aborting would reopen the
//     split-brain the rollback transaction exists to close (#9811).
//   - arm: the three drivers arm differently (rename ancestry for
//     commit/peer-sync, the rollback-plan flag for the rollback).
//   - stampMode: commit re-reads the CURRENT active digest
//     (stampActiveAppliedIfConvergedUnderSem); peer-sync stamps the
//     digest captured from the tree SyncApply promoted
//     (stampDigestIfConvergedUnderSem, the #6296 fix); the rollback
//     does NOT stamp here — its #12073 discharge stamps
//     MarkAppliedDigest(debt.appliedDigest) itself, and the deferred
//     (sync) vs synchronous (rollback) discharge timing differs for
//     the same reason (see the driver).
//   - respCfg (commit only): the #9841 MTU-warning response
//     projection; peer-sync/rollback pass commitOnly=false.
//   - rollback resync: the rollback's peer resync does NOT honour
//     applyErrSkipsPeerSync — see the decision note at the rollback
//     driver. That decision stays in the driver (the resync is
//     peer-push policy, not part of this sequence), stated at
//     executeConfirmedRollback and pinned by its cell.

// promotedApplyKind selects the caller-specific obligations of
// finalizePromotedApplyLocked. The kinds differ in stamp mode and
// deferred handling; everything else is shared.
type promotedApplyKind int

const (
	promotedApplyCommit promotedApplyKind = iota
	promotedApplySync
	promotedApplyRollback
)

// promotedArmKind selects the armPolicyInvalidation* helper the
// finalize step calls. The three drivers genuinely arm differently:
// commit/peer-sync carry rename ancestry (the descriptor slice is a
// distinct arm when present, a nil-descriptor arm otherwise); the
// rollback arms the rollback-plan variant (#12073 discharge stamp).
type promotedArmKind int

const (
	promotedArmWithRename promotedArmKind = iota // armPolicyInvalidationPlanWithRename
	promotedArmPlain                             // armPolicyInvalidationPlan
	promotedArmRollback                          // armPolicyInvalidationRollbackPlan
)

// already-promoted config plus the obligations of its driver.
type promotedApply struct {
	kind promotedApplyKind
	// oldActive is the pre-promotion config, for the invalidation arm and
	// discharge. newCfg is the promoted config to apply; finalization
	// clones and populates DNS from cache after transaction drivers warm it
	// before acquiring applySem.
	oldActive, newCfg *config.Config
	// armKind selects which armPolicyInvalidation* helper the
	// finalize step calls (see promotedArmKind below). Keeping the
	// choice an enum — not a closure — keeps the arm helpers
	// textually called from exactly this file (acceptance (a)).
	armKind promotedArmKind
	// renameApply carries commit/peer-sync rename ancestry into
	// the arm (nil when there is none).
	renameApply *pendingRenameApply
	// applyCtx is the context the apply runs under (see the file
	// doc: cancel-only for commit/sync, Background for rollback).
	applyCtx context.Context
	// commitOnly selects the commit driver's apply wrapper: when
	// true, the helper runs applyConfigLockedForCommit (the #9841
	// MTU-warning projection) instead of the bare apply, and
	// outcome.respCfg carries its response object. Peer-sync and
	// rollback pass false: no response exists to carry warnings.
	commitOnly bool
	// appliedDigest is the digest captured under applySem for the
	// tree being applied (peer-sync only, #6296). Empty on the other
	// drivers.
	appliedDigest string
	// syncPeer/peerSnapshotAuth drive the post-discharge peer push on
	// the commit driver. The rollback driver does not push through
	// the helper (its resync is a separate, unconditional step);
	// peer-sync never pushes.
	syncPeer         peerSyncPolicy
	peerSnapshotAuth *peerSnapshotProtocolAuthorization
	// pushPeer selects the commit-driver peer push. False on
	// peer-sync/rollback.
	pushPeer bool
	// logDischargeErr (rollback only): the rollback is a timer
	// callback with no return path, so a PARTIAL discharge is
	// surfaced via a loud slog.Error instead of being joined into a
	// return value (#5578).
	logDischargeErr bool
}

// promotedApplyOutcome is what finalizePromotedApplyLocked learned
// from one promoted apply. Drivers shape their own results from it.
type promotedApplyOutcome struct {
	// newCfg is the DNS-resolved pointer actually applied.
	newCfg *config.Config
	// respCfg is the commit driver's #9841 response projection (nil
	// when commitResp was not requested or the apply failed).
	respCfg *config.Config
	// applyErr is the apply error AFTER the #12072 unpublished-
	// capture surfacing has been joined in.
	applyErr error
	// fatal records the driver's decision: commit classifies the
	// surfaced apply error, while peer-sync and rollback classify the
	// bare apply error. A fatal commit/peer-sync outcome must not
	// propagate (no discharge ran, no stamp, and — on drivers that
	// push — no push).
	fatal bool
	// clearErr is the discharge's PARTIAL-invalidation error (nil
	// when no discharge ran or it fully succeeded). On the rollback
	// driver with logDischargeErr it has already been logged.
	clearErr error
	// localErr is errors.Join(applyErr, clearErr): the local
	// convergence outcome the stamp gates on.
	localErr error
	// peerPushErr is the commit driver's peer-push error (only when
	// pushPeer was set and the apply was not fatal).
	peerPushErr error
	// joined is errors.Join(localErr, peerPushErr) — the commit
	// driver's returned error before result shaping.
	joined error
	// deferredPending is set on the peer-sync driver when the apply
	// succeeded but publication is deferred: the caller returns a
	// cluster.ConfigApplyPendingError instead of the outcome error.
	deferredPending bool
	// deferredNoCompletion is set on the peer-sync driver when the
	// apply succeeded, publication is deferred, but no completion
	// was recorded: the caller returns applyErr (the synthesized
	// "has no publication completion" error) without arming.
	deferredNoCompletion bool
	// deferredCompletion is the deferred publication's completion
	// channel (peer-sync only, when deferredPending).
	deferredCompletion <-chan error
	// dischargeRan reports whether the #12073 discharge ran (false
	// on a fatal apply; on peer-sync it is set by the deferred
	// discharge in the caller).
	dischargeRan bool
}

// surfacingIncompleteCapture joins the #12072 unpublished-capture
// error into applyErr, once, on every driver. An unpublished attempt
// (applyErr != nil and publication did not land) whose retained debt
// matches the applied config must surface its incomplete capture: the
// capture's one ERROR alarm (enumerateErr) is the only place that
// alarm is raised, and deferring it until a later landed discharge
// would leave the operator blind to a partial scan in the meantime.
// The debt survives for a later complete scan; enumerateErr is
// once-only (errorSurfaced), so settled retries never replay it.
func (d *Daemon) surfacingIncompleteCapture(newCfg *config.Config, applyErr error) error {
	if applyErr != nil && !d.policyInvalidationPublishLanded {
		if debt := d.policyInvalidationDebt; debt != nil &&
			debt.newCfg == newCfg && debt.capture != nil {
			applyErr = errors.Join(applyErr, debt.capture.enumerateErr())
		}
	}
	return applyErr
}

// finalizePromotedApplyLocked runs the shared post-promotion
// sequence for one already-promoted config: resolve DNS, arm the
// #6948 plan, apply, surface the #12072 unpublished capture, classify
// fatal vs non-fatal, discharge the #12073 invalidation debt (when
// publication landed), stamp the applied marker (commit/sync modes),
// and — commit mode only — push to the peer.
//
// Caller MUST hold d.applySem. The helper never acquires it: the
// drivers' preflight/promotion steps hold it across the promotion
// and the apply as one critical section, and the #6296 stamp rule
// requires the stamp to run under the same hold.
//
// Driver-specific result shaping stays in the drivers:
//
//   - commit: fatal → (compiled, ErrCommittedNotApplied wrap);
//     otherwise return the (possibly warning-projected) response
//     config with outcome.joined.
//   - peer-sync: fatal → discard (nil, applyErr); deferred →
//     ConfigApplyPendingError; otherwise (compiled, applyErr) with
//     the discharge deferred into the caller's return path so it
//     joins retErr at return time (see syncAndApplyWithAncestry).
//   - rollback: noteConfigApplyResult(applyErr) latches/discharges
//     the #9811 retry debt; a fatal apply STILL resyncs to the peer
//     (the decision and its rationale live at the rollback driver);
//     the discharge runs synchronously
//     here (not deferred) because the rollback has no caller whose
//     retErr could carry it.
func (d *Daemon) finalizePromotedApplyLocked(p promotedApply) promotedApplyOutcome {
	var out promotedApplyOutcome
	// #17782: all driver DNS network work is complete before applySem.
	// Consume a privately marked refresher clone when one was supplied;
	// otherwise create a private clone and read only the warmed cache.
	newCfg := p.newCfg
	if config.HasDNSNames(p.newCfg) && !d.consumeDNSResolved(p.newCfg) {
		newCfg = p.newCfg.CloneForDNSRefresh()
		config.PopulateDNSFromCache(newCfg)
	}
	out.newCfg = newCfg
	// #6948: arm the commit-time session-invalidation plan BEFORE the apply.
	// Only this caller holds the pre-commit active config — the store promoted
	// the new one upstream — and the invalidation's candidate set has to be READ
	// while the live rows still carry the OLD policy numbering it is derived
	// from. applyConfigLocked takes that capture at the publication boundary;
	// without the plan it falls back to the pre-#6948 post-apply scan, which
	// sweeps the sessions of whichever policy inherited a deleted policy's id.
	switch p.armKind {
	case promotedArmWithRename:
		d.armPolicyInvalidationPlanWithRename(p.oldActive, newCfg, p.renameApply)
	case promotedArmPlain:
		d.armPolicyInvalidationPlan(p.oldActive, newCfg)
	case promotedArmRollback:
		d.armPolicyInvalidationRollbackPlan(p.oldActive, newCfg)
	}

	var applyErr error
	if p.commitOnly {
		// #9841: the committing wrapper returns the response object
		// projecting this attempt's unconverged-MTU records. Every
		// other driver uses the bare apply: no response exists to
		// carry warnings.
		out.respCfg, applyErr = d.applyConfigLockedForCommit(p.applyCtx, newCfg)
	} else {
		applyErr = d.applyConfigLocked(p.applyCtx, newCfg)
	}
	// #12072 surfaces the unpublished capture before the drivers make
	// their fatal decision. The pre-consolidation commit path joined
	// the capture error first, then classified the joined result; keep
	// that ordering so a cancel/authority capture failure prevents
	// commit discharge, peer-push and stamp. Peer-sync deliberately
	// retains its old bare-apply classification while surfacing the
	// capture error in its returned result.
	bareApplyErr := applyErr
	applyErr = d.surfacingIncompleteCapture(newCfg, applyErr)
	out.applyErr = applyErr
	if p.kind == promotedApplyCommit {
		out.fatal = applyErrSkipsPeerSync(applyErr)
	} else {
		out.fatal = applyErrSkipsPeerSync(bareApplyErr)
	}

	switch p.kind {
	case promotedApplySync:
		// The peer-sync discharge is DEFERRED by the caller (it must
		// join retErr at return time, after the device-map alarm, and
		// stamp the captured digest from that same deferred block —
		// the #6296 placement). The helper therefore classifies and
		// detects the deferred-publication case here, and the caller
		// runs discharge + stamp via
		// dischargeAndStampSyncLocked. On a fatal apply nothing is
		// armed: no discharge, no stamp.
		if out.fatal {
			return out
		}
		if applyErr == nil && !d.policyInvalidationPublishLanded {
			completion := d.deferredSnapshotCompletionForConfig(newCfg)
			if completion == nil {
				out.applyErr = errors.New("deferred config snapshot has no publication completion")
				out.localErr = out.applyErr
				out.joined = out.applyErr
				out.deferredNoCompletion = true
				return out
			}
			out.deferredPending = true
			out.deferredCompletion = completion
			return out
		}
		// Non-fatal (including a non-fatal tail error): publication
		// landed, so the caller discharges. Signal via localErr being
		// just the apply error for now; the deferred discharge joins
		// its own error in the caller.
		out.localErr = applyErr
		out.joined = applyErr
		return out

	case promotedApplyRollback:
		// #9811: latch the outcome for the caller-less retry owner.
		// noteConfigApplyResult DISCHARGES on success, so an apply
		// that works needs no separate site.
		d.noteConfigApplyResult(applyErr)
		if applyErr != nil {
			slog.Error("commit confirmed auto-rollback dataplane apply failed", "err", applyErr)
		}
		// Discharge synchronously (no caller to join into), via the
		// ONE discharge call below. NOTE: unlike commit/sync, the
		// rollback discharges even when the apply was fatal — this
		// preserves the pre-consolidation behaviour exactly (the
		// rollback copy had no fatal classification and always
		// discharged when publication landed). Tightening this to
		// skip on fatal would change #5578/#9811 semantics and is
		// deliberately NOT done here; see the resync decision note
		// at executeConfirmedRollback.
		out.clearErr = d.dischargePromotedLocked(p, newCfg, out.fatal)
		out.dischargeRan = d.policyInvalidationPublishLanded
		if out.clearErr != nil && p.logDischargeErr {
			slog.Error("commit confirmed auto-rollback: policy session invalidation was PARTIAL; "+
				"some rolled-back-policy sessions may keep forwarding under stale authorization", "err", out.clearErr)
		}
		// No stamp here: the #12073 discharge stamps
		// MarkAppliedDigest(debt.appliedDigest) itself when it
		// settles the debt. Adding a stamp*UnderSem call would
		// double-stamp (and the discharge's PublishLanded/debt gates
		// differ from the stamp helpers' — see stampDigestIfConvergedUnderSem).
		out.localErr = errors.Join(applyErr, out.clearErr)
		out.joined = out.localErr
		return out

	default: // promotedApplyCommit
		if out.fatal {
			// Do NOT push — the peer stays on its prior snapshot. Skip
			// deletion-clear too (see the file doc). The driver wraps
			// the error in configstore.ErrCommittedNotApplied (#16828).
			return out
		}
		// #4234 Junos-default deletion-clear + modified-policy
		// re-eval + #4342 default-policy re-eval: the config is
		// committed + active and the dataplane armed, so any session
		// admitted by a now-deleted/tightened/default-changed policy
		// must stop forwarding immediately (and be dropped on the
		// standby too) rather than linger until idle timeout. Runs
		// under d.applySem (the caller holds it), after the dataplane
		// apply so the new policy set is already live.
		//
		// #5578: a PARTIAL invalidation is joined into the returned
		// error alongside the non-fatal apply error (mark-and-
		// continue: the config stays committed + active and still
		// syncs to the peer, but the operator sees the failure and
		// can re-commit).
		// #5858/#7212: the ONE commit-time entry point for
		// "authorization the operator just changed, versus sessions
		// already established".
		out.clearErr = d.dischargePromotedLocked(p, newCfg, out.fatal)
		out.dischargeRan = d.policyInvalidationPublishLanded
		// Committed + active locally with the dataplane armed. A
		// non-fatal best-effort subsystem error must NOT skip the
		// peer sync (#4034): the standby has to receive the committed
		// config or the nodes diverge.
		//
		// #5962: the policy is RESOLVED HERE (inside wantsPush), not
		// at the entry point, for the same reason the pre-consolidation
		// code resolved it here.
		if p.pushPeer && p.syncPeer.wantsPush(d.cluster) {
			out.peerPushErr = d.pushCommittedConfigToPeer(p.peerSnapshotAuth)
		}
		out.localErr = errors.Join(applyErr, out.clearErr)
		out.joined = errors.Join(out.localErr, out.peerPushErr)
		// #4957: a fully-successful local commit apply means the
		// committed active config has converged on the dataplane. A
		// peer push failure is independent: it must not erase the
		// local applied proof, though it remains in the return error.
		d.stampActiveAppliedIfConvergedUnderSem(out.localErr)
		return out
	}
}

// dischargeAndStampSyncLocked is the peer-sync driver's deferred
// half: it discharges the #12073 debt and stamps the captured digest,
// in that order, and returns the discharge error for the caller to
// join into its return. It runs inside the caller's deferred block
// (before applySem.Release) so the stamp keys the digest captured
// for THIS sync (#6296) and no competing promotion can inherit it.
//
// retErr is the caller's return error BEFORE the discharge error is
// joined; the stamp gates on the JOINED outcome (apply + discharge),
// matching stampActiveAppliedIfConvergedUnderSem's localErr gate on
// the commit driver.
// dischargePromotedLocked is the ONE call site of
// dischargePolicyInvalidationDebtLocked in the finalize pipeline:
// the #12073 discharge runs iff publication landed. fatal is the
// caller's classification — commit/peer-sync never reach here on a
// fatal apply (they return earlier); the rollback reaches here
// regardless (its preserved no-classification behaviour), so fatal
// does not gate the discharge; it is carried for the record.
func (d *Daemon) dischargePromotedLocked(p promotedApply, newCfg *config.Config, fatal bool) error {
	_ = fatal
	if !d.policyInvalidationPublishLanded {
		return nil
	}
	return d.dischargePolicyInvalidationDebtLocked(p.oldActive, newCfg)
}

func (d *Daemon) dischargeAndStampSyncLocked(oldActive, newCfg *config.Config, appliedDigest string, retErr error) error {
	clearErr := d.dischargePromotedLocked(promotedApply{oldActive: oldActive, kind: promotedApplySync}, newCfg, false)
	// #1956 V-1 passive-node device-map admission gate (OQ-15.1 option
	// (a): passive gate + loud health alarm). The active node's strict
	// commit can only validate ITS OWN hardware (R-8), so a synced
	// config whose LOCAL device-map section would strand THIS node's
	// management on next boot must be surfaced loudly here. We do NOT
	// strip/modify the synced delta (that creates the config-divergence
	// overwrite loop); the stores stay identical and the #1922
	// lifeline keeps mgmt reachable at runtime. The alarm is the
	// operator's signal that the peer-pushed map needs fixing before
	// a reboot. (Option (b), distributed pre-commit validation, is the
	// documented end-state follow-up.)
	d.deviceMapPassiveAdmissionAlarm(newCfg)
	d.stampDigestIfConvergedUnderSem(errors.Join(retErr, clearErr), appliedDigest)
	return clearErr
}

// Compile-time references: the outcome carries these types for the
// drivers' shaping; keep the imports anchored here.
var (
	_ = cluster.ConfigApplyPendingError{}
	_ = configstore.ErrCommittedNotApplied
)
