package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// deletedPolicyRuntimeIDs returns the set of numeric runtime policy IDs (the
// value stamped on an admitted session's policy_id, #3056) belonging to
// policies present in oldCfg but ABSENT from newCfg. Identity is the stable
// string key (userspace.StablePolicyRuleID: "<from>-><to>/<name>"), so a
// sibling policy's deletion never shifts a survivor's key.
//
// Only DELETED policies are reported. A policy whose match/action CHANGED but
// whose zones+name are unchanged keeps the same stable key, is present in both
// maps, and is therefore NOT reported here.
//
// That is a division of labour, NOT a gap. The changed-policy case is handled
// by changedPolicyRuntimeIDs / clearSessionsForModifiedPolicies in this file,
// gated on `security policies policy-rematch`, and
// clearSessionsForPolicyChanges runs both on every commit. An earlier revision
// of this comment called it "the deferred #4234 modified-policy
// (policy-rematch) half, intentionally out of scope" — which was true when it
// was written and stopped being true when that half shipped. It matters
// because this is the first comment a reader hits when tracing commit-time
// session invalidation: following it to a now-closed issue leads to the
// conclusion that a shipped, security-relevant behaviour (in-progress sessions
// re-evaluated against a tightened policy) is missing, and then to
// re-implementing it or telling an operator xpf does not do it.
//
// policy_id 0 is EXCLUDED from the returned set even when the literal first
// policy (PolicySetID 0, RuleIndex 0 — policyID() == 0) is deleted or renamed.
// The wire value 0 is OVERLOADED: it is both that first policy's id AND the
// "unspecified"/legacy zero-value carried by non-security sessions
// (host-inbound / neighbor-seed / fabric / tunnel installs stamp policy_id 0)
// and by any pre-#3056 or older-HA-peer session that only ever carried the wire
// scalar. userspace-dp already special-cases 0 for exactly this reason —
// policy.rs `DuplicatePolicyId` (M01) excludes 0 from its uniqueness check, and
// `reresolve_session_policy_id` treats the idx-0 non-policy sessions as
// unbound. Clearing every policy_id==0 session because the first policy was
// deleted/renamed (a rename is delete+add by stable key) would sweep all those
// host-local/fabric/tunnel/synced sessions — a forwarding blip on a common op,
// and during a rolling upgrade an old peer syncs its WHOLE table with
// policy_id 0, so a first-policy delete would wipe it (mass loss / TCP resets
// on failover, the #1960 rolling-upgrade class, amplified by the #2468
// delete-sync propagation). Excluding 0 here does NOT leave the first policy's
// sessions to idle out. An earlier revision of this comment said it did, and
// that was false for a one-way flow: the next-packet re-derivation declines a
// reverse packet (#8356 GATE 1) and, while a type-constrained ICMP permit
// exists, an ICMP one (GATE 1b), and reverse packets keep the forward half
// alive (companion_keeps_alive), so a reverse-sustained flow kept transiting
// under the deleted policy (#9526). The first policy's sessions are cleared by
// the HELPER instead, where a discriminator exists: a session that policy
// admitted binds the rule's counter handle, and none of the overloaded-zero
// sessions above binds one. On the forwarding-snapshot rotation that removes
// the old snapshot's policy_id-0 rule, each worker purges the forward sessions
// bound to it together with their reverse companions
// (purge_sessions_bound_to_deleted_first_policy, userspace-dp
// afxdp/session_glue). So excluding 0 from this set stays correct, and every
// OTHER deleted policy (id >= 1) still clears here.
//
// This set is only meaningful against rows that still carry the OLD numbering,
// which is why the invalidation READS the session table before the dataplane
// publishes the new snapshot and deletes from that capture afterwards (#6948,
// daemon_policy_invalidate_capture.go). Two writers move a live row's policy_id
// the moment the snapshot goes live: new admissions use the NEW ids, and the
// helper's #3395 live-row refresh (reresolve_session_policy_id, driven from
// refresh_bpf_conntrack_last_seen into the same pinned conntrack map Go
// enumerates) re-resolves every forward row from its bound rule handle against
// the CURRENT rule table. A deleted policy's rows become
// DEFAULT_POLICY_SENTINEL_ID (u32::MAX — its rule_id no longer resolves) and a
// surviving policy's rows become that policy's NEW id, which may be the id this
// set targets.
//
// An earlier revision of this comment said the clear "runs synchronously in the
// apply path (right after the dataplane ApplyConfig), before the next refresh
// tick". It did not: the sweep ran after the WHOLE of applyConfigLocked,
// including applyTailReconciles (DNS, sudoers, sshd, IPsec, VRRP, FRR), while
// the refresh runs a 2048-slot slice every 100ms with a 10s full-table target
// — so on a real box a large fraction of the table had already been re-stamped
// by the time the sweep read it. The claim mattered because it is the stated
// reason the numeric-id diff is sound, and it is recorded here rather than
// deleted so the next reader can see which premise moved.
//
// Returns nil when oldCfg is nil (boot / first commit — nothing to invalidate)
// or nothing was deleted.
func deletedPolicyRuntimeIDs(oldCfg, newCfg *config.Config) map[uint32]struct{} {
	if oldCfg == nil {
		return nil
	}
	oldIDs := dpuserspace.PolicyIDsByStableKey(oldCfg)
	if len(oldIDs) == 0 {
		return nil
	}
	newIDs := dpuserspace.PolicyIDsByStableKey(newCfg)
	var deleted map[uint32]struct{}
	for key, id := range oldIDs {
		if id == 0 {
			// Overloaded wire value — never sweep policy_id==0 sessions. See the
			// doc comment above (mirrors policy.rs DuplicatePolicyId M01).
			continue
		}
		if _, stillPresent := newIDs[key]; stillPresent {
			continue
		}
		if deleted == nil {
			deleted = make(map[uint32]struct{})
		}
		deleted[id] = struct{}{}
	}
	return deleted
}

// clearSessionsForDeletedPolicies invalidates, at commit time, every live
// session admitted by a policy that the just-committed config removed — the
// Junos-DEFAULT behavior that drops a deleted policy's sessions immediately
// rather than leaving them forwarding until idle timeout (#4234 deletion-clear
// half). It is deliberately bounded:
//
//   - It runs ONLY when at least one policy was deleted (deletedPolicyRuntimeIDs
//     returns a non-empty set); a commit with no policy deletion pays no
//     session-table scan.
//   - It clears ONLY sessions whose stored policy_id matches a deleted policy;
//     a MODIFIED policy (same zones+name) keeps its key and is never touched
//     HERE — clearSessionsForModifiedPolicies covers it under `policy-rematch`.
//     (This said "the deferred policy-rematch half"; it is not deferred, it
//     ships in this file.)
//
// The clear reuses the same companion-aware delete the GC and cluster-stale
// reconcile use (SessionStore.DeleteBatchKnownV4/V6 removes the forward entry,
// its reverse companion, and any dynamic DNAT/NAT64 companion), and propagates
// each deletion to the HA peer through the identical delete-sync channel the GC
// delete callback uses (#2468 QueueDeleteV4/V6) — so a session dropped on the
// owner is dropped on the standby too and cannot resurrect on failover.
//
// Handles both zone-pair and global (junos-global) policies uniformly: the
// stable key already encodes each policy's scope, so a deleted policy in either
// namespace contributes its numeric ID to the deleted set.
//
// Caller must hold d.applySem (all commit/sync/rollback call sites do), so this
// cannot race a concurrent apply that would reprogram the policy-ID namespace.
//
// Returns a non-nil error when the invalidation was PARTIAL (a session-table
// enumerate or batch-delete failed): some sessions of the deleted policy may
// keep forwarding under the now-revoked authorization, so the caller MUST join
// this into the commit/sync/rollback result rather than let it be lost to a log
// line (#5578).
func (d *Daemon) clearSessionsForDeletedPolicies(oldCfg, newCfg *config.Config) error {
	// #6948: when the apply took a pre-publication capture, delete exactly what
	// it observed. The capture read the session table while the rows still
	// carried the OLD numbering this id set was derived from, which neither a
	// post-activation admission nor the helper's #3395 live-row re-stamp can
	// contaminate. See daemon_policy_invalidate_capture.go.
	if c := d.policyInvalidationCapture; c != nil {
		return d.deleteInvalidatedSessions(c.deleted, dataplane.DeleteReasonPolicyDeleted, "deleted")
	}
	return d.clearSessionsForPolicyIDs(
		deletedPolicyRuntimeIDs(oldCfg, newCfg),
		dataplane.DeleteReasonPolicyDeleted,
		"deleted",
	)
}

// clearSessionsForModifiedPolicies invalidates, at commit time, every live
// session admitted by a policy that survives the commit (same zones+name) but
// whose MATCH or ACTION changed — the Junos `security policies policy-rematch`
// behavior of re-evaluating in-progress sessions against the changed policy set
// (#4234 modified-policy half). It is gated on `policy-rematch` being set in the
// committed config (changedPolicyRuntimeIDs returns nil otherwise) and, like the
// deletion-clear, is bounded to sessions whose stored policy_id matches a
// changed policy; an unchanged policy's sessions are never touched.
//
// A cleared session's next packet re-enters policy evaluation and is admitted or
// dropped by the NEW policy — so a tightened (permit→deny, narrowed-match)
// policy takes effect on live traffic instead of lingering until idle timeout.
//
// A surviving policy whose SCHEDULER binding effectively flipped active→inactive
// is treated as a verdict change too (#4343): policyRuleInactive (userspace-dp
// policies.go) is FAIL-CLOSED, so an inactive-scheduled policy is skipped in the
// rule chain — its live sessions must re-enter evaluation exactly like a
// permit→deny action change. The old/new per-scheduler active-state maps are
// evaluated at commit time from each config's schedulers via the same helper the
// apply transaction uses (policySchedulerActiveStateForApplyLocked); the caller
// holds d.applySem so d.scheduler cannot race.
//
// The `extensive` sub-case (Junos re-evaluates sessions of UNCHANGED policies
// when a referenced address-book / application object changes) is deliberately
// NOT implemented here — this clears only the policies whose own match/action
// text changed. `policy-rematch extensive` stays tracked as a follow-up
// (compiler_validate_warn.go advisory).
//
// Returns a non-nil error on a PARTIAL invalidation (enumerate/delete failure)
// so the caller can surface the stale-authorization gap; see
// clearSessionsForDeletedPolicies (#5578).
func (d *Daemon) clearSessionsForModifiedPolicies(oldCfg, newCfg *config.Config) error {
	// #6948: see clearSessionsForDeletedPolicies. The rematch half is exposed to
	// the same two contaminations — a surviving-but-changed policy's OLD id can
	// be inherited by a different policy, and the #3395 refresh re-stamps this
	// policy's own rows to its NEW id — so it consumes the same capture.
	if c := d.policyInvalidationCapture; c != nil {
		return d.deleteInvalidatedSessions(c.modified, dataplane.DeleteReasonPolicyModified, "modified (policy-rematch)")
	}
	now := time.Now()
	oldSched := d.policySchedulerActiveStateForApplyLocked(oldCfg, now)
	newSched := d.policySchedulerActiveStateForApplyLocked(newCfg, now)
	return d.clearSessionsForPolicyIDs(
		changedPolicyRuntimeIDs(oldCfg, newCfg, oldSched, newSched),
		dataplane.DeleteReasonPolicyModified,
		"modified (policy-rematch)",
	)
}

// defaultPolicyChanged reports whether the implicit default-policy changed in a
// way that must invalidate live default-PERMIT sessions, and whether the clear
// is UNCONDITIONAL (a verdict change) or gated on `policy-rematch` (a log-only
// flip). The implicit default-policy is the catch-all a flow hits when it
// matches no configured zone-pair / global / wildcard rule; a default-PERMIT
// verdict installs a session stamped DefaultPolicySentinelID (0xFFFFFFFF), which
// the named-policy invalidators never touch because they diff only
// PolicyIDsByStableKey (configured policies, never emitting the sentinel). So a
// `default-policy permit-all` -> `deny-all` (or reject) commit otherwise leaves
// the existing default-permit flows forwarding until idle timeout — the #4342
// stale-intent gap.
//
//   - An ACTION change (permit<->deny/reject) is a verdict change: clear
//     UNCONDITIONALLY, mirroring the always-on deletion-clear. A tightening
//     (permit->deny) must drop the now-should-be-denied sessions; the reverse
//     (deny->permit) installs nothing to sweep, so the clear is a harmless no-op
//     there (no session carries the sentinel under a default-deny).
//   - A LOG-only flip (action unchanged, session-init/session-close toggled) is
//     re-evaluation, not a verdict change: gate it on `policy-rematch` so a live
//     default-permit session re-installs under the new logging intent only when
//     the operator opted into rematch, matching the modified-policy half's
//     posture. Without policy-rematch the flip applies to new sessions only.
func defaultPolicyChanged(oldCfg, newCfg *config.Config) (changed, unconditional bool) {
	if oldCfg == nil || newCfg == nil {
		return false, false
	}
	if oldCfg.Security.DefaultPolicy != newCfg.Security.DefaultPolicy {
		return true, true
	}
	if oldCfg.Security.DefaultPolicyLogSessionInit != newCfg.Security.DefaultPolicyLogSessionInit ||
		oldCfg.Security.DefaultPolicyLogSessionClose != newCfg.Security.DefaultPolicyLogSessionClose {
		return true, false
	}
	return false, false
}

// clearSessionsForDefaultPolicyChange invalidates, at commit time, every live
// default-PERMIT session (policy_id == DefaultPolicySentinelID) when the
// implicit default-policy's verdict or logging intent changed (#4342). It reuses
// the shared clearSessionsForPolicyIDs core, so the drop is companion-aware and
// HA-delete-synced to the standby exactly like the named-policy clears.
//
// The overloaded-id-0 fail-safe that deletedPolicyRuntimeIDs / changedPolicy-
// RuntimeIDs apply does NOT apply here: the target id is the 0xFFFFFFFF sentinel,
// which by construction can never alias policy_id 0 (host-inbound / fabric /
// tunnel / synced sessions and old HA peers all carry 0, never 0xFFFFFFFF — see
// DefaultPolicySentinelID). Sweeping the sentinel is therefore safe and precise.
//
// Caller must hold d.applySem (all commit/sync/rollback call sites do).
//
// Returns a non-nil error on a PARTIAL invalidation (enumerate/delete failure)
// so the caller can surface the stale-authorization gap; see
// clearSessionsForDeletedPolicies (#5578).
func (d *Daemon) clearSessionsForDefaultPolicyChange(oldCfg, newCfg *config.Config) error {
	// #6948: see clearSessionsForDeletedPolicies. The sentinel is never
	// inherited, so this class cannot be over-cleared by renumbering — but it
	// shares the capture so that ALL THREE classes read the session table
	// exactly once, at one instant, on the same side of the publication
	// boundary. A per-class read would put them on different sides of it.
	if c := d.policyInvalidationCapture; c != nil {
		return d.deleteInvalidatedSessions(c.deflt, dataplane.DeleteReasonDefaultPolicyChanged, "default-policy changed")
	}
	return d.clearSessionsForPolicyIDs(
		defaultPolicyChangeRuntimeIDs(oldCfg, newCfg),
		dataplane.DeleteReasonDefaultPolicyChanged,
		"default-policy changed",
	)
}

// defaultPolicyChangeRuntimeIDs is the #4342 target set: the default-policy
// sentinel when the implicit default-policy changed in a way that must
// invalidate live default-PERMIT sessions, and nil otherwise. Factored out of
// clearSessionsForDefaultPolicyChange so the pre-publication capture
// (#6948) and the legacy post-apply path decide the GATE identically — a
// duplicated gate is a divergence waiting to happen, and this one is what makes
// a log-only flip without `policy-rematch` a no-op.
func defaultPolicyChangeRuntimeIDs(oldCfg, newCfg *config.Config) map[uint32]struct{} {
	changed, unconditional := defaultPolicyChanged(oldCfg, newCfg)
	if !changed {
		return nil
	}
	if !unconditional && (newCfg == nil || !newCfg.Security.PolicyRematch) {
		// Log-only flip without policy-rematch: leave live default-permit
		// sessions to log per their install-time intent (Junos re-evaluates
		// in-progress sessions only under policy-rematch).
		return nil
	}
	return map[uint32]struct{}{dataplane.DefaultPolicySentinelID: {}}
}

// reportSessionAuthorizationChanges is the ONE commit-time entry point for
// "authorization the operator just changed, versus sessions already
// established". It exists as a single named seam rather than a bare call at
// each of the three commit sites (commit, commit-confirmed, confirmed-rollback)
// because a fourth site would otherwise be easy to add with the invalidation
// left out.
//
// #7212: it used to have a SECOND half — the #5858 advisory, a commit-time
// warning that an attached or tightened interface INPUT filter did NOT revoke
// established sessions and that the operator had to run `clear security flow
// session interface <name>` themselves. That warning existed only because the
// revocation did not, and its central claim ("ESTABLISHED sessions are NOT
// revoked and keep forwarding under the previous filter until they idle out")
// is now FALSE: the dataplane revalidates each established session against the
// changed static filter on its next packet and revokes the ones the filter now
// denies (userspace-dp `evaluate_input_filter_on_session_hit`). A commit-time
// warning that misstates current behaviour, and names a remedy the operator no
// longer needs, is worse than none — an operator who learns one warning is
// stale discounts the ones that matter. The advisory, its `filterCanDeny` gate,
// and their tests were deleted with the revocation, in the same change.
//
// Note the asymmetry that remains and is correct: a POLICY change is revoked
// HERE, at commit, because the policy that admitted a session is stamped on it
// and the set of affected sessions is knowable from the config diff alone. A
// FILTER change is revoked in the dataplane, lazily, because which sessions a
// filter newly denies is a per-5-tuple question the control plane cannot answer
// without re-deriving every session's verdict — and answering it by interface
// instead, the obvious symmetry, is what #5858 rejected: it drops PERMITTED
// flows, and a purged permitted SNAT flow reinstalls on a different translated
// port.
//
// Returns the policy invalidation's error contract unchanged (#5578): non-nil
// means a PARTIAL clear, so some traffic may keep forwarding under stale
// authorization.
//
// Caller must hold d.applySem.
func (d *Daemon) reportSessionAuthorizationChanges(oldCfg, newCfg *config.Config) error {
	return d.clearSessionsForPolicyChanges(oldCfg, newCfg)
}

// clearSessionsForPolicyChanges runs the three commit-time session
// invalidations — the deletion-clear (#4234), the modified-policy re-eval
// (policy-rematch), and the default-policy change clear (#4342) — in order and
// JOINS their errors so a caller can surface a PARTIAL invalidation in one
// place (#5578). errors.Join evaluates all three arguments, so every clear is
// attempted even if an earlier one fails; a non-nil return means at least one
// clear could not fully drop its target sessions, so some traffic may keep
// forwarding under stale authorization after a tightening/deleting commit.
// Returns nil when every clear was a no-op or fully succeeded.
//
// Caller must hold d.applySem (all commit/sync/rollback call sites do).
func (d *Daemon) clearSessionsForPolicyChanges(oldCfg, newCfg *config.Config) error {
	// #6948: the pre-publication capture is CONSUMED here — read once for the
	// three clears below, then dropped, so a later apply that bails before the
	// capture point can never delete against a stale candidate set. The shared
	// enumerate error is reported once for all three classes (they share one
	// scan).
	// The three clears below read d.policyInvalidationCapture themselves — the
	// same object this local names — so the reset must not run until they have.
	capture := d.policyInvalidationCapture
	defer func() { d.policyInvalidationCapture = nil }()
	var captureErr error
	if capture != nil {
		captureErr = capture.enumerateErr()
	}
	return errors.Join(
		captureErr,
		d.clearSessionsForDeletedPolicies(oldCfg, newCfg),
		d.clearSessionsForModifiedPolicies(oldCfg, newCfg),
		d.clearSessionsForDefaultPolicyChange(oldCfg, newCfg),
	)
}

// clearSessionsForPolicyIDs is the shared core behind the deletion-clear
// (#4234) and the modified-policy re-eval: it drops every live session whose
// stored policy_id is in ids, using the same companion-aware delete + HA
// delete-sync propagation the GC and cluster-stale reconcile use. ids is the
// set of OLD numeric policy IDs the target sessions carry; an empty set is a
// no-op (a commit with no matching policy change pays no session-table scan).
// reason is the documentary delete label; what labels the change class in the
// summary log line.
//
// Caller must hold d.applySem (all commit/sync/rollback call sites do), so this
// cannot race a concurrent apply that would reprogram the policy-ID namespace.
//
// Error contract (#5578): the return value AGGREGATES every enumerate and
// batch-delete failure (errors.Join). A non-nil return means the invalidation
// was PARTIAL — a failed ForEachV4/V6 iteration leaves UNVISITED sessions in the
// live table, and a failed DeleteBatchKnownV4/V6 leaves MATCHED sessions
// INSTALLED — so traffic the new policy should now DENY may keep forwarding
// under the old session's stale authorization. The slog.Error/Warn lines are
// kept for operator diagnostics, but the error is ALSO returned so the caller
// can join it into the commit/sync/rollback result instead of the security gap
// being silently swallowed. Both families are always attempted before the error
// is returned (a partial clear is strictly better than none). Returns nil when
// there was nothing to do (no ids / no dataplane / no matching sessions) or the
// clear fully succeeded.
func (d *Daemon) clearSessionsForPolicyIDs(ids map[uint32]struct{}, reason dataplane.DeleteReason, what string) error {
	rt := d.dataplane()
	if rt == nil || len(ids) == 0 {
		return nil
	}

	store := rt.Sessions()
	if store == nil {
		return nil
	}
	// Collect forward entries only; DeleteBatchKnownV4/V6 expands each to its
	// reverse + DNAT companions. A reverse entry carries the SAME policy_id as
	// its forward, so including it would double-delete the same session and, for
	// a NAT'd flow, target the translated tuple instead of the install key.
	//
	// Capture the enumerate error: a failed iteration yields a partial (or empty)
	// entry set, so clearing what we gathered would silently leave should-be-
	// cleared sessions forwarding while logging an apparently-clean invalidation.
	// Surface it loudly and suppress the success line so the partial clear is
	// observable, not masked (Copilot #4320).
	// #6948: the id set was computed from the OLD config's numbering, and
	// runtime policy ids are POSITIONAL — deleting a policy renumbers every
	// later one. The dataplane starts admitting under the NEW numbering as soon
	// as the apply publishes it, which happens long before this sweep runs, so a
	// session admitted in between by a policy that INHERITED a deleted policy's
	// id matches `ids` and would be dropped while correctly permitted.
	//
	// admittedAfterActivation is the discriminator. It is STRICTLY greater on
	// purpose: Created has one-second granularity, so a session created in the
	// same integer second as the stamp is ambiguous, and an ambiguous session is
	// still cleared — the direction this code already chose (over-clear is
	// fail-safe for security; under-clear is a stale-authorization gap).
	//
	// That leaves a residual: this narrows the over-clear from the entire
	// post-activation apply, tail included, to at most one second. It does not
	// eliminate it, and nothing here should be read as claiming otherwise —
	// closing it fully needs either an admission fence across
	// activation->invalidation or a stable admitting-rule identity on the row.
	activationSecs := d.policyActivationSecs
	admittedAfterActivation := func(created uint64) bool {
		return activationSecs != 0 && created > activationSecs
	}

	var v4Entries []dataplane.SessionEntryV4
	v4EnumErr := store.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if admittedAfterActivation(val.Created) {
			return true
		}
		if _, hit := ids[val.PolicyID]; hit {
			v4Entries = append(v4Entries, dataplane.SessionEntryV4{Key: key, Value: val})
		}
		return true
	})

	var v6Entries []dataplane.SessionEntryV6
	v6EnumErr := store.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		// #6948: same boundary as v4. Both families must apply it or the defect
		// simply moves to the other address family.
		if admittedAfterActivation(val.Created) {
			return true
		}
		if _, hit := ids[val.PolicyID]; hit {
			v6Entries = append(v6Entries, dataplane.SessionEntryV6{Key: key, Value: val})
		}
		return true
	})
	// errs accumulates every enumerate/delete failure so the caller can join it
	// into the commit/sync/rollback result (#5578) — the failure is no longer
	// lost to a log line while the commit reports success with stale authorized
	// sessions still forwarding.
	var errs []error
	enumFailed := v4EnumErr != nil || v6EnumErr != nil
	if enumFailed {
		slog.Error("policy session invalidation: session-table enumerate failed; clear is PARTIAL — some sessions of changed policies may keep forwarding",
			"change", what, "reason", reason, "policies", len(ids),
			"v4_err", v4EnumErr, "v6_err", v6EnumErr,
			"v4_matched", len(v4Entries), "v6_matched", len(v6Entries))
		if v4EnumErr != nil {
			errs = append(errs, fmt.Errorf("policy session invalidation (%s): v4 enumerate: %w", what, v4EnumErr))
		}
		if v6EnumErr != nil {
			errs = append(errs, fmt.Errorf("policy session invalidation (%s): v6 enumerate: %w", what, v6EnumErr))
		}
		// Fall through to clear what we DID enumerate — a partial clear is
		// strictly better than none — but the error log above ensures the
		// partial state is visible and the success line below is skipped.
	}

	errs = append(errs, d.deleteInvalidatedSessions(capturedSessions{
		targets:    len(ids),
		v4:         v4Entries,
		v6:         v6Entries,
		enumFailed: enumFailed,
	}, reason, what))
	return errors.Join(errs...)
}

// deleteInvalidatedSessions issues the deletes for ONE change class's candidate
// set and is the single place the commit-time invalidation actually removes a
// session. Both producers feed it: the #6948 pre-publication capture
// (daemon_policy_invalidate_capture.go) and the legacy post-apply enumeration
// above. Keeping one delete site is what makes the two producers
// indistinguishable to the HA peer, the delete reason, and the operator log —
// the choice of producer changes WHICH sessions are deleted, never HOW.
//
// The delete reuses the companion-aware DeleteBatchKnownV4/V6 (forward entry +
// reverse companion + any dynamic DNAT/NAT64 companion) and propagates each
// deletion to the HA peer through the same #2468 delete-sync channel the GC
// delete callback uses, so a session dropped on the owner is dropped on the
// standby too and cannot resurrect on failover.
//
// Returns a non-nil error when a batch delete failed — MATCHED sessions stay
// INSTALLED, which is the #5578 stale-authorization gap the caller must surface
// rather than swallow. c.enumFailed suppresses the success line only: an
// incomplete candidate set must not be reported as a complete clear.
//
// Caller must hold d.applySem.
func (d *Daemon) deleteInvalidatedSessions(c capturedSessions, reason dataplane.DeleteReason, what string) error {
	if c.empty() {
		return nil
	}
	rt := d.dataplane()
	if rt == nil {
		return nil
	}
	store := rt.Sessions()
	if store == nil {
		return nil
	}
	// Whether to propagate the local deletes to the HA peer. Mirrors the GC
	// delete callback (daemon_run.go): only a node that is primary for some RG
	// owns the authoritative session and syncs its deletes; the peer ignores
	// deletes for sessions it does not hold.
	ss := d.getSessionSync()
	syncPeer := d.cluster != nil && d.cluster.IsLocalPrimaryAny() && ss != nil

	var errs []error
	v4Cleared := 0
	if len(c.v4) > 0 {
		if n, err := store.DeleteBatchKnownV4(c.v4, reason); err != nil {
			slog.Warn("policy session invalidation: v4 clear failed",
				"reason", reason, "policies", c.targets, "matched", len(c.v4), "err", err)
			errs = append(errs, fmt.Errorf("policy session invalidation (%s): v4 delete: %w", what, err))
		} else {
			v4Cleared = n
		}
		if syncPeer {
			for _, e := range c.v4 {
				ss.QueueDeleteV4(e.Key)
			}
		}
	}

	v6Cleared := 0
	if len(c.v6) > 0 {
		if n, err := store.DeleteBatchKnownV6(c.v6, reason); err != nil {
			slog.Warn("policy session invalidation: v6 clear failed",
				"reason", reason, "policies", c.targets, "matched", len(c.v6), "err", err)
			errs = append(errs, fmt.Errorf("policy session invalidation (%s): v6 delete: %w", what, err))
		} else {
			v6Cleared = n
		}
		if syncPeer {
			for _, e := range c.v6 {
				ss.QueueDeleteV6(e.Key)
			}
		}
	}

	// One-time state transition, not a per-session/per-tick event — slog.Info is
	// the right level (project logging rules). Suppress the success line when the
	// enumerate failed: the counts describe only what we managed to gather, so an
	// Info "cleared" line would misreport a partial clear as complete (the Error
	// line already recorded it).
	if !c.enumFailed && len(errs) == 0 {
		slog.Info("cleared sessions of changed policies at commit",
			"change", what,
			"policies", c.targets,
			"v4_cleared", v4Cleared,
			"v6_cleared", v6Cleared,
			"ha_sync", syncPeer)
	}
	return errors.Join(errs...)
}

// changedPolicyRuntimeIDs returns the OLD numeric runtime IDs of policies that
// survive the commit (present in BOTH oldCfg and newCfg by stable key) but whose
// MATCH or ACTION changed — the set the modified-policy re-evaluation clears.
//
// It is GATED on `security policies policy-rematch` in the committed (new)
// config: Junos re-evaluates in-progress sessions against a modified policy only
// when policy-rematch is set. Without it, a modified policy's sessions keep
// forwarding until idle timeout (the historical xpf behavior), which the commit
// advisory documents.
//
// Only MODIFIED survivors are reported: a DELETED policy (absent from newCfg) is
// the deletion-clear's job (deletedPolicyRuntimeIDs) and is skipped here; an
// UNCHANGED policy keeps forwarding. The OLD numeric ID is used because live
// sessions were stamped under the old config and carry it (identical rationale
// to deletedPolicyRuntimeIDs). policy_id 0 is excluded for the same overloaded-
// wire-value reason documented there (host-inbound / fabric / tunnel / synced
// sessions and old HA peers all carry 0). Unlike a deletion, a MODIFIED first
// policy is not covered by the helper's #9526 purge, which keys on the rule
// vanishing from the snapshot: its sessions are left to the next-packet
// re-derivation, which declines reverse packets, so a one-way reverse-sustained
// flow keeps its old verdict (#9604).
//
// oldSched / newSched are the per-scheduler active-state maps under the old and
// new configs, evaluated at the same commit-time instant (nil when a config has
// no schedulers). They drive the #4343 scheduler active->inactive verdict-change
// detection (policySchedulerBecameInactive); pass nil/nil to consider only
// match/action changes.
//
// Returns nil when oldCfg is nil (boot), policy-rematch is unset, or nothing
// changed.
func changedPolicyRuntimeIDs(oldCfg, newCfg *config.Config, oldSched, newSched map[string]bool) map[uint32]struct{} {
	if oldCfg == nil || newCfg == nil || !newCfg.Security.PolicyRematch {
		return nil
	}
	oldIDs := dpuserspace.PolicyIDsByStableKey(oldCfg)
	if len(oldIDs) == 0 {
		return nil
	}
	newIDs := dpuserspace.PolicyIDsByStableKey(newCfg)
	oldPolicies := dpuserspace.PoliciesByStableKey(oldCfg)
	newPolicies := dpuserspace.PoliciesByStableKey(newCfg)

	// #8993: `policy-rematch extensive` also re-evaluates sessions of an
	// UNCHANGED policy when a referenced object's DEFINITION changes. Computed
	// ONCE for the whole diff rather than per policy -- each call builds the
	// address-book table and the full policy snapshot set, so doing it inside
	// the loop would be quadratic in policy count on every commit.
	//
	// Both maps are nil unless `extensive` is configured, so the plain
	// `policy-rematch` path does no extra work at all.
	var oldResolved, newResolved map[string]string
	if newCfg.Security.PolicyRematchExtensive {
		oldResolved = dpuserspace.PolicyResolvedFingerprints(oldCfg)
		newResolved = dpuserspace.PolicyResolvedFingerprints(newCfg)
	}

	var changed map[uint32]struct{}
	for key, id := range oldIDs {
		if id == 0 {
			// Overloaded wire value — never sweep policy_id==0 sessions.
			continue
		}
		if _, stillPresent := newIDs[key]; !stillPresent {
			// Deleted — handled by the deletion-clear, not here.
			continue
		}
		oldPol := oldPolicies[key]
		newPol := newPolicies[key]
		if oldPol == nil || newPol == nil {
			continue
		}
		if !policyMatchOrActionChanged(oldPol, newPol) &&
			!policySchedulerBecameInactive(oldPol, newPol, oldSched, newSched) &&
			!policyReferencedObjectChanged(newCfg, key, oldResolved, newResolved) {
			continue
		}
		if changed == nil {
			changed = make(map[uint32]struct{})
		}
		changed[id] = struct{}{}
	}
	return changed
}

// policySchedulerBecameInactive reports whether a surviving policy's EFFECTIVE
// enforcement state flipped from active to inactive across the commit — the
// scheduler-binding analogue of an action tightening (#4343). policyRuleInactive
// (userspace-dp policies.go, exported as PolicyInactive) is FAIL-CLOSED: a policy
// bound to an inactive-or-undefined scheduler is stamped Inactive and its rule is
// SKIPPED in the chain, so an active->inactive flip is a verdict change for a
// live session — its next packet no longer matches this policy and re-enters
// evaluation (falling through to a later rule or the default-policy). This covers
// both a scheduler-name BINDING change (unscheduled->scheduled-and-inactive, or
// active-scheduler->inactive-scheduler) and a same-binding scheduler whose active
// WINDOW the commit redefined out from under the current instant.
//
// The inactive->active direction is intentionally NOT a clear trigger: while the
// policy was inactive it admitted no sessions, so none carry its policy_id — a
// sweep would be a pure no-op. Only the tightening direction (active->inactive)
// has live sessions to re-evaluate.
func policySchedulerBecameInactive(oldPol, newPol *config.Policy, oldSched, newSched map[string]bool) bool {
	wasActive := !dpuserspace.PolicyInactive(oldPol.SchedulerName, oldSched)
	nowInactive := dpuserspace.PolicyInactive(newPol.SchedulerName, newSched)
	return wasActive && nowInactive
}

// policyMatchOrActionChanged reports whether two same-identity policies differ
// in a way that changes the verdict for an in-progress session: the terminal
// ACTION (permit/deny/reject) or any MATCH predicate (source/destination
// addresses, applications, the address-excluded senses, or a global policy's
// from/to zone scope). Address and application lists are compared as SETS so a
// pure reordering — which does not change what the policy matches — does not
// trigger a needless session clear. Non-verdict attributes (description, count,
// log) are intentionally ignored: they do not affect whether a live session
// should still be permitted. scheduler-name is NOT ignored — it gates
// fail-closed enforcement (policyRuleInactive), so a scheduler active->inactive
// transition is handled separately by policySchedulerBecameInactive (#4343),
// which needs the runtime scheduler active-state and so cannot be decided from
// the two Policy structs alone.
// policyReferencedObjectChanged reports whether the RESOLVED form of a policy
// changed while its own match/action text did not -- the `extensive` case
// (#8993). It is the third arm of the modified-policy test and fires only when
// `policy-rematch extensive` is configured, because only then are the
// fingerprint maps built.
//
// FAIL-QUIET, DELIBERATELY. A nil map means the fingerprint could not be
// computed (an address book that does not build, a config the commit path
// rejects anyway). Reporting "changed" there would clear every session on a
// config that is about to be refused; reporting "unchanged" falls back to the
// name-level comparison, which is exactly today's behaviour. A missing KEY is
// likewise not a change: a policy absent from one side is an add or a delete,
// and both are handled by their own paths.
func policyReferencedObjectChanged(newCfg *config.Config, key string, oldResolved, newResolved map[string]string) bool {
	if newCfg == nil || !newCfg.Security.PolicyRematchExtensive {
		return false
	}
	if oldResolved == nil || newResolved == nil {
		return false
	}
	oldFP, okOld := oldResolved[key]
	newFP, okNew := newResolved[key]
	if !okOld || !okNew {
		return false
	}
	return oldFP != newFP
}

func policyMatchOrActionChanged(oldPol, newPol *config.Policy) bool {
	if oldPol.Action != newPol.Action {
		return true
	}
	om, nm := oldPol.Match, newPol.Match
	if om.SourceAddressExcluded != nm.SourceAddressExcluded ||
		om.DestinationAddressExcluded != nm.DestinationAddressExcluded {
		return true
	}
	// #4626 M03: a global policy's from/to-zone scope is a zone SET; compare as
	// sets (like the address/application lists) so a pure reordering of the
	// scope does not trigger a needless session clear.
	return !sameStringSet(om.FromZones, nm.FromZones) ||
		!sameStringSet(om.ToZones, nm.ToZones) ||
		!sameStringSet(om.SourceAddresses, nm.SourceAddresses) ||
		!sameStringSet(om.DestinationAddresses, nm.DestinationAddresses) ||
		!sameStringSet(om.Applications, nm.Applications)
}

// sameStringSet reports whether two string slices contain the same elements
// irrespective of order or duplicates.
func sameStringSet(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	sa := make(map[string]struct{}, len(a))
	for _, v := range a {
		sa[v] = struct{}{}
	}
	sb := make(map[string]struct{}, len(b))
	for _, v := range b {
		sb[v] = struct{}{}
	}
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if _, ok := sb[k]; !ok {
			return false
		}
	}
	return true
}
