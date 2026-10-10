package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6948 — commit-time session invalidation reads the session table BEFORE the
// dataplane publishes the new policy set, then deletes the captured rows after
// publication. The prepublish boundary still matters: it excludes sessions
// admitted under the new snapshot while allowing a cleared flow to re-evaluate
// against that snapshot.
//
// Runtime policy IDs are POSITIONAL (policySetID*MaxRulesPerPolicy + ruleIndex,
// pkg/dataplane/userspace/policies.go). The target IDs come from oldCfg, but a
// session's stored policy_id is frozen at admission and may reflect an ordering
// older than oldCfg after an earlier insert or removal. The helper's prepublish
// READ therefore resolves each bound policy_counter's stable rule_id against
// the currently applied snapshot before applying the requested-ID predicate.
// The helper's read-authority fence below requires that snapshot to be oldCfg,
// so Go receives the same positional ID namespace used to compute the target set.
//
// This read-time resolution is separate from #3395's BPF conntrack-row refresh:
// that refresh updates the mirror, not SessionTable metadata. In helper-backed
// prepublish mode, unbound sync-derived rows and SharedPromote rows are excluded
// because their scalar may be stale; locally authored unbound rows retain the
// scalar policy-ID path.
//
// PROPERTY: bound rows in helper-backed prepublish reads are matched after
// stable rule_id resolution against the verified oldCfg snapshot; orphaned
// bound handles resolve to the default-policy sentinel. Unbound sync-derived
// and SharedPromote rows cannot match by stale scalar, while locally authored
// unbound rows still can. The non-helper BPF fallback uses scalar IDs and does
// not provide this stable-handle property. Captured row identity is then used
// for the post-publish delete.
//
// RESIDUAL: a session admitted by a to-be-deleted policy between the capture
// and publish is not in the capture and keeps forwarding until idle timeout.
// Capturing at the last statement before ApplyConfig holds this stale-
// authorization window to the apply call itself.

// pendingRenameApply binds config ancestry to the exact promoted active
// generation, which is the transaction key. Ownership transferred from the
// store at bind time in commitWithGenBinding; the daemon copy is the sole
// owner afterward, retained for peer retry/reconnect and pruned by the next
// commit's bind.
type pendingRenameApply struct {
	descriptors []configstore.RenameDescriptor
}

// policyInvalidationPlan is the (old, new) config pair a commit-class apply
// will diff for the commit-time session invalidation. The apply's CALLER arms
// it before calling applyConfigLocked, because only the caller holds the
// pre-commit active config — by the time the apply runs, the store has already
// promoted the new one. capturePolicyInvalidationLocked consumes it at the
// publication boundary.
type policyInvalidationPlan struct {
	oldCfg      *config.Config
	newCfg      *config.Config
	renameApply *pendingRenameApply
}

// policyInvalidationScanFailure remembers the old authority under which a scan
// was incomplete. A later complete scan can retire it only if that same
// authority is still active; the target need not match when its earlier
// publication failed.
type policyInvalidationScanFailure struct {
	oldCfg *config.Config
}

// policyInvalidationDebt owns the candidate identities until the corresponding
// authorization changes succeed. A refusal to enumerate under a mismatched or
// unknown authority is tracked separately from an incomplete enumeration.
type policyInvalidationDebt struct {
	oldCfg            *config.Config
	newCfg            *config.Config
	// predecessorCfg is retained across authority re-anchors to recognize
	// when a rollback exactly restores the target's predecessor.
	predecessorCfg    *config.Config
	renameApply       *pendingRenameApply
	capture           *policyInvalidationCapture
	scanFailure       *policyInvalidationScanFailure
	authorityRefusal  error
	publishGeneration uint64
	// appliedDigest is captured only after this target's full local apply
	// succeeds and is stamped after the debt's candidates clear.
	appliedDigest string
	// landed is the predecessor obligation whose target had already landed
	// when this unlanded target's capture merged it forward. A superseded
	// target's retire restores it instead of dropping the whole debt.
	landed *policyInvalidationDebt
}

// capturedSessions is one change class's pre-publication candidate set: the
// forward session entries that carried a target policy id when the capture ran.
// targets is the number of policy ids the class was looking for, kept for the
// summary log line (the post-capture code no longer has the id set).
type capturedSessions struct {
	targets int
	v4      []dataplane.SessionEntryV4
	v6      []dataplane.SessionEntryV6
	// policy retains the helper READ rows, including their incarnation and
	// companion identities, for the userspace identity-conditional delete.
	policy []dpuserspace.SessionPolicyMatch
	// enumFailed marks a candidate set gathered from an INCOMPLETE scan. It
	// suppresses the delete site's success line only — the counts describe what
	// was gathered, not what existed, so reporting them as a complete clear
	// would mask the partial state the enumerate error already recorded.
	enumFailed bool
}

func (c capturedSessions) empty() bool {
	return len(c.v4) == 0 && len(c.v6) == 0 && len(c.policy) == 0
}

func (c *policyInvalidationCapture) candidateCount() int {
	if c == nil {
		return 0
	}
	return len(c.deleted.v4) + len(c.deleted.v6) + len(c.deleted.policy) +
		len(c.modified.v4) + len(c.modified.v6) + len(c.modified.policy) +
		len(c.deflt.v4) + len(c.deflt.v6) + len(c.deflt.policy)
}

// policyInvalidationCapture is the whole pre-publication snapshot: one bucket
// per change class, plus the enumerate errors.
//
// A capture without an authority refusal is authoritative — the three clears
// delete exactly what it holds and never re-enumerate. An EMPTY non-nil capture
// therefore means "the capture ran and there was nothing to invalidate", which is
// a different state from nil ("no capture was taken; fall back to the legacy
// post-apply enumeration"). An authority refusal is instead a publication-blocking
// state; treating it as an empty capture could delete against the wrong namespace.
type policyInvalidationCapture struct {
	deleted  capturedSessions
	modified capturedSessions
	deflt    capturedSessions
	// renamed rows are retained and re-bound by the next Rust snapshot; they
	// must never enter any delete bucket.
	renamed        []dpuserspace.PolicySessionRebind
	renameAncestry []dpuserspace.PolicyRenameAncestry

	// readErr is the userspace helper READ failure (P9); v4Err/v6Err belong
	// to the store path only.
	readErr error
	v4Err   error
	v6Err   error
	// authorityErr means no enumeration was attempted because the helper
	// authority was stale/unknown. It must not be treated as a scan failure.
	authorityErr error
	// scanComplete is true only after a complete read/iteration at the
	// authority named by the capture plan.
	scanComplete bool
	// errorSurfaced prevents a settled callback from logging/returning the same
	// enumeration failure again after the originating apply reported it.
	errorSurfaced bool
}

// armPolicyInvalidationPlan records the config pair the next applyConfigLocked
// should capture for. Caller holds d.applySem.
func (d *Daemon) armPolicyInvalidationPlan(oldCfg, newCfg *config.Config) {
	d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, nil)
}

func policyInvalidationAppliedConfig(rt any) *config.Config {
	if rt == nil {
		return nil
	}
	unwrapped := dataplane.Unwrap(rt)
	if unwrapped == nil {
		return nil
	}
	if provider, ok := unwrapped.(interface{ Manager() *dpuserspace.Manager }); ok {
		if manager := provider.Manager(); manager != nil {
			// The legacy adapter exposes Manager() but not Manager's optional
			// policy-read authority directly.
			return manager.PolicyReadConfig()
		}
	}
	if provider, ok := unwrapped.(interface {
		PolicyReadConfig() *config.Config
	}); ok {
		// The manager accessor returns nil when an apply outcome is unknown,
		// even if its last acknowledged snapshot still names an older config.
		return provider.PolicyReadConfig()
	}
	if provider, ok := unwrapped.(interface {
		AppliedConfig() *config.Config
	}); ok {
		return provider.AppliedConfig()
	}
	return nil
}
func (d *Daemon) armPolicyInvalidationPlanWithRename(
	oldCfg, newCfg *config.Config,
	renameApply *pendingRenameApply,
) {
	// A landed target becomes the namespace for the next fresh scan. Keep
	// identity-specific delete obligations from the prior capture, but do not
	// keep interpreting every future diff in its pre-publish namespace. The
	// authority fence, not a publication generation stamp, proves this re-anchor.
	if debt := d.policyInvalidationDebt; debt != nil {
		immediatePair := debt.newCfg == oldCfg
		if immediatePair && policyInvalidationAppliedConfig(d.dataplane()) == oldCfg {
			debt.oldCfg = oldCfg
		} else if !immediatePair {
			// Rename ancestry composes only across the immediate pair.
			renameApply = nil
		}
		oldCfg = debt.oldCfg
	}
	d.policyInvalidationPlan = &policyInvalidationPlan{
		oldCfg:      oldCfg,
		newCfg:      newCfg,
		renameApply: renameApply,
	}
}

// capturePolicyInvalidationLocked takes the pre-publication candidate snapshot.
// It MUST be called from the apply path at the last statement before the
// dataplane publishes the new policy snapshot (rt.ApplyConfig), and it consumes
// the armed plan so a later apply cannot re-capture against a stale config
// pair.
//
// It is a no-op when no plan is armed (boot, and every non-commit apply): the
// capture stays nil and the clears fall back to the legacy post-apply
// enumeration, which is what those paths did before #6948.
//
// cfg is the config THIS apply is publishing, and the plan is used only if it
// describes that config. An apply that bails before this point leaves its plan
// armed — a context abort, a preflight rejection — and the next apply to reach
// here may be a different one entirely (a feed-driven re-apply, #5646). A
// candidate set is a list of live 5-tuples, so capturing one against a config
// pair that is not this apply's is the same class of error as reading the table
// after the publish: it names sessions by a diff that does not describe what is
// happening. Identity, not equality: the arm site passes the very
// *config.Config the apply is called with.
//
// Caller holds d.applySem.
func (d *Daemon) capturePolicyInvalidationLocked(cfg *config.Config) {
	plan := d.policyInvalidationPlan
	d.policyInvalidationPlan = nil
	d.policyInvalidationCapture = nil
	d.policyInvalidationDebtAdopted = false
	originalDebt := d.policyInvalidationDebt
	if plan == nil {
		// A bare retry (the #9811 owner, feed refresh, or another background
		// apply) has no caller to arm a fresh plan. Adopt the retained obligation
		// only for its exact target config; when the helper confirms that target
		// already landed, the capture below re-anchors to that known namespace.
		if debt := d.policyInvalidationDebt; debt != nil && debt.newCfg == cfg {
			oldCfg := debt.oldCfg
			if policyInvalidationAppliedConfig(d.dataplane()) == debt.newCfg {
				// A bare retry after catch-up uses the already-landed
				// snapshot as its authority and reuses the retained identities.
				oldCfg = debt.newCfg
				debt.oldCfg = oldCfg
			}
			plan = &policyInvalidationPlan{
				oldCfg: oldCfg, newCfg: debt.newCfg, renameApply: debt.renameApply,
			}
			d.policyInvalidationDebtAdopted = true
		} else {
			return
		}
	}
	if plan.newCfg != cfg {
		// A plan left behind by an apply that never reached its own capture.
		// Take no capture against a different config; an existing debt remains
		// intact and can be adopted by its matching retry.
		slog.Warn("policy session invalidation: dropping a stale pre-publication plan; " +
			"it was armed for a different config than this apply is publishing")
		return
	}
	applied := policyInvalidationAppliedConfig(d.dataplane())
	if debt := d.policyInvalidationDebt; debt != nil && applied != nil && debt.newCfg != applied {
		var active *config.Config
		if d.store != nil {
			active = d.store.ActiveConfig()
		}
		// Retire only when helper and store agree on another authority. A store
		// move alone may be a target not yet applied by the helper.
		if active != debt.newCfg && active == applied {
			activeHost := ""
			if active != nil {
				activeHost = active.System.HostName
			}
			restored := debt.landed
			if restored != nil && restored.newCfg != applied {
				restored = nil
			}
			restoredCandidateCount := 0
			if restored != nil {
				restoredCandidateCount = restored.capture.candidateCount()
			}
			slog.Warn("policy session invalidation: retiring superseded target debt",
				"applied_host", applied.System.HostName, "store_active_host", activeHost,
				"restored", restored != nil,
				"scan_failure", restored != nil && restored.scanFailure != nil,
				"candidate_count", restoredCandidateCount)
			d.policyInvalidationDebt = restored
			originalDebt = restored
		}
	}
	if applied != nil && applied != plan.oldCfg && applied != plan.newCfg {
		// Positional policy IDs must be derived from the helper's known
		// predecessor, not a stale store snapshot.
		plan.oldCfg = applied
		if debt := d.policyInvalidationDebt; debt != nil && debt.newCfg == applied {
			debt.oldCfg = applied
		}
	} else if applied != nil && applied == plan.newCfg && plan.oldCfg != applied {
		// The helper has already published this target. Reuse retained
		// candidates under that known authority. Without matching debt there
		// is no proof the target's pre-publication capture was discharged, so
		// keep the refusal fail-closed.
		if debt := d.policyInvalidationDebt; debt != nil && debt.newCfg == applied {
			plan.oldCfg = applied
			debt.oldCfg = applied
			d.policyInvalidationDebtAdopted = true
		} else {
			refusal := fmt.Errorf(
				"%w: helper already holds the invalidation target without retained candidate debt",
				dpuserspace.ErrPolicyReadAuthority)
			d.refusePolicyInvalidationAuthorityLocked(
				plan, originalDebt, &policyInvalidationCapture{}, refusal)
			return
		}
	}
	previousGeneration := uint64(0)
	var previousCapture *policyInvalidationCapture
	var previousScanFailure *policyInvalidationScanFailure
	var landed *policyInvalidationDebt
	if debt := d.policyInvalidationDebt; debt != nil {
		undoesLandedTarget := applied != nil && debt.newCfg == applied &&
			plan.newCfg != applied && debt.predecessorCfg != nil &&
			debt.predecessorCfg == plan.newCfg
		if applied != nil && debt.newCfg == applied && plan.newCfg != applied {
			// An exact rollback restores the landed target's predecessor, so
			// its candidates are no longer owed. Restore only any earlier
			// landed debt; preserve scanFailure below to remain fail-closed
			// until a complete capture or authoritative full clear.
			if undoesLandedTarget {
				landed = debt.landed
			} else {
				// A landed debt's own predecessor was already merged into it
				// and can never be restored again; cut the chain so it stays
				// bounded.
				debt.landed = nil
				landed = debt
			}
		} else if debt.newCfg != applied {
			// An unlanded predecessor passes on the landed obligation it was
			// itself carrying (nested superseding target, same-target retry).
			landed = debt.landed
		}
		previousCapture = debt.capture
		previousScanFailure = debt.scanFailure
		if undoesLandedTarget {
			// The current capture may contain both this target's candidates
			// and its predecessor's. Only the latter remain owed after undo.
			previousCapture = nil
			if landed != nil {
				previousCapture = landed.capture
			}
		}
		if debt.newCfg == plan.newCfg {
			previousGeneration = debt.publishGeneration
		}
	}
	predecessorCfg := plan.oldCfg
	if debt := d.policyInvalidationDebt; debt != nil && debt.newCfg == plan.newCfg {
		predecessorCfg = debt.predecessorCfg
	}
	d.policyInvalidationDebt = &policyInvalidationDebt{
		oldCfg: plan.oldCfg, newCfg: plan.newCfg, predecessorCfg: predecessorCfg,
		renameApply: plan.renameApply, scanFailure: previousScanFailure,
		publishGeneration: previousGeneration, landed: landed,
	}

	// The three target sets are computed HERE, once, and the clears consume the
	// buckets rather than recomputing. changedPolicyRuntimeIDs' scheduler
	// active-state (#4343) is evaluated at a single instant for both configs,
	// exactly as clearSessionsForModifiedPolicies does.
	now := time.Now()
	oldSched := d.policySchedulerActiveStateForApplyLocked(plan.oldCfg, now)
	newSched := d.policySchedulerActiveStateForApplyLocked(plan.newCfg, now)
	deleted := deletedPolicyRuntimeIDs(plan.oldCfg, plan.newCfg)
	modified := changedPolicyRuntimeIDs(plan.oldCfg, plan.newCfg, oldSched, newSched)
	feedOverlay := d.feedSnapshotsForConfig(plan.newCfg)
	deflt := defaultPolicyChangeRuntimeIDs(plan.oldCfg, plan.newCfg)

	capture := &policyInvalidationCapture{}
	var renameBindings map[uint32]policyRenameBinding
	if plan.renameApply != nil && plan.newCfg != nil && plan.newCfg.Security.PolicyRematchExtensive {
		var valid bool
		renameBindings, capture.renameAncestry, valid = expandPolicyRenameAncestry(
			plan.oldCfg, plan.newCfg, plan.renameApply.descriptors)
		if !valid {
			renameBindings = nil
			capture.renameAncestry = nil
		}
		for oldID, binding := range renameBindings {
			binding.policyInactiveFn = dpuserspace.PolicyInactiveFn(newSched)
			binding.feedOverlay = feedOverlay
			renameBindings[oldID] = binding
		}
	}
	capture.deleted.targets = len(deleted)
	capture.modified.targets = len(modified)
	capture.deflt.targets = len(deflt)

	if len(deleted)+len(modified)+len(deflt) == 0 && len(renameBindings) == 0 {
		// Nothing to invalidate on this commit — record the empty capture so the
		// clears know one was taken and skip the session-table scan entirely.
		d.retainPolicyInvalidationCaptureLocked(mergePolicyInvalidationCaptures(previousCapture, capture))
		return
	}

	rt := d.dataplane()
	if rt == nil {
		d.retainPolicyInvalidationCaptureLocked(previousCapture)
		return
	}
	store := rt.Sessions()
	// #10512: userspace policy invalidation reads the helper authority, not
	// the BPF mirror. A missing/incomplete READ is a partial invalidation and
	// must never be converted into an authoritative empty capture.
	if lister, ok := rt.(interface {
		ListSessionsByPolicy(dpuserspace.SessionPolicyListRequest) (dpuserspace.ControlResponse, error)
	}); ok {
		// The target IDs belong to plan.oldCfg's positional namespace. Keep
		// every read under that known authority, and block publication if the
		// authority is unknown or changed after the daemon-side check.
		appliedCfg := policyInvalidationAppliedConfig(rt)
		if appliedCfg != plan.oldCfg {
			refusal := fmt.Errorf(
				"%w: policy session READ authority is unknown or changed during capture",
				dpuserspace.ErrPolicyReadAuthority)
			d.refusePolicyInvalidationAuthorityLocked(plan, originalDebt, capture, refusal)
			return
		}

		ids := captureRequestedPolicyIDs(deleted, modified, deflt, renameBindings)
		resp, err := lister.ListSessionsByPolicy(dpuserspace.SessionPolicyListRequest{
			PolicyIDs:      ids,
			Mode:           "prepublish",
			Families:       []uint8{4, 6},
			Classes:        []string{"forward"},
			ExpectedConfig: plan.oldCfg,
		})
		if errors.Is(err, dpuserspace.ErrPolicyReadAuthority) {
			d.refusePolicyInvalidationAuthorityLocked(plan, originalDebt, capture, err)
			return
		}
		// P7 terminal (shared with the legacy producer): a transport
		// error gathers nothing → empty buckets + error. An INCOMPLETE
		// read still matches what was gathered (delete-partial:
		// revoking some stale sessions beats revoking none) while the
		// joined readErr surfaces the gap once via the aggregate.
		// HA-sync covers the partial (per attempted match), so the peer
		// observes the same revocation.
		if err != nil {
			capture.readErr = fmt.Errorf("policy session READ: %w", err)
			capture.deleted.enumFailed = true
			capture.modified.enumFailed = true
			capture.deflt.enumFailed = true
			d.retainPolicyInvalidationCaptureLocked(mergePolicyInvalidationCaptures(previousCapture, capture))
			return
		}
		if !resp.SessionPolicyComplete {
			capture.readErr = fmt.Errorf(
				"policy session READ incomplete: %s",
				strings.Join(resp.SessionPolicyPerWorkerErrors, ", "),
			)
		}
		for _, match := range resp.SessionPolicyMatches {
			// P6: the helper must not over-return into unchanged
			// policies — an extraneous match would over-clear. Skip +
			// loud (the scan is suspect, so the end check below marks
			// the whole capture partial).
			// #10626: rename first-check, before P6 — the helper twin of the
			// legacy rename-before-classify below. A renamed session the new
			// policy still permits is retained (rebound); a denied one joins
			// `deleted.policy` with its entries, exactly once.
			if binding, ok := renameBindings[match.PolicyID]; ok {
				if record, permitted := rematchRenamedMatch(plan.oldCfg, plan.newCfg, binding, match); permitted {
					capture.renamed = append(capture.renamed, record)
				} else {
					// Convert-then-append (mirrors the normal path below): a
					// malformed denied match must not enter the batch, where
					// Rust fails the WHOLE delete batch closed and zero
					// deletes apply.
					entry4, entry6, err := policyMatchEntries(match)
					if err != nil {
						capture.readErr = errors.Join(capture.readErr, err)
						continue
					}
					capture.deleted.policy = append(capture.deleted.policy, match)
					if entry4 != nil {
						capture.deleted.v4 = append(capture.deleted.v4, *entry4)
					}
					if entry6 != nil {
						capture.deleted.v6 = append(capture.deleted.v6, *entry6)
					}
				}
				continue
			}
			if !idInSet(deleted, match.PolicyID) && !idInSet(modified, match.PolicyID) && !idInSet(deflt, match.PolicyID) {
				capture.readErr = errors.Join(capture.readErr, fmt.Errorf("policy session READ: extraneous policy %d", match.PolicyID))
				continue
			}
			entry4, entry6, err := policyMatchEntries(match)
			if err != nil {
				capture.readErr = errors.Join(capture.readErr, err)
				continue
			}
			target := &capture.deleted
			if idInSet(modified, match.PolicyID) {
				target = &capture.modified
			} else if idInSet(deflt, match.PolicyID) {
				target = &capture.deflt
			}
			target.policy = append(target.policy, match)
			if entry4 != nil {
				target.v4 = append(target.v4, *entry4)
			}
			if entry6 != nil {
				target.v6 = append(target.v6, *entry6)
			}
		}
		if capture.readErr != nil {
			capture.deleted.enumFailed = true
			capture.modified.enumFailed = true
			capture.deflt.enumFailed = true
		} else {
			capture.scanComplete = true
		}
		d.retainPolicyInvalidationCaptureLocked(mergePolicyInvalidationCaptures(previousCapture, capture))
		return
	}
	if store == nil {
		d.retainPolicyInvalidationCaptureLocked(previousCapture)
		return
	}

	// ONE pass per address family for all three classes. The classes are
	// disjoint by construction — changedPolicyRuntimeIDs skips ids that
	capture.v4Err = store.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if binding, ok := renameBindings[val.PolicyID]; ok {
			if record, permitted := rematchRenamedV4(plan.oldCfg, plan.newCfg, binding, key, val); permitted {
				capture.renamed = append(capture.renamed, record)
			} else {
				capture.deleted.v4 = append(capture.deleted.v4, dataplane.SessionEntryV4{
					Key: key, Value: val, PurgeTunnelVariants: !capturedTunnelDiscriminatorValid(key.Protocol, val.TunnelDiscriminator),
				})
			}
			return true
		}
		switch {
		case idInSet(deleted, val.PolicyID):
			capture.deleted.v4 = append(capture.deleted.v4, dataplane.SessionEntryV4{
				Key: key, Value: val, PurgeTunnelVariants: !capturedTunnelDiscriminatorValid(key.Protocol, val.TunnelDiscriminator),
			})
		case idInSet(modified, val.PolicyID):
			capture.modified.v4 = append(capture.modified.v4, dataplane.SessionEntryV4{
				Key: key, Value: val, PurgeTunnelVariants: !capturedTunnelDiscriminatorValid(key.Protocol, val.TunnelDiscriminator),
			})
		case idInSet(deflt, val.PolicyID):
			capture.deflt.v4 = append(capture.deflt.v4, dataplane.SessionEntryV4{
				Key: key, Value: val, PurgeTunnelVariants: !capturedTunnelDiscriminatorValid(key.Protocol, val.TunnelDiscriminator),
			})
		}
		return true
	})
	capture.v6Err = store.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if binding, ok := renameBindings[val.PolicyID]; ok {
			if record, permitted := rematchRenamedV6(plan.oldCfg, plan.newCfg, binding, key, val); permitted {
				capture.renamed = append(capture.renamed, record)
			} else {
				capture.deleted.v6 = append(capture.deleted.v6, dataplane.SessionEntryV6{
					Key: key, Value: val, PurgeTunnelVariants: !capturedTunnelDiscriminatorValid(key.Protocol, val.TunnelDiscriminator),
				})
			}
			return true
		}
		switch {
		case idInSet(deleted, val.PolicyID):
			capture.deleted.v6 = append(capture.deleted.v6, dataplane.SessionEntryV6{
				Key: key, Value: val, PurgeTunnelVariants: !capturedTunnelDiscriminatorValid(key.Protocol, val.TunnelDiscriminator),
			})
		case idInSet(modified, val.PolicyID):
			capture.modified.v6 = append(capture.modified.v6, dataplane.SessionEntryV6{
				Key: key, Value: val, PurgeTunnelVariants: !capturedTunnelDiscriminatorValid(key.Protocol, val.TunnelDiscriminator),
			})
		case idInSet(deflt, val.PolicyID):
			capture.deflt.v6 = append(capture.deflt.v6, dataplane.SessionEntryV6{
				Key: key, Value: val, PurgeTunnelVariants: !capturedTunnelDiscriminatorValid(key.Protocol, val.TunnelDiscriminator),
			})
		}
		return true
	})

	if capture.v4Err != nil || capture.v6Err != nil {
		capture.deleted.enumFailed = true
		capture.modified.enumFailed = true
		capture.deflt.enumFailed = true
	}
	if capture.v4Err == nil && capture.v6Err == nil {
		capture.scanComplete = true
	}

	d.retainPolicyInvalidationCaptureLocked(mergePolicyInvalidationCaptures(previousCapture, capture))
}

func policyInvalidationCaptureError(capture *policyInvalidationCapture) error {
	if capture == nil {
		return nil
	}
	switch {
	case capture.readErr != nil && capture.v4Err == nil && capture.v6Err == nil:
		return capture.readErr
	case capture.readErr == nil && capture.v4Err != nil && capture.v6Err == nil:
		return capture.v4Err
	case capture.readErr == nil && capture.v4Err == nil && capture.v6Err != nil:
		return capture.v6Err
	default:
		return errors.Join(capture.readErr, capture.v4Err, capture.v6Err)
	}
}

func (d *Daemon) refusePolicyInvalidationAuthorityLocked(
	plan *policyInvalidationPlan,
	previousDebt *policyInvalidationDebt,
	capture *policyInvalidationCapture,
	err error,
) {
	capture.authorityErr = err
	d.policyInvalidationPlan = plan
	d.policyInvalidationCapture = capture
	d.policyInvalidationDebtAdopted = false
	if previousDebt != nil {
		previousDebt.authorityRefusal = err
		d.policyInvalidationDebt = previousDebt
		return
	}
	d.policyInvalidationDebt = &policyInvalidationDebt{
		oldCfg: plan.oldCfg, newCfg: plan.newCfg, predecessorCfg: plan.oldCfg,
		renameApply: plan.renameApply, authorityRefusal: err,
	}
}

func (d *Daemon) retainPolicyInvalidationCaptureLocked(capture *policyInvalidationCapture) {
	if debt := d.policyInvalidationDebt; debt != nil {
		if capture == nil && debt.scanFailure != nil {
			capture = &policyInvalidationCapture{}
		}
		if capture != nil {
			currentErr := policyInvalidationCaptureError(capture)
			if failure := debt.scanFailure; failure != nil &&
				capture.scanComplete && currentErr == nil &&
				failure.oldCfg == debt.oldCfg {
				// A complete scan at the same old authority proves the
				// candidate set even if it supersedes a target that never
				// published. A landed target advances debt.oldCfg, so it
				// cannot retire a failure from the prior namespace.
				debt.scanFailure = nil
			}
			if debt.scanFailure == nil && currentErr != nil {
				debt.scanFailure = &policyInvalidationScanFailure{oldCfg: debt.oldCfg}
			}
			if capture.scanComplete {
				debt.authorityRefusal = nil
			}
			// Keep the failure marker separate from this capture's own errors:
			// only the capture that observed an incomplete scan returns it to
			// the originating commit. Later retries do not repeat that error.
			debt.capture = capture
		}
	}
	d.policyInvalidationCapture = capture
}

func (d *Daemon) notePolicyInvalidationPublish(cfg *config.Config, generation uint64) {
	// Generation zero is the callback's "not stamped" sentinel; never let an
	// unknown result erase a previously useful same-target generation.
	if generation == 0 {
		return
	}
	if debt := d.policyInvalidationDebt; debt != nil && debt.newCfg == cfg {
		debt.publishGeneration = generation
	}
}

type policyInvalidationMatchIdentity struct {
	family             uint8
	routingDomain      uint32
	tuple              dpuserspace.SessionPolicyTuple
	sessionID          uint64
	companionSessionID uint64
}

func policyInvalidationMatchID(match dpuserspace.SessionPolicyMatch) policyInvalidationMatchIdentity {
	family := match.AddrFamily
	if family == 0 {
		family = match.Tuple.AddrFamily
	}
	return policyInvalidationMatchIdentity{
		family:             family,
		routingDomain:      match.RoutingDomain,
		tuple:              match.Tuple,
		sessionID:          match.ExpectedRTFlowSessionID,
		companionSessionID: match.ExpectedCompanionRTFlowSessionID,
	}
}

// mergePolicyInvalidationCaptures carries forward prior delete candidates that
// the fresh scan did not rediscover. The row keys are stable even when
// publication has restamped the row's policy id; scan failures are tracked
// separately with the config pair whose enumeration they invalidate.
func mergePolicyInvalidationCaptures(previous, current *policyInvalidationCapture) *policyInvalidationCapture {
	if previous == nil {
		return current
	}
	if current == nil {
		return previous
	}
	if previous.deleted.empty() && previous.modified.empty() && previous.deflt.empty() {
		return current
	}

	v4Capacity := len(previous.deleted.v4) + len(previous.modified.v4) + len(previous.deflt.v4) +
		len(current.deleted.v4) + len(current.modified.v4) + len(current.deflt.v4)
	v6Capacity := len(previous.deleted.v6) + len(previous.modified.v6) + len(previous.deflt.v6) +
		len(current.deleted.v6) + len(current.modified.v6) + len(current.deflt.v6)
	policyCapacity := len(previous.deleted.policy) + len(previous.modified.policy) + len(previous.deflt.policy) +
		len(current.deleted.policy) + len(current.modified.policy) + len(current.deflt.policy)
	seenV4 := make(map[dataplane.SessionKey]struct{}, v4Capacity)
	seenV6 := make(map[dataplane.SessionKeyV6]struct{}, v6Capacity)
	seenPolicy := make(map[policyInvalidationMatchIdentity]struct{}, policyCapacity)

	mark := func(bucket capturedSessions) {
		for _, entry := range bucket.v4 {
			seenV4[entry.Key] = struct{}{}
		}
		for _, entry := range bucket.v6 {
			seenV6[entry.Key] = struct{}{}
		}
		for _, match := range bucket.policy {
			seenPolicy[policyInvalidationMatchID(match)] = struct{}{}
		}
	}
	mark(current.deleted)
	mark(current.modified)
	mark(current.deflt)

	merge := func(previous, current capturedSessions) capturedSessions {
		for _, entry := range previous.v4 {
			if _, ok := seenV4[entry.Key]; !ok {
				seenV4[entry.Key] = struct{}{}
				current.v4 = append(current.v4, entry)
			}
		}
		for _, entry := range previous.v6 {
			if _, ok := seenV6[entry.Key]; !ok {
				seenV6[entry.Key] = struct{}{}
				current.v6 = append(current.v6, entry)
			}
		}
		for _, match := range previous.policy {
			key := policyInvalidationMatchID(match)
			if _, ok := seenPolicy[key]; !ok {
				seenPolicy[key] = struct{}{}
				current.policy = append(current.policy, match)
			}
		}
		return current
	}
	current.deleted = merge(previous.deleted, current.deleted)
	current.modified = merge(previous.modified, current.modified)
	current.deflt = merge(previous.deflt, current.deflt)
	return current
}

// capturePolicyInvalidationBeforeDeferredPublish runs outside Manager.mu from
// the userspace status loop. It refreshes the retained candidate set at the
// actual deferred-publish boundary, after sessions admitted while XSK startup
// was pending have joined the old snapshot's table.
// An unknown or mismatched authority is returned to the Manager's prepare hook
// so it holds the deferred publication and can retry after status catch-up.
func (d *Daemon) capturePolicyInvalidationBeforeDeferredPublish(generation uint64) error {
	if d == nil || d.applySem == nil {
		return nil
	}
	if err := d.applySem.Acquire(d.applyCancelCtx(), 1); err != nil {
		return err
	}
	defer d.applySem.Release(1)

	debt := d.policyInvalidationDebt
	if debt == nil || debt.publishGeneration == 0 || generation < debt.publishGeneration {
		return nil
	}
	if d.store != nil {
		active := d.store.ActiveConfig()
		if active != nil && active != debt.newCfg {
			return nil
		}
	}
	appliedDigest := debt.appliedDigest
	d.policyInvalidationPlan = &policyInvalidationPlan{
		oldCfg: debt.oldCfg, newCfg: debt.newCfg, renameApply: debt.renameApply,
	}
	d.capturePolicyInvalidationLocked(debt.newCfg)
	if capture := d.policyInvalidationCapture; capture != nil && capture.authorityErr != nil {
		return fmt.Errorf("policy session invalidation authority refusal: %w", capture.authorityErr)
	}
	if current := d.policyInvalidationDebt; current != nil && current.newCfg == debt.newCfg {
		// This is the same successful apply, now at its actual publication
		// boundary. Preserve its eligibility for the applied marker across the
		// refreshed candidate capture.
		current.appliedDigest = appliedDigest
	}
	d.policyInvalidationDebtAdopted = false

	// The retained full snapshot already contains the first attempt's rename
	// metadata. Refresh it with the candidates captured at this actual publish
	// boundary so sessions admitted during the deferral window can be rebound
	// or deleted under the same one-shot decision.
	if rt := d.dataplane(); rt != nil {
		if adapter, ok := rt.(interface{ Manager() *dpuserspace.Manager }); ok {
			if mgr := adapter.Manager(); mgr != nil {
				capture := d.policyInvalidationCapture
				if capture != nil {
					mgr.SetDeferredPolicyRenameMetadata(
						generation, capture.renameAncestry, capture.renamed)
				}
			}
		}
	}
	return nil
}

// policyInvalidationSnapshotPublished is called when a full policy snapshot
// reaches a successful completion boundary (acknowledged publish or
// content-equivalent status settle). It must not clear inline: Manager invokes
// its committer with Manager.mu held, while the clear's helper READ acquires
// that same mutex. The worker waits for applySem and therefore runs after any
// synchronous commit-site discharge has completed.
func (d *Daemon) policyInvalidationSnapshotPublished(generation uint64) {
	if d == nil || d.applySem == nil {
		return
	}
	if d.applySem.TryAcquire(1) {
		owed := d.policyInvalidationDebt != nil
		d.applySem.Release(1)
		if !owed {
			return
		}
	}
	if !d.policyInvalidationDischargeWorker.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.policyInvalidationDischargeWorker.Store(false)
		d.dischargePolicyInvalidationAfterPublish(generation)
	}()
}

func (d *Daemon) dischargePolicyInvalidationAfterPublish(generation uint64) {
	if d == nil || d.applySem == nil {
		return
	}
	if err := d.applySem.Acquire(d.applyCancelCtx(), 1); err != nil {
		return
	}
	defer d.applySem.Release(1)

	debt := d.policyInvalidationDebt
	if debt == nil {
		return
	}
	if debt.publishGeneration == 0 {
		// A status-loop catch-up may publish a snapshot whose original ACK
		// was lost. Stamp that successful completion only when the manager
		// now confirms this exact config under a known authority.
		if generation == 0 || policyInvalidationAppliedConfig(d.dataplane()) != debt.newCfg {
			return
		}
		debt.publishGeneration = generation
	}
	if generation < debt.publishGeneration {
		return
	}
	if d.store != nil {
		active := d.store.ActiveConfig()
		if active != nil && active != debt.newCfg {
			return
		}
		if active == debt.newCfg && debt.appliedDigest == "" {
			// The catch-up callback is a successful apply boundary even
			// when the original caller lost its response.
			debt.appliedDigest = d.store.ActiveDigest()
		}
	}
	if err := d.dischargePolicyInvalidationDebtLocked(debt.oldCfg, debt.newCfg); err != nil {
		slog.Error("deferred policy session invalidation was PARTIAL; some sessions may keep forwarding under stale authorization",
			"err", err, "generation", generation)
		return
	}
}

// dischargePolicyInvalidationDebtLocked consumes the captured debt only after
// every requested authorization change succeeds. The fallback pair preserves
// legacy behavior for test seams and dataplanes without a pre-publication
// capture.
func (d *Daemon) dischargePolicyInvalidationDebtLocked(oldCfg, newCfg *config.Config) error {
	if debt := d.policyInvalidationDebt; debt != nil {
		if debt.capture != nil {
			d.policyInvalidationCapture = debt.capture
		}
		err := d.reportSessionAuthorizationChanges(debt.oldCfg, debt.newCfg)
		if err != nil {
			return err
		}
		if debt.scanFailure != nil {
			// A successful delete retry is not proof that an earlier partial
			// enumeration found every row. Keep the debt quiet until a later
			// complete capture supersedes that gap.
			return nil
		}
		d.policyInvalidationDebt = nil
		if d.store != nil {
			d.store.MarkAppliedDigest(debt.appliedDigest)
		}
		if plan := d.policyInvalidationPlan; plan != nil && plan.newCfg == debt.newCfg {
			// The target's captured work is settled; a stale authority-refusal
			// plan must not block later background applies of that target.
			d.policyInvalidationPlan = nil
		}
		return nil
	}
	return d.reportSessionAuthorizationChanges(oldCfg, newCfg)
}

// captureAndStagePolicyRenameAncestry is the ONE production handoff from the
// pre-publication capture to the dataplane's rename staging: take the capture
// (which consumes the armed plan), then hand any rename ancestry + rebind
// records to the dataplane before it publishes the new snapshot. The
// dataplane without the staging interface (or a capture without rename rows)
// receives empty slices, which is a no-op by construction.
//
// The dataplane-apply path calls this at the last statement before it
// publishes the new policy snapshot (see the #6948 placement comment at the
// call site); the HA joint test's apply seam calls this same helper rather
// than re-implementing the transfer, so the staging logic has exactly one
// implementation and the test reds if it is removed. Caller holds d.applySem.
func (d *Daemon) captureAndStagePolicyRenameAncestry(cfg *config.Config) error {
	d.capturePolicyInvalidationLocked(cfg)
	if captured := d.policyInvalidationCapture; captured != nil && captured.authorityErr != nil {
		slog.Error("policy session invalidation authority or candidate proof is unavailable; holding snapshot publication",
			"err", captured.authorityErr)
		return fmt.Errorf("policy session invalidation authority refusal: %w", captured.authorityErr)
	}
	rt := d.dataplane()
	if rt == nil {
		return nil
	}
	var ancestry []dpuserspace.PolicyRenameAncestry
	var rebinds []dpuserspace.PolicySessionRebind
	if captured := d.policyInvalidationCapture; captured != nil {
		ancestry = captured.renameAncestry
		rebinds = captured.renamed
	}
	if setter, ok := rt.(interface {
		SetPolicyRenameAncestry([]dpuserspace.PolicyRenameAncestry, []dpuserspace.PolicySessionRebind)
	}); ok {
		setter.SetPolicyRenameAncestry(ancestry, rebinds)
	}
	return nil
}

// #10626: the policy-ID set the helper READ is asked for: the three changed
// classes plus the rename bindings' keys, deduplicated. The bindings union is
// defensive inclusion (over-requesting is harmless: unmatched IDs return no
// rows); what keeps a renamed match from tripping the P6 extraneous-match
// guard is the rename first-check `continue` below, not this union — binding
// keys are old numerics of vanished stable keys and are normally already in
// `deleted`. Identical output when no rename bindings exist (pure refactor).
func captureRequestedPolicyIDs(deleted, modified, deflt map[uint32]struct{}, renameBindings map[uint32]policyRenameBinding) []uint32 {
	ids := make([]uint32, 0, len(deleted)+len(modified)+len(deflt)+len(renameBindings))
	seen := make(map[uint32]struct{}, len(deleted)+len(modified)+len(deflt)+len(renameBindings))
	for id := range deleted {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	for id := range modified {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	for id := range deflt {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	for id := range renameBindings {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

func idInSet(ids map[uint32]struct{}, id uint32) bool {
	if len(ids) == 0 {
		return false
	}
	_, ok := ids[id]
	return ok
}

// policyMatchEntries converts one helper READ match into the existing
// dataplane entry shape consumed by the companion-aware delete path. The
// helper is authoritative for the routing domain and RT_FLOW identity; the
// mirror value is only a transport container for that identity.
func policyMatchEntries(match dpuserspace.SessionPolicyMatch) (*dataplane.SessionEntryV4, *dataplane.SessionEntryV6, error) {
	family := match.AddrFamily
	if family == 0 {
		family = match.Tuple.AddrFamily
	}
	if match.ExpectedRTFlowSessionID == 0 {
		return nil, nil, fmt.Errorf(
			"policy session READ: identity-missing for policy %d (%s -> %s)",
			match.PolicyID, match.Tuple.SrcIP, match.Tuple.DstIP,
		)
	}
	if match.ExpectedCompanionRTFlowSessionID != 0 && match.ReverseKey == nil {
		return nil, nil, fmt.Errorf(
			"policy session READ: companion identity without reverse key for policy %d",
			match.PolicyID,
		)
	}
	switch family {
	case 4:
		key, discriminator, err := policyTupleV4(match.Tuple)
		if err != nil {
			return nil, nil, err
		}
		val := dataplane.SessionValue{
			PolicyID:            match.PolicyID,
			Created:             match.CreatedSecs,
			RoutingDomain:       match.RoutingDomain,
			RTFlowSessionID:     match.ExpectedRTFlowSessionID,
			TunnelDiscriminator: discriminator,
		}
		if val.RoutingDomain == 0 {
			val.RoutingDomain = match.Tuple.RoutingDomain
		}
		if match.ReverseKey != nil {
			reverse, _, err := policyTupleV4(*match.ReverseKey)
			if err != nil {
				return nil, nil, err
			}
			val.ReverseKey = reverse
		}
		return &dataplane.SessionEntryV4{Key: key, Value: val}, nil, nil
	case 6:
		key, discriminator, err := policyTupleV6(match.Tuple)
		if err != nil {
			return nil, nil, err
		}
		val := dataplane.SessionValueV6{
			PolicyID:            match.PolicyID,
			Created:             match.CreatedSecs,
			RoutingDomain:       match.RoutingDomain,
			RTFlowSessionID:     match.ExpectedRTFlowSessionID,
			TunnelDiscriminator: discriminator,
		}
		if val.RoutingDomain == 0 {
			val.RoutingDomain = match.Tuple.RoutingDomain
		}
		if match.ReverseKey != nil {
			reverse, _, err := policyTupleV6(*match.ReverseKey)
			if err != nil {
				return nil, nil, err
			}
			val.ReverseKey = reverse
		}
		return nil, &dataplane.SessionEntryV6{Key: key, Value: val}, nil
	default:
		return nil, nil, fmt.Errorf("policy session READ: unsupported address family %d", family)
	}
}

func policyTupleV4(tuple dpuserspace.SessionPolicyTuple) (dataplane.SessionKey, uint64, error) {
	src := net.ParseIP(tuple.SrcIP).To4()
	dst := net.ParseIP(tuple.DstIP).To4()
	if src == nil || dst == nil {
		return dataplane.SessionKey{}, 0, fmt.Errorf("policy session READ: invalid IPv4 tuple %q -> %q", tuple.SrcIP, tuple.DstIP)
	}
	var key dataplane.SessionKey
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = tuple.SrcPort
	key.DstPort = tuple.DstPort
	key.Protocol = tuple.Protocol
	return key, tuple.TunnelDiscriminator, nil
}

func policyTupleV6(tuple dpuserspace.SessionPolicyTuple) (dataplane.SessionKeyV6, uint64, error) {
	src := net.ParseIP(tuple.SrcIP).To16()
	dst := net.ParseIP(tuple.DstIP).To16()
	if src == nil || dst == nil || net.ParseIP(tuple.SrcIP).To4() != nil || net.ParseIP(tuple.DstIP).To4() != nil {
		return dataplane.SessionKeyV6{}, 0, fmt.Errorf("policy session READ: invalid IPv6 tuple %q -> %q", tuple.SrcIP, tuple.DstIP)
	}
	var key dataplane.SessionKeyV6
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = tuple.SrcPort
	key.DstPort = tuple.DstPort
	key.Protocol = tuple.Protocol
	return key, tuple.TunnelDiscriminator, nil
}

// enumerateErr reports the capture's enumerate failure ONCE for all three
// classes (the scan is shared, so reporting it per class would triple-count one
// failure). A failed scan leaves UNVISITED sessions out of every bucket, so
// the invalidation that follows is PARTIAL in exactly the #5578 sense —
// traffic the new policy should now DENY may keep forwarding under the old
// session's stale authorization. The error reaches the originating commit and
// raises one ERROR-level alarm. The userspace READ contributes at most ONE entry
// (readErr); v4/v6 legs belong to the store path only (P9).
// The retained scan-failure marker keeps ActiveApplied false while the
// unresolved identities remain. A complete scan at the same old authority can
// retire an unpublished failure; after publication, a successful full session
// clear retires it only while that target is still the known applied config.
// errorSurfaced keeps later status ticks quiet.
func (c *policyInvalidationCapture) enumerateErr() error {
	if c.errorSurfaced || (c.readErr == nil && c.v4Err == nil && c.v6Err == nil) {
		return nil
	}
	c.errorSurfaced = true
	slog.Error("policy session invalidation: pre-publication scan incomplete; retry under the original authority if publication did not land; after publication, a successful full `clear security flow session` at the known target removes unidentified rows and retires the scan debt",
		"read_err", c.readErr, "v4_err", c.v4Err, "v6_err", c.v6Err,
		"deleted_matched", len(c.deleted.v4)+len(c.deleted.v6),
		"modified_matched", len(c.modified.v4)+len(c.modified.v6),
		"default_matched", len(c.deflt.v4)+len(c.deflt.v6))
	var errs []error
	if c.readErr != nil {
		errs = append(errs, fmt.Errorf("policy session invalidation: %w", c.readErr))
	}
	if c.v4Err != nil {
		errs = append(errs, fmt.Errorf("policy session invalidation: v4 enumerate: %w", c.v4Err))
	}
	if c.v6Err != nil {
		errs = append(errs, fmt.Errorf("policy session invalidation: v6 enumerate: %w", c.v6Err))
	}
	return errors.Join(errs...)
}
