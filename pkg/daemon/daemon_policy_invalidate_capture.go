package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
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
	rollback    bool
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
	oldCfg *config.Config
	newCfg *config.Config
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
	// tailFailed prevents status-loop catch-up from treating publication as
	// proof that a deferred apply's failed local tail converged.
	tailFailed bool
	// landed is the predecessor obligation whose target had already landed
	// when this unlanded target's capture merged it forward. A superseded
	// target's retire restores it instead of dropping the whole debt.
	landed *policyInvalidationDebt
	// reauthorized holds retained helper candidates permitted by the rollback
	// target. They stop being owed only once that target is applied; a
	// superseding target re-owes them.
	reauthorized *policyInvalidationCapture
	// rollbackSource retains pre-rollback debt until the restored target lands.
	rollbackSource *policyInvalidationCapture
	rollback       bool
}

// deferredSnapshotApply retains the applied-marker digest and HA completion
// for one full snapshot until the helper accepts it. An in-band refusal
// resolves the current HA attempt as failed but retains the marker record for
// the status loop's later successful retry.
type deferredSnapshotApply struct {
	cfg        *config.Config
	generation uint64
	digest     string
	completion chan error
	reported   bool
}

var errDeferredSnapshotSuperseded = errors.New("deferred config snapshot superseded before publication")

func (d *Daemon) recordDeferredSnapshotApply(cfg *config.Config, generation uint64) {
	if cfg == nil || generation == 0 {
		return
	}
	var digest string
	if d.store != nil {
		digest = d.store.ActiveDigest()
	}
	pending := &deferredSnapshotApply{
		cfg: cfg, generation: generation, digest: digest,
		completion: make(chan error, 1),
	}
	d.deferredSnapshotApplyMu.Lock()
	if previous := d.deferredSnapshotApply; previous != nil {
		sameTarget := (previous.digest != "" && previous.digest == digest) || previous.cfg == cfg
		if sameTarget {
			previous.cfg = cfg
			previous.generation = generation
			if previous.reported {
				previous.completion = make(chan error, 1)
				previous.reported = false
			}
			d.deferredSnapshotApplyMu.Unlock()
			return
		}
		if !previous.reported {
			previous.reported = true
			previous.completion <- errDeferredSnapshotSuperseded
		}
	}
	d.deferredSnapshotApply = pending
	d.deferredSnapshotApplyMu.Unlock()
}

func (d *Daemon) resolveDeferredSnapshotApplyAfterSynchronousPublish(cfg *config.Config, generation uint64) {
	var digest string
	if d.store != nil {
		digest = d.store.ActiveDigest()
	}
	d.deferredSnapshotApplyMu.Lock()
	pending := d.deferredSnapshotApply
	if pending == nil {
		d.deferredSnapshotApplyMu.Unlock()
		return
	}
	sameTarget := (pending.digest != "" && pending.digest == digest) || pending.cfg == cfg
	if sameTarget && d.policyInvalidationDebt != nil {
		pending.cfg = cfg
		pending.generation = generation
		d.deferredSnapshotApplyMu.Unlock()
		return
	}
	d.deferredSnapshotApply = nil
	d.deferredSnapshotApplyMu.Unlock()

	if sameTarget {
		if d.store != nil {
			d.store.MarkAppliedDigest(pending.digest)
		}
		if !pending.reported {
			pending.completion <- nil
		}
		return
	}
	if !pending.reported {
		pending.completion <- errDeferredSnapshotSuperseded
	}
}

func (d *Daemon) deferredSnapshotCompletion(generation uint64) <-chan error {
	d.deferredSnapshotApplyMu.Lock()
	defer d.deferredSnapshotApplyMu.Unlock()
	if pending := d.deferredSnapshotApply; pending != nil && generation >= pending.generation {
		return pending.completion
	}
	return nil
}

func (d *Daemon) failDeferredSnapshotApplyForConfig(cfg *config.Config, err error) {
	if d == nil || cfg == nil || err == nil {
		return
	}
	var digest string
	if d.store != nil {
		digest = d.store.ActiveDigest()
	}
	d.deferredSnapshotApplyMu.Lock()
	pending := d.deferredSnapshotApply
	if pending == nil || !((pending.digest != "" && pending.digest == digest) || pending.cfg == cfg) {
		d.deferredSnapshotApplyMu.Unlock()
		return
	}
	d.deferredSnapshotApply = nil
	if !pending.reported {
		pending.reported = true
		pending.completion <- err
	}
	d.deferredSnapshotApplyMu.Unlock()
}

func (d *Daemon) deferredSnapshotCompletionForConfig(cfg *config.Config) <-chan error {
	d.deferredSnapshotApplyMu.Lock()
	defer d.deferredSnapshotApplyMu.Unlock()
	if pending := d.deferredSnapshotApply; pending != nil && pending.cfg == cfg {
		return pending.completion
	}
	return nil
}

// rejectDeferredSnapshotApply runs from Manager's status-loop callback under
// Manager.mu, so it only performs a bounded channel send and never waits.
func (d *Daemon) rejectDeferredSnapshotApply(generation uint64, err error) {
	d.deferredSnapshotApplyMu.Lock()
	defer d.deferredSnapshotApplyMu.Unlock()
	if pending := d.deferredSnapshotApply; pending != nil &&
		generation >= pending.generation && !pending.reported {
		pending.reported = true
		pending.completion <- err
	}
}

func (d *Daemon) completeDeferredSnapshotApply(generation uint64) {
	var activeDigest string
	if d.store != nil {
		activeDigest = d.store.ActiveDigest()
	}
	d.deferredSnapshotApplyMu.Lock()
	pending := d.deferredSnapshotApply
	if pending == nil || generation < pending.generation {
		d.deferredSnapshotApplyMu.Unlock()
		return
	}
	d.deferredSnapshotApply = nil
	d.deferredSnapshotApplyMu.Unlock()

	// A newer generation proves only that SOME snapshot landed. Settle this
	// record as applied only while its config is still the active target;
	// a different promoted config supersedes it (HA NACK, peer re-push).
	if pending.digest != "" && activeDigest != pending.digest {
		if !pending.reported {
			pending.completion <- errDeferredSnapshotSuperseded
		}
		return
	}
	// A retained scan-failure debt keeps the marker withheld, matching every
	// other marker site's debt gate (#12072/#12323).
	if d.store != nil && d.policyInvalidationDebt == nil {
		d.store.MarkAppliedDigest(pending.digest)
	}
	if !pending.reported {
		pending.completion <- nil
	}
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
	// candidateRuleIDs binds helper candidate identity to the stable rule key
	// that admitted it. Runtime policy IDs are positional and change across
	// config generations, so rollback re-authorization must not infer the
	// candidate's rule from the rollback target's policy ID.
	candidateRuleIDs map[policyInvalidationMatchIdentity]string
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

func (d *Daemon) armPolicyInvalidationRollbackPlan(oldCfg, newCfg *config.Config) {
	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	if d.policyInvalidationPlan != nil {
		d.policyInvalidationPlan.rollback = true
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
	// A retained authority refusal for an exact rollback to the debt's
	// predecessor is retried by a later background apply, not by the original
	// rollback caller. Let that matching successful publication discharge the
	// recaptured debt; a superseding commit is not an exact rollback.
	if originalDebt != nil && originalDebt.authorityRefusal != nil &&
		originalDebt.predecessorCfg != nil && plan.newCfg == originalDebt.predecessorCfg {
		d.policyInvalidationDebtAdopted = true
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
	var reauthorized *policyInvalidationCapture
	var tailFailed bool
	if debt := d.policyInvalidationDebt; debt != nil {
		tailFailed = debt.tailFailed && debt.newCfg == plan.newCfg
		landedTarget := applied != nil && debt.newCfg == applied && plan.newCfg != applied
		switch {
		case landedTarget && debt.predecessorCfg != nil && debt.predecessorCfg == plan.newCfg:
			// An exact rollback restores the landed target's predecessor, so
			// its candidates are no longer owed. Restore only any earlier
			// landed debt; preserve scanFailure below to remain fail-closed
			// until a complete capture or authoritative full clear. This
			// one-level path keeps its pre-#12532 behavior: the target's own
			// candidates leave the obligation here, before the undo publishes.
			landed = debt.landed
			if landed != nil {
				previousCapture = landed.capture
			}
		case landedTarget:
			// A landed debt's own predecessor was already merged into it and
			// can never be restored again; cut the chain so it stays bounded.
			debt.landed = nil
			landed = debt
			previousCapture = debt.capture
		default:
			// Carry landed obligations across superseding targets and same-target
			// adopts. Reusing the existing record keeps the chain depth at one.
			landed = debt.landed
			previousCapture = debt.capture
			if debt.reauthorized != nil && applied != debt.newCfg {
				// The rollback target has not landed. A same-target retry keeps
				// waiting for it; any other target re-owes those candidates.
				if debt.newCfg == plan.newCfg {
					reauthorized = debt.reauthorized
				} else {
					previousCapture = mergePolicyInvalidationCaptures(
						debt.reauthorized, clonePolicyInvalidationCapture(debt.capture))
				}
			}
		}
		previousScanFailure = debt.scanFailure
		if debt.newCfg == plan.newCfg {
			previousGeneration = debt.publishGeneration
		}
	}
	predecessorCfg := plan.oldCfg
	if debt := d.policyInvalidationDebt; debt != nil && debt.newCfg == plan.newCfg {
		predecessorCfg = debt.predecessorCfg
	}
	rollbackIntent := plan.rollback
	var rollbackSource *policyInvalidationCapture
	if originalDebt != nil {
		switch {
		case originalDebt.rollback && originalDebt.newCfg == plan.newCfg:
			// A rejected same-target publish is a retry of the same rollback.
			// Reuse its source, while incorporating any additional candidates
			// found in the retry capture.
			rollbackSource = mergePolicyInvalidationCaptures(
				clonePolicyInvalidationCapture(originalDebt.rollbackSource),
				clonePolicyInvalidationCapture(originalDebt.capture))
			rollbackIntent = true
		case plan.rollback:
			// A different rollback target must re-owe the latest capture, not
			// an earlier rollback source that predates newly retained rows.
			rollbackSource = originalDebt.capture
		}
	}
	d.policyInvalidationDebt = &policyInvalidationDebt{
		oldCfg: plan.oldCfg, newCfg: plan.newCfg, predecessorCfg: predecessorCfg,
		renameApply: plan.renameApply, scanFailure: previousScanFailure,
		publishGeneration: previousGeneration, landed: landed, reauthorized: reauthorized,
		rollback: rollbackIntent, rollbackSource: rollbackSource, tailFailed: tailFailed,
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
		// #12515: an empty diff is convergence-proof only when the helper's
		// applied snapshot is provably the plan's old authority. A lost-ACK
		// commit-confirm C2 republishes as a C1->C1 rollback plan (debt.oldCfg
		// re-anchor above); a session admitted only by C2 may still be live.
		// Refuse publication under unknown or mismatched authority so the retry
		// can re-anchor to the helper's reconciled C2 snapshot and capture its
		// sessions before applying C1.
		// This runs under applySem, so no daemon config publication can change
		// the sampled authority before the matching ApplyConfig.
		if rt := d.dataplane(); rt != nil && plan.oldCfg != nil {
			// Only dataplans with the helper's authority-aware LIST surface
			// have a snapshot authority to fence here; legacy fallbacks cannot
			// distinguish unknown publication outcomes.
			if _, ok := rt.(interface {
				ListSessionsByPolicy(dpuserspace.SessionPolicyListRequest) (dpuserspace.ControlResponse, error)
			}); ok && policyInvalidationAppliedConfig(rt) != plan.oldCfg {
				refusal := fmt.Errorf(
					"%w: empty-diff policy invalidation authority is unknown or changed",
					dpuserspace.ErrPolicyReadAuthority)
				d.refusePolicyInvalidationAuthorityLocked(plan, originalDebt, capture, refusal)
				return
			}
		}
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
		// #12532: invert plan.oldCfg's stable-key map once per capture so the
		// provenance lookup below is O(1) per candidate, not a policy walk.
		var ruleKeys map[uint32]string
		if len(resp.SessionPolicyMatches) != 0 {
			ruleKeys = policyRuleKeysByRuntimeID(plan.oldCfg)
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
					recordPolicyCandidateRule(capture, ruleKeys, match)
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
			recordPolicyCandidateRule(capture, ruleKeys, match)
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
			// Re-authorize only obligations retained before this rollback.
			// Fresh candidates still follow ordinary deletion/rematch policy,
			// including default-policy log-only rematches. Kept candidates are
			// denied by the rollback target and remain deletion obligations.
			// Merge them into this capture because exact-undo capture deliberately
			// does not carry the target's landed set; rejection must not discard
			// them before a superseding target can re-owe the candidates.
			if debt.rollback && debt.rollbackSource != nil {
				changed, unconditional := defaultPolicyChanged(debt.oldCfg, debt.newCfg)
				preserveDefaultRematch := changed && !unconditional &&
					debt.newCfg != nil && debt.newCfg.Security.PolicyRematch
				kept, permitted := d.reauthorizePolicyCandidates(
					debt.rollbackSource, debt.newCfg, preserveDefaultRematch)
				debt.reauthorized = mergePolicyInvalidationCaptures(debt.reauthorized, permitted)
				capture = mergePolicyInvalidationCaptures(capture, kept)
				// Remove permitted identities from the merged capture so a
				// fresh sentinel classification cannot reintroduce them as a
				// delete while the rollback target remains unpublished.
				removeReauthorizedPolicyCandidates(capture, permitted)
			}
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
	if current.candidateRuleIDs == nil && len(previous.candidateRuleIDs) != 0 {
		current.candidateRuleIDs = make(map[policyInvalidationMatchIdentity]string)
	}
	for id, ruleID := range previous.candidateRuleIDs {
		if ruleID != "" {
			current.candidateRuleIDs[id] = ruleID
		}
	}
	// New candidates are already represented in seenPolicy; do not let them
	// replace retained stable-rule provenance for an identical row.
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

// policyRuleKeysByRuntimeID inverts PolicyIDsByStableKey once, so a capture's
// provenance lookups cost O(1) per candidate instead of one policy walk each
// (#12532). The default-policy sentinel maps to DefaultPolicyName. A runtime ID
// claimed by two stable keys maps to "": unknown provenance stays debt.
func policyRuleKeysByRuntimeID(cfg *config.Config) map[uint32]string {
	ids := dpuserspace.PolicyIDsByStableKey(cfg)
	keys := make(map[uint32]string, len(ids)+1)
	for key, id := range ids {
		if _, claimed := keys[id]; claimed {
			keys[id] = ""
			continue
		}
		keys[id] = key
	}
	keys[dataplane.DefaultPolicySentinelID] = dataplane.DefaultPolicyName
	return keys
}

// recordPolicyCandidateRule binds a helper candidate to the stable rule key
// that admitted it in the capture's old namespace. An unknown runtime ID
// records nothing, so re-authorization keeps that candidate as debt.
func recordPolicyCandidateRule(
	capture *policyInvalidationCapture, ruleKeys map[uint32]string, match dpuserspace.SessionPolicyMatch,
) {
	key := ruleKeys[match.PolicyID]
	if key == "" {
		return
	}
	if capture.candidateRuleIDs == nil {
		capture.candidateRuleIDs = make(map[policyInvalidationMatchIdentity]string)
	}
	capture.candidateRuleIDs[policyInvalidationMatchID(match)] = key
}

// clonePolicyInvalidationCapture copies the candidate buckets and provenance,
// so merging into the copy cannot mutate a debt that a refusal may restore.
func clonePolicyInvalidationCapture(capture *policyInvalidationCapture) *policyInvalidationCapture {
	if capture == nil {
		return nil
	}
	clone := *capture
	for _, bucket := range []*capturedSessions{&clone.deleted, &clone.modified, &clone.deflt} {
		bucket.v4 = slices.Clone(bucket.v4)
		bucket.v6 = slices.Clone(bucket.v6)
		bucket.policy = slices.Clone(bucket.policy)
	}
	clone.candidateRuleIDs = maps.Clone(capture.candidateRuleIDs)
	return &clone
}

// reauthorizePolicyCandidates splits retained helper candidates into those the
// restored config still forbids (kept) and those it permits. Positional policy
// IDs may differ at every nesting level, so each candidate is judged by the
// stable rule key recorded when it was captured. capture itself is never
// modified: an authority refusal later in the same capture restores the
// original debt, which must still own every candidate. Unknown provenance,
// colliding zone IDs, and malformed tuples are kept and therefore fail closed.
// permitted is nil when the restored config permits no candidate.
func (d *Daemon) reauthorizePolicyCandidates(
	capture *policyInvalidationCapture, restored *config.Config, preserveDefaultRematch bool,
) (kept, permitted *policyInvalidationCapture) {
	if capture == nil || restored == nil {
		return capture, nil
	}
	// A StableZoneID collision makes the zone attribution of every candidate
	// ambiguous, so nothing can be shown to be permitted.
	zoneNames, ok := zoneNamesByID(restored)
	if !ok {
		return capture, nil
	}
	policies := dpuserspace.PoliciesByStableKey(restored)
	feedOverlay := d.feedSnapshotsForConfig(restored)
	policyInactive := dpuserspace.PolicyInactiveFn(
		d.policySchedulerActiveStateForApplyLocked(restored, time.Now()))
	isPermitted := func(key string, match dpuserspace.SessionPolicyMatch) bool {
		if key == dataplane.DefaultPolicyName && preserveDefaultRematch {
			return false
		}
		from, to := zoneNames[match.IngressZoneID], zoneNames[match.EgressZoneID]
		if key == "" || from == "" || to == "" {
			return false
		}
		if key != dataplane.DefaultPolicyName {
			parts := strings.SplitN(key, "/", 2)
			zones := strings.SplitN(parts[0], "->", 2)
			global := strings.HasPrefix(key, "junos-global->junos-global/")
			if len(parts) != 2 || len(zones) != 2 ||
				(!global &&
					(zones[0] != "any" && zones[0] != from ||
						zones[1] != "any" && zones[1] != to)) {
				return false
			}
			policy, exists := policies[key]
			if !exists || policy.Action != config.PolicyPermit {
				return false
			}
		}
		family := match.AddrFamily
		if family == 0 {
			family = match.Tuple.AddrFamily
		}
		src, dst := net.ParseIP(match.Tuple.SrcIP), net.ParseIP(match.Tuple.DstIP)
		if family == 4 {
			src, dst = src.To4(), dst.To4()
		} else if family == 6 {
			src, dst = src.To16(), dst.To16()
			if src == nil || dst == nil || net.ParseIP(match.Tuple.SrcIP).To4() != nil ||
				net.ParseIP(match.Tuple.DstIP).To4() != nil {
				return false
			}
		} else {
			return false
		}
		if src == nil || dst == nil {
			return false
		}
		query := policymatch.Query{
			FromZone: from, ToZone: to, SrcIP: src, DstIP: dst,
			Protocol: policyQueryProtocol(match.Tuple.Protocol),
			SrcPort:  int(match.Tuple.SrcPort), DstPort: int(match.Tuple.DstPort),
			SrcFamily: fmt.Sprintf("v%d", family), DstFamily: fmt.Sprintf("v%d", family),
		}
		if match.DNAT && match.NATDstIP != "" {
			translated := net.ParseIP(match.NATDstIP)
			if family == 4 {
				translated = translated.To4()
			} else {
				translated = translated.To16()
				if translated == nil || translated.To4() != nil {
					return false
				}
			}
			if translated == nil {
				return false
			}
			query.DstIP = translated
		}
		if match.DNAT && match.NATDstPort != 0 {
			query.DstPort = int(match.NATDstPort)
		}
		query.FeedOverlay = feedOverlay
		query.PolicyInactiveFn = policyInactive
		result := policymatch.Match(restored, query)
		return result.Action == config.PolicyPermit
	}
	keptCapture := *capture
	kept = &keptCapture
	kept.candidateRuleIDs = maps.Clone(capture.candidateRuleIDs)
	permitted = &policyInvalidationCapture{}
	// split keeps a v4/v6 entry unless only permitted candidates name its key.
	split := func(bucket capturedSessions) (keep, allow capturedSessions) {
		if bucket.empty() {
			return bucket, capturedSessions{}
		}
		keep = capturedSessions{targets: bucket.targets, enumFailed: bucket.enumFailed}
		keepV4, allowV4 := map[dataplane.SessionKey]struct{}{}, map[dataplane.SessionKey]struct{}{}
		keepV6, allowV6 := map[dataplane.SessionKeyV6]struct{}{}, map[dataplane.SessionKeyV6]struct{}{}
		for _, match := range bucket.policy {
			id := policyInvalidationMatchID(match)
			key := capture.candidateRuleIDs[id]
			allowed := isPermitted(key, match)
			if allowed {
				allow.policy = append(allow.policy, match)
				if permitted.candidateRuleIDs == nil {
					permitted.candidateRuleIDs = make(map[policyInvalidationMatchIdentity]string)
				}
				permitted.candidateRuleIDs[id] = key
				delete(kept.candidateRuleIDs, id)
			} else {
				keep.policy = append(keep.policy, match)
			}
			family := match.AddrFamily
			if family == 0 {
				family = match.Tuple.AddrFamily
			}
			switch family {
			case 4:
				if key, _, err := policyTupleV4(match.Tuple); err == nil {
					if allowed {
						allowV4[key] = struct{}{}
					} else {
						keepV4[key] = struct{}{}
					}
				}
			case 6:
				if key, _, err := policyTupleV6(match.Tuple); err == nil {
					if allowed {
						allowV6[key] = struct{}{}
					} else {
						keepV6[key] = struct{}{}
					}
				}
			}
		}
		for _, entry := range bucket.v4 {
			_, allowed := allowV4[entry.Key]
			if _, owed := keepV4[entry.Key]; owed || !allowed {
				keep.v4 = append(keep.v4, entry)
			}
			if allowed {
				allow.v4 = append(allow.v4, entry)
			}
		}
		for _, entry := range bucket.v6 {
			_, allowed := allowV6[entry.Key]
			if _, owed := keepV6[entry.Key]; owed || !allowed {
				keep.v6 = append(keep.v6, entry)
			}
			if allowed {
				allow.v6 = append(allow.v6, entry)
			}
		}
		return keep, allow
	}
	kept.deleted, permitted.deleted = split(capture.deleted)
	kept.modified, permitted.modified = split(capture.modified)
	kept.deflt, permitted.deflt = split(capture.deflt)
	if permitted.candidateCount() == 0 {
		return capture, nil
	}
	return kept, permitted
}

// removeReauthorizedPolicyCandidates removes only rows whose retained
// provenance has already been proven permitted by the rollback target. The
// fresh capture otherwise remains intact, preserving ordinary rematch clears.
func removeReauthorizedPolicyCandidates(
	capture, permitted *policyInvalidationCapture,
) {
	if capture == nil || permitted == nil || permitted.candidateCount() == 0 {
		return
	}
	type sessionIdentityV4 struct {
		key                 dataplane.SessionKey
		routingDomain       uint32
		sessionID           uint64
		tunnelDiscriminator uint64
	}
	type sessionIdentityV6 struct {
		key                 dataplane.SessionKeyV6
		routingDomain       uint32
		sessionID           uint64
		tunnelDiscriminator uint64
	}
	ids := make(map[policyInvalidationMatchIdentity]struct{}, permitted.candidateCount())
	sessionIDsV4 := make(map[sessionIdentityV4]struct{}, permitted.candidateCount())
	sessionIDsV6 := make(map[sessionIdentityV6]struct{}, permitted.candidateCount())
	for _, bucket := range []capturedSessions{permitted.deleted, permitted.modified, permitted.deflt} {
		for _, match := range bucket.policy {
			ids[policyInvalidationMatchID(match)] = struct{}{}
			v4, v6, err := policyMatchEntries(match)
			if err != nil {
				continue
			}
			if v4 != nil {
				sessionIDsV4[sessionIdentityV4{
					key: v4.Key, routingDomain: v4.Value.RoutingDomain,
					sessionID:           v4.Value.RTFlowSessionID,
					tunnelDiscriminator: v4.Value.TunnelDiscriminator,
				}] = struct{}{}
			}
			if v6 != nil {
				sessionIDsV6[sessionIdentityV6{
					key: v6.Key, routingDomain: v6.Value.RoutingDomain,
					sessionID:           v6.Value.RTFlowSessionID,
					tunnelDiscriminator: v6.Value.TunnelDiscriminator,
				}] = struct{}{}
			}
		}
	}
	filter := func(bucket *capturedSessions) {
		policy := bucket.policy[:0]
		for _, match := range bucket.policy {
			id := policyInvalidationMatchID(match)
			if _, ok := ids[id]; ok {
				delete(capture.candidateRuleIDs, id)
				continue
			}
			policy = append(policy, match)
		}
		bucket.policy = policy
		v4 := bucket.v4[:0]
		for _, entry := range bucket.v4 {
			id := sessionIdentityV4{
				key: entry.Key, routingDomain: entry.Value.RoutingDomain,
				sessionID:           entry.Value.RTFlowSessionID,
				tunnelDiscriminator: entry.Value.TunnelDiscriminator,
			}
			if _, ok := sessionIDsV4[id]; !ok {
				v4 = append(v4, entry)
			}
		}
		bucket.v4 = v4
		v6 := bucket.v6[:0]
		for _, entry := range bucket.v6 {
			id := sessionIdentityV6{
				key: entry.Key, routingDomain: entry.Value.RoutingDomain,
				sessionID:           entry.Value.RTFlowSessionID,
				tunnelDiscriminator: entry.Value.TunnelDiscriminator,
			}
			if _, ok := sessionIDsV6[id]; !ok {
				v6 = append(v6, entry)
			}
		}
		bucket.v6 = v6
	}
	filter(&capture.deleted)
	filter(&capture.modified)
	filter(&capture.deflt)
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
		if !owed && d.deferredSnapshotCompletion(generation) == nil {
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

func (d *Daemon) rejectDeferredSnapshotPublish(generation uint64, err error) {
	d.rejectDeferredSnapshotApply(generation, err)
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
	if debt != nil {
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
			if active == debt.newCfg && debt.appliedDigest == "" && !debt.tailFailed {
				// The catch-up callback is a successful apply boundary even
				// when the original caller lost its response.
				debt.appliedDigest = d.store.ActiveDigest()
			}
		}
		if err := d.dischargePolicyInvalidationDebtLocked(debt.oldCfg, debt.newCfg); err != nil {
			slog.Error("deferred policy session invalidation was PARTIAL; some sessions may keep forwarding under stale authorization",
				"err", err, "generation", generation)
			d.rejectDeferredSnapshotApply(generation, err)
			return
		}
	}
	d.completeDeferredSnapshotApply(generation)
}

// dischargePolicyInvalidationDebtLocked consumes the captured debt only after
// every requested authorization change succeeds. The fallback pair preserves
// legacy behavior for test seams and dataplanes without a pre-publication
// capture.
func (d *Daemon) dischargePolicyInvalidationDebtLocked(oldCfg, newCfg *config.Config) error {
	if debt := d.policyInvalidationDebt; debt != nil {
		if pending := debt.reauthorized; pending != nil {
			// Callers discharge only after publication landed. The restored
			// target's permit holds only while the helper confirms that
			// target is applied; otherwise its pending candidates are owed.
			debt.reauthorized = nil
			if policyInvalidationAppliedConfig(d.dataplane()) != debt.newCfg {
				debt.capture = mergePolicyInvalidationCaptures(
					pending, clonePolicyInvalidationCapture(debt.capture))
			}
		}
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
