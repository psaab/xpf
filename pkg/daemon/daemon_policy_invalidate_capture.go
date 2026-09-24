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

// #6948 — the commit-time session invalidation reads the session table BEFORE
// the dataplane publishes the new policy set, not after.
//
// Runtime policy ids are POSITIONAL (policySetID*MaxRulesPerPolicy + ruleIndex,
// pkg/dataplane/userspace/policies.go), so deleting a policy renumbers every
// later one:
//
//	C1 = [A, B, C]  ->  A=0, B=1, C=2
//	delete B
//	C2 = [A, C]     ->  A=0, C=1        <- C INHERITED B's id
//
// The invalidation computes its target set from the OLD numbering
// (deletedPolicyRuntimeIDs / changedPolicyRuntimeIDs read oldCfg), but it runs
// after applyConfigLocked returns — the whole apply tail included. In that
// window the value it matches on, the live row's policy_id, moves under it in
// TWO independent ways:
//
//  1. ADMISSION. The dataplane admits under the NEW numbering from the instant
//     the apply publishes the snapshot, so a session admitted afterwards by
//     surviving policy C carries policy_id 1 and matches the deletion set.
//
//  2. RE-STAMPING (the larger half, and invisible to a creation-time guard).
//     The helper's #3395 live-row refresh re-resolves every forward row's
//     policy_id from its bound rule handle against the CURRENT rule table and
//     writes it back into the same pinned conntrack map the Go sweep
//     enumerates (refresh_bpf_conntrack_last_seen, userspace-dp
//     afxdp/bpf_map/mod.rs). It runs in the worker loop on a rolling cycle —
//     CT_SLICE_INTERVAL_NS 100ms per slice, CT_REFRESH_SLICE_BUDGET 2048 slab
//     slots, CT_REFRESH_WINDOW_NS 10s full-table target
//     (afxdp/worker/loop_body/mod.rs) — so within the seconds the apply tail
//     takes it re-stamps established rows to the NEW numbering. C's
//     LONG-ESTABLISHED sessions are re-stamped 2 -> 1 and swept by the
//     deletion set, and B's own sessions are re-stamped to
//     DEFAULT_POLICY_SENTINEL_ID (their rule no longer resolves) and are
//     MISSED. Their creation time is ancient, so no "admitted after
//     activation" test can see either.
//
// The fix is to stop reading a value that is being rewritten. The candidate
// sessions are captured in ONE enumeration taken immediately before
// rt.ApplyConfig publishes the snapshot, while the numbering the target set was
// derived from is still the numbering the rows carry, and the deletes are
// issued from that capture after the apply. Placement is the design: the
// capture is a READ, so it cannot re-admit anything (an unconditional sweep
// moved before the publish would delete sessions of a policy that is still
// live, and an active flow would immediately re-establish under it — the
// inverse defect); and the deletes still land after the new policy set is live,
// so a cleared flow re-evaluates against the NEW config exactly as before.
//
// PROPERTY: every session the commit-time invalidation deletes was OBSERVED
// carrying its target policy id under the OLD policy numbering. No session
// admitted under, or re-stamped to, the new numbering can enter the candidate
// set.
//
// RESIDUAL: a session admitted by a to-be-deleted policy between the capture
// and the publish is not in the capture and keeps forwarding until idle
// timeout. That is the stale-authorization direction, so it is deliberately
// held to the smallest window the control plane can reach — the ApplyConfig
// call itself — by capturing at the last statement before it. It is strictly
// narrower than the pre-#6948 window (the whole post-activation apply tail).

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


// policyInvalidationCapture is the whole pre-publication snapshot: one bucket
// per change class, plus the enumerate errors.
//
// A NON-NIL capture is authoritative — the three clears delete exactly what it
// holds and never re-enumerate. An EMPTY non-nil capture therefore means "the
// capture ran and there was nothing to invalidate", which is a different state
// from nil ("no capture was taken; fall back to the legacy post-apply
// enumeration"). Conflating the two would silently disable the invalidation on
// a commit with nothing to clear, or re-introduce the post-apply read this
// exists to remove.
type policyInvalidationCapture struct {
	deleted  capturedSessions
	modified capturedSessions
	deflt    capturedSessions
	// renamed rows are retained and re-bound by the next Rust snapshot; they
	// must never enter any delete bucket.
	renamed        []dpuserspace.PolicySessionRebind
	renameAncestry []dpuserspace.PolicyRenameAncestry

	// readErr is the userspace helper READ failure, if any (P9): ONE
	// error for the one scan — never aliased into both v4Err/v6Err
	// (that double-counted a single failure in the commit result).
	// v4Err/v6Err belong to the store ForEach path only.
	readErr error
	v4Err   error
	v6Err   error
}

// armPolicyInvalidationPlan records the config pair the next applyConfigLocked
// should capture for. Caller holds d.applySem.
func (d *Daemon) armPolicyInvalidationPlan(oldCfg, newCfg *config.Config) {
	d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, nil)
}

func (d *Daemon) armPolicyInvalidationPlanWithRename(
	oldCfg, newCfg *config.Config,
	renameApply *pendingRenameApply,
) {
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
	if plan == nil {
		return
	}
	if plan.newCfg != cfg {
		// A plan left behind by an apply that never reached its own capture.
		// Dropped above; take no capture, so this apply's invalidation (if any)
		// falls back to the legacy scan rather than deleting a candidate set
		// gathered for a different commit.
		slog.Warn("policy session invalidation: dropping a stale pre-publication plan; " +
			"it was armed for a different config than this apply is publishing")
		return
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
		d.policyInvalidationCapture = capture
		return
	}

	rt := d.dataplane()
	if rt == nil {
		return
	}
	store := rt.Sessions()
	// #10512: userspace policy invalidation reads the helper authority, not
	// the BPF mirror. A missing/incomplete READ is a partial invalidation and
	// must never be converted into an authoritative empty capture.
	if lister, ok := rt.(interface {
		ListSessionsByPolicy(dpuserspace.SessionPolicyListRequest) (dpuserspace.ControlResponse, error)
	}); ok {
		ids := captureRequestedPolicyIDs(deleted, modified, deflt, renameBindings)
		resp, err := lister.ListSessionsByPolicy(dpuserspace.SessionPolicyListRequest{
			PolicyIDs: ids,
			Mode:      "prepublish",
			Families:  []uint8{4, 6},
			Classes:   []string{"forward"},
		})
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
			d.policyInvalidationCapture = capture
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
		}
		d.policyInvalidationCapture = capture
		return
	}

	if store == nil {
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

	d.policyInvalidationCapture = capture
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
func (d *Daemon) captureAndStagePolicyRenameAncestry(cfg *config.Config) {
	d.capturePolicyInvalidationLocked(cfg)
	rt := d.dataplane()
	if rt == nil {
		return
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
// session's stale authorization — and the error must reach the commit result
// rather than a log line. The userspace READ contributes at most ONE entry
// (readErr); v4/v6 legs belong to the store path only (P9).
func (c *policyInvalidationCapture) enumerateErr() error {
	if c.readErr == nil && c.v4Err == nil && c.v6Err == nil {
		return nil
	}
	slog.Error("policy session invalidation: pre-publication enumerate failed; clear is PARTIAL — some sessions of changed policies may keep forwarding",
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
