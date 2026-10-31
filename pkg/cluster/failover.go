// Package cluster — failover.go owns the entire manual-failover locking
// domain: single-RG and multi-RG (batch) manual failover protocol, the
// transfer-commit state machine (peer transfer-out overrides, transfer-
// commit grace windows, local transfer-out hold), and the heartbeat
// peer-state override application helper. Co-locating these keeps the
// shared *Locked helpers next to every caller that needs them and makes
// the "committed-failover-suppresses-stale-heartbeat" invariant
// answerable by reading this file end-to-end.
//
// Cross-file callers:
//   - heartbeat_manager.go::handlePeerHeartbeat calls
//     applyTransferCommitOverridesOnPeerStateLocked to apply pending
//     transfer-out overrides + expire grace windows while rebuilding
//     newPeerGroups.
//   - heartbeat_manager.go::handlePeerTimeout calls
//     suppressPeerTimeoutForTransferCommitLocked to keep a recent
//     transfer-commit window from triggering an immediate
//     peer-lost cascade.
//
// Both are package-private cross-file method calls on *Manager.
package cluster

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Single-RG manual failover and transfer protocol.
// =============================================================================

// FailoverOutcome reports what a manual-failover request actually did to one
// redundancy group (#8000).
//
// It exists because "no error" and "the failover happened" are not the same
// thing on this path, and the difference is invisible to the caller. A
// `ResetFailover` landing in the unlocked pre-hook window bumps the RG's
// failover generation, and the reset WINS: the trailing SecondaryHold write is
// abandoned and nil is returned (#5246, pinned by
// failover_races_5245_5246_test.go). That is correct and must not become an
// error — but reporting it as plain success is what left an operator unable to
// tell which RGs of a batch actually moved.
type FailoverOutcome int

const (
	// FailoverApplied: the RG was placed in SecondaryHold by this request.
	FailoverApplied FailoverOutcome = iota
	// FailoverSuperseded: a concurrent ResetFailover won; this request made no
	// change. NOT an error — the reset is the operator's newer intent.
	FailoverSuperseded
)

// ErrFailoverSuperseded is the verdict a superseded remote transfer-out
// resolves its fence barrier with (#9036).
//
// It is a FAILURE for ack purposes even though nothing went wrong. #5640
// requires an applied-ack to mean "this node is fenced"; a supersede means it
// never demoted at all, which is the one condition an applied-ack must never
// be sent for. The distinction #8000 removed from the wire — by dropping the
// barrier, which makes the wait return nil, which is indistinguishable from a
// real fence — is restored by resolving the barrier with THIS instead of
// deleting it, so the operator still gets the true reason rather than #8000's
// misleading fence timeout.
var ErrFailoverSuperseded = errors.New("failover superseded by concurrent reset; no transfer performed")

func (o FailoverOutcome) String() string {
	if o == FailoverSuperseded {
		return "superseded"
	}
	return "applied"
}

// nextFailoverOwnerLocked allocates an identity for a failover reservation.
// Caller must hold m.mu. A non-zero token is required because zero means that
// no reservation exists in failoverInProgress.
func (m *Manager) nextFailoverOwnerLocked() uint64 {
	m.failoverOwnerSeq++
	if m.failoverOwnerSeq == 0 {
		// The sequence is practically unexhaustible, but never let uint64
		// wrap make an old token equal to a future reservation.
		m.failoverOwnerSeq++
	}
	return m.failoverOwnerSeq
}

// releaseFailoverLocked drops a reservation only when it still belongs to the
// caller. An old request can outlive a remove+re-add and must not clear the
// fresh incarnation's newer reservation. Caller must hold m.mu.
func (m *Manager) releaseFailoverLocked(rgID int, owner uint64) {
	if current, ok := m.failoverInProgress[rgID]; ok && current == owner {
		delete(m.failoverInProgress, rgID)
	}
}

// failoverReservation is the single reserve/barrier/relock/commit protocol
// shared by ManualFailover, ManualFailoverBatch and ForceSecondary (#17120).
// It captures, under m.mu, the exact RG incarnation (pointer) for every
// reserved or snapshotted id, plus failover generation, active/disabled
// membership and owner token for every RESERVED id (r.ids). ForceSecondary
// snapshots disabled RGs (pointer+active only, in rgs/active) so membership
// revalidation covers them without reserving them. Pointer identity is the
// unified revalidation policy: a config remove+re-add allocates a fresh
// RedundancyGroupState even when the numeric id and the purged generation
// (0) coincide, so exists+gen alone would demote an incarnation the barrier
// never ran for. Generation still catches a ResetFailover on the same
// incarnation (#5246/#10004).
type failoverReservation struct {
	ids    []int // reserved ids (owner token + gen captured)
	owners map[int]uint64
	gens   map[int]uint64
	rgs    map[int]*RedundancyGroupState // reserved + snapshot-only ids
	active map[int]bool                  // nil for manual failover (no membership check)
}

// reserveLocked reserves every id in reserveIDs (owner token + generation
// capture; these block concurrent manual failover and carry the #10004
// supersede gen-bump). When snapshotIDs is non-nil (ForceSecondary) the
// reservation additionally snapshots pointer+active for those ids WITHOUT
// reserving them, so membership revalidation covers disabled RGs that the
// parent never blocked. Caller must hold m.mu. supersedeExisting
// (ForceSecondary/#10004) bumps the generation of an already-reserved RG
// before taking it over, so an older in-flight abort cannot restore over the
// new commit; manual failover instead rejects an existing reservation.
func (m *Manager) reserveLocked(reserveIDs, snapshotIDs []int, checkActive, supersedeExisting bool) (*failoverReservation, error) {
	for _, rgID := range reserveIDs {
		if _, ok := m.groups[rgID]; !ok {
			return nil, fmt.Errorf("redundancy group %d not found", rgID)
		}
		if !supersedeExisting && m.failoverInProgress[rgID] != 0 {
			if len(reserveIDs) == 1 {
				return nil, fmt.Errorf("failover already in progress for redundancy group %d, please wait", rgID)
			}
			return nil, fmt.Errorf("failover already in progress for redundancy groups %v, please wait", reserveIDs)
		}
	}
	for _, rgID := range snapshotIDs {
		if _, ok := m.groups[rgID]; !ok {
			return nil, fmt.Errorf("redundancy group %d not found", rgID)
		}
	}
	r := &failoverReservation{
		ids:    append([]int(nil), reserveIDs...),
		owners: make(map[int]uint64, len(reserveIDs)),
		gens:   make(map[int]uint64, len(reserveIDs)),
		rgs:    make(map[int]*RedundancyGroupState, len(reserveIDs)+len(snapshotIDs)),
	}
	if checkActive {
		r.active = make(map[int]bool, len(reserveIDs)+len(snapshotIDs))
	}
	for _, rgID := range reserveIDs {
		if supersedeExisting && m.failoverInProgress[rgID] != 0 {
			m.failoverGen[rgID]++
		}
		owner := m.nextFailoverOwnerLocked()
		m.failoverInProgress[rgID] = owner
		r.owners[rgID] = owner
		r.gens[rgID] = m.failoverGen[rgID]
		rg := m.groups[rgID]
		r.rgs[rgID] = rg
		if checkActive {
			r.active[rgID] = rg.State != StateDisabled
		}
	}
	// Snapshot-only ids (ForceSecondary disabled RGs): capture pointer+active
	// for revalidation without reserving or gen-bumping — a manual failover
	// on a disabled RG during the barrier stays admissible, as on parent.
	for _, rgID := range snapshotIDs {
		rg := m.groups[rgID]
		r.rgs[rgID] = rg
		if checkActive {
			r.active[rgID] = rg.State != StateDisabled
		}
	}
	return r, nil
}

// releaseReservationLocked drops every reservation still owned by this
// reservation. Caller must hold m.mu.
func (m *Manager) releaseReservationLocked(r *failoverReservation) {
	for _, rgID := range r.ids {
		m.releaseFailoverLocked(rgID, r.owners[rgID])
	}
}

// runPreHook runs the single retry loop for ids, always logging retries.
// logName is "manual failover" or "manual failover batch" (ForceSecondary
// passes "manual failover", preserving its members' per-RG wording).
// Call WITHOUT m.mu: the barrier waits on a peer round trip.
func (m *Manager) runPreHook(ids []int, logName string) error {
	m.mu.Lock()
	preHook := m.preManualFailoverFn
	retryTimeout := m.preManualFailoverRetryTimeout
	retryInterval := m.preManualFailoverRetryInterval
	m.mu.Unlock()
	if preHook == nil {
		return nil
	}
	for _, rgID := range ids {
		deadline := time.Now().Add(retryTimeout)
		for attempts := 1; ; attempts++ {
			if err := preHook(rgID); err != nil {
				if !IsRetryablePreFailoverError(err) {
					return fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
				}
				remaining := time.Until(deadline)
				if remaining <= 0 {
					return fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
				}
				sleep := retryInterval
				if sleep <= 0 {
					sleep = DefaultPreManualFailoverRetryInterval
				}
				if sleep > remaining {
					sleep = remaining
				}
				// Batch retry carries the full member set ("rgs") as on
				// parent; single/ForceSecondary keep the per-RG form.
				if logName == "manual failover batch" {
					slog.Info("cluster: waiting to admit "+logName,
						"rgs", ids,
						"rg", rgID,
						"attempt", attempts,
						"remaining", remaining.String(),
						"err", err)
				} else {
					slog.Info("cluster: waiting to admit "+logName,
						"rg", rgID,
						"attempt", attempts,
						"remaining", remaining.String(),
						"err", err)
				}
				time.Sleep(sleep)
				continue
			}
			break
		}
	}
	return nil
}

// revalidateLocked is the one revalidation policy for all three entry
// points. Caller must hold m.mu. It returns:
//   - missing: an id no longer exists (or, when active was captured, any
//     membership/active change — ForceSecondary's all-or-nothing gate)
//   - superseded: ids whose generation changed (reset won, #5246)
//   - changed: an id whose pointer changed without a generation change
//     (remove+re-add at gen 0) — callers must abort, not demote.
func (m *Manager) revalidateLocked(r *failoverReservation) (missing []int, superseded []int, changed int, changedSet bool) {
	for _, rgID := range r.ids {
		rg, ok := m.groups[rgID]
		if !ok {
			missing = append(missing, rgID)
			continue
		}
		if rg != r.rgs[rgID] {
			if !changedSet {
				changed, changedSet = rgID, true
			}
			continue
		}
		if r.active != nil && (rg.State != StateDisabled) != r.active[rgID] {
			missing = append(missing, rgID)
			continue
		}
		if m.failoverGen[rgID] != r.gens[rgID] {
			superseded = append(superseded, rgID)
		}
	}
	if r.active != nil {
		// ForceSecondary snapshot-only ids (disabled at capture): pointer or
		// active change is a membership change, but they were never reserved
		// so no generation check applies.
		for rgID, snap := range r.rgs {
			if _, reserved := r.owners[rgID]; reserved {
				continue
			}
			rg, ok := m.groups[rgID]
			if !ok {
				missing = append(missing, rgID)
				continue
			}
			if rg != snap {
				if !changedSet {
					changed, changedSet = rgID, true
				}
				continue
			}
			if (rg.State != StateDisabled) != r.active[rgID] {
				missing = append(missing, rgID)
			}
		}
		// A count change means membership changed even if every captured
		// id still matches.
		if len(m.groups) != len(r.rgs) && len(missing) == 0 {
			missing = append(missing, -1)
		}
	}
	return missing, superseded, changed, changedSet
}

// ManualFailover forces a redundancy group to transfer out of primary.
// Unlike ForceSecondary, this preserves the group's monitor-derived weight
// and advertises an explicit transfer-out state so the peer can claim
// primary without relying on weight-zero election semantics.
func (m *Manager) ManualFailover(rgID int) (FailoverOutcome, error) {
	m.mu.Lock()
	resv, rerr := m.reserveLocked([]int{rgID}, nil, false, false)
	if rerr != nil {
		m.mu.Unlock()
		return FailoverApplied, rerr
	}
	staleFn := m.peerConfigStaleFn
	m.mu.Unlock()

	// #9569: this demotes the local node, so the peer is what gets promoted.
	if err := peerConfigStaleRefusal(staleFn, fmt.Sprintf("manual failover of redundancy group %d", rgID)); err != nil {
		m.mu.Lock()
		m.releaseReservationLocked(resv)
		m.mu.Unlock()
		return FailoverApplied, err
	}

	preHookErr := m.runPreHook([]int{rgID}, "manual failover")

	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.releaseReservationLocked(resv)

	if preHookErr != nil {
		return FailoverApplied, preHookErr
	}

	missing, superseded, _, changedSet := m.revalidateLocked(resv)
	if len(missing) > 0 {
		return FailoverApplied, fmt.Errorf("redundancy group %d not found", rgID)
	}
	if changedSet {
		// #17120: remove+re-add during the barrier — the barrier ran for the
		// old incarnation, not this fresh pointer (gen may coincide at 0).
		return FailoverApplied, fmt.Errorf("redundancy group %d not found", rgID)
	}
	// If a ResetFailover ran during the unlocked pre-hook window it bumped
	// this RG's failover generation (#5246). Detect the supersede and abandon.
	if len(superseded) > 0 {
		slog.Info("cluster: manual failover superseded by reset, abandoning", "rg", rgID)
		return FailoverSuperseded, nil
	}
	rg := m.groups[rgID]
	oldState := rg.State
	m.clearRemoteTransferOutLeaseLocked(rgID)
	rg.transferCommitRolePinned = false
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now()
	rg.State = StateSecondaryHold
	rg.FailoverCount++
	if oldState != rg.State {
		m.sendEvent(rg.GroupID, oldState, rg.State, "Manual failover")
	}
	slog.Info("cluster: manual failover", "rg", rgID)
	return FailoverApplied, nil
}

// ForceSecondary sets weight to 0 for all redundancy groups, forcing this node
// to become secondary. Used by ISSU to drain traffic to the peer before upgrade.
// Returns an error if the peer is not alive (no peer to take over), or if the
// pre-manual-failover hook cannot prove that the peer has received the current
// session state. The hook is the userspace session-sync demotion barrier; it
// MUST run before any RG is demoted so a failed barrier leaves the node fully
// forwarding (#10261).
func (m *Manager) ForceSecondary() error {
	m.mu.Lock()
	staleFn := m.peerConfigStaleFn
	m.mu.Unlock()
	if err := peerConfigStaleRefusal(staleFn, "to force secondary"); err != nil {
		return err
	}

	m.mu.Lock()
	if !m.peerAlive {
		m.mu.Unlock()
		return fmt.Errorf("peer not alive — cannot force secondary without active peer")
	}
	// Snapshot EVERY configured RG (including disabled) so membership/active
	// revalidation covers the whole config, but RESERVE only active RGs —
	// matching parent: disabled RGs are never demoted, so they must not block
	// a concurrent manual failover nor take the #10004 supersede gen-bump.
	allIDs := make([]int, 0, len(m.groups))
	for rgID := range m.groups {
		allIDs = append(allIDs, rgID)
	}
	sort.Ints(allIDs)
	var activeIDs, disabledIDs []int
	for _, rgID := range allIDs {
		if m.groups[rgID].State != StateDisabled {
			activeIDs = append(activeIDs, rgID)
		} else {
			disabledIDs = append(disabledIDs, rgID)
		}
	}
	resv, rerr := m.reserveLocked(activeIDs, disabledIDs, true, true)
	if rerr != nil {
		m.mu.Unlock()
		return rerr
	}
	ids := activeIDs
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.releaseReservationLocked(resv)
		m.mu.Unlock()
	}()

	if err := m.runPreHook(ids, "manual failover"); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.peerAlive {
		return fmt.Errorf("peer not alive — cannot force secondary without active peer")
	}
	missing, superseded, _, changedSet := m.revalidateLocked(resv)
	if len(missing) > 0 || changedSet {
		return fmt.Errorf("redundancy-group membership changed while preparing force-secondary; aborting without demotion")
	}
	if len(superseded) > 0 {
		return fmt.Errorf("redundancy-group %d changed while preparing force-secondary; aborting without demotion", superseded[0])
	}
	for _, rgID := range ids {
		rg := m.groups[rgID]
		oldState := rg.State
		m.clearRemoteTransferOutLeaseLocked(rg.GroupID)
		rg.transferCommitRolePinned = false
		rg.Weight = 0
		rg.forcedSecondary = true
		rg.ManualFailover = true
		rg.ManualFailoverAt = time.Now()
		rg.State = StateSecondary
		if oldState != rg.State {
			rg.FailoverCount++
			m.sendEvent(rg.GroupID, oldState, rg.State, "Forced secondary (ISSU)")
		}
	}
	slog.Info("cluster: forced secondary for all RGs (ISSU)")
	return nil
}

// ResetFailover clears manual failover for one redundancy group and resumes
// normal election for that group.
//
// It deliberately does NOT clear the node-global kernel-upgrade election
// hold (#15239, A56-01). The hold is node-scoped: an unverified candidate
// kernel must stay SECONDARY on every RG until the promotion marker
// confirms it. A single-RG operator reset (`request chassis cluster
// failover reset redundancy-group <N>`, or the gRPC
// cluster-failover-reset:<N> action) is a per-RG rejoin assertion, not a
// node rejoin — clearing the hold here made the whole node
// election-eligible and let it claim primary on every RG before
// xpf-kernel-promote verified the dataplane. The hold is released only by
// the promotion-marker reconcile (ClearKernelUpgradeHold), by
// ResetAllFailover (the orchestrator rejoin via `xpfd upgrade kernel
// rejoin` / RejoinAndConfirm and kernel self-recovery — every configured
// RG, synchronously, preserving the never-both-down property at the
// all-RG scope where it belongs), or by the reboot to known-good where it
// is never re-set. While the hold is set, the recalcWeight election below
// still runs but electRG/electSingleNode keep every RG secondary.
func (m *Manager) ResetFailover(rgID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if m.kernelUpgradeHold {
		slog.Info("cluster: failover reset leaves kernel-upgrade hold in place (single-RG reset is not a node rejoin)", "rg", rgID)
	}
	rg.ManualFailover = false
	rg.forcedSecondary = false
	rg.transferCommitRolePinned = false
	rg.ManualFailoverAt = time.Time{}
	// Drop every piece of transfer-commit state for this RG (#14979, D34-04).
	// ResetFailover is the operator's explicit declaration that the
	// transfer this state describes is over and normal election resumes.
	// Leaving any of it armed means stale transfer authority outlives the
	// reset it was granted under:
	//
	//   - transferOverrides has NO expiry: it re-forces the peer to
	//     SecondaryHold on every heartbeat (#6527/#6656), so electRG takes
	//     its "Peer transfer out" arm and self-elects primary regardless
	//     of what the peer reports — dual-primary if the peer has also
	//     reclaimed (e.g. its own preempt reclaim after this reset).
	//   - peerTransferCommitGraceUntil likewise rewrites every peer
	//     heartbeat to SecondaryHold until it expires (~10s floor).
	//   - localTransferOutHoldUntil is cluster-wide peer-timeout
	//     suppression state (suppressPeerTimeoutForTransferCommitLocked
	//     scans the whole map, not per-RG): one RG's leftover hold
	//     suppresses peer-loss detection for the ENTIRE cluster, and it
	//     also keeps a transferCommitRolePinned secondary parked via
	//     electRG's committed-secondary arm.
	//
	// clearPeerTransferOutOverrideLocked drops the whole transferOverride
	// entry (reqID + peer snapshot together, #17125), so a later abort
	// restore for a pre-reset reqID then no-ops on reqID mismatch.
	m.clearPeerTransferOutOverrideLocked(rgID)
	m.clearAbortedPeerTransferLocked(rgID)
	delete(m.peerTransferCommitGraceUntil, rgID)
	delete(m.localTransferOutHoldUntil, rgID)
	// Drop any armed remote transfer-out lease for this RG, mirroring the
	// ManualFailover / ForceSecondary(ISSU) / ManualFailoverBatch reset paths.
	// The lease's electRG auto-restore is gated on ManualFailover, so a leftover
	// entry is inert once we clear the hold here — but leaving it in the maps
	// lets repeated resets accumulate dormant entries. Clearing it keeps the
	// lease maps in lockstep with ManualFailover on every reset path (#6301).
	m.clearRemoteTransferOutLeaseLocked(rgID)
	// Invalidate any in-flight ManualFailover / ManualFailoverBatch whose
	// pre-failover hook released m.mu: bump the per-RG failover generation so
	// its post-hook re-check abandons the trailing SecondaryHold write instead
	// of clobbering this reset (#5246).
	m.failoverGen[rgID]++
	m.recalcWeight(rg) // restore weight from monitor state + run election
	slog.Info("cluster: failover reset", "rg", rgID)
	return nil
}

// FenceStatus returns the configured fencing action and history of fence events.
func (m *Manager) FenceStatus() (action string, events []HistoryEvent) {
	m.mu.RLock()
	action = m.peerFencing
	m.mu.RUnlock()
	events = m.history.Events(EventFence)
	return
}

// operatorHoldSnapshot records the operator intent that a peer-transfer
// request or the peer-loss clears temporarily clear: the local manual hold,
// the peer transfer-out override (#17125: one transferOverride
// value), and the aborted-request marker. A
// reset that wins while the caller is outside m.mu increments failoverGen;
// the generation check prevents a stale restore from resurrecting that
// newer operator decision (#5246). The restore also leaves any newer hold
// already installed by another operator path untouched.
//
// This is the single snapshot/restore pair for that intent: both the
// peer-transfer abort arms (abortRequestedPeerFailover{,Batch}) and the
// #15211 fence-abort restore in handlePeerTimeout go through it, so a
// guard added here cannot be lost in a hand copy elsewhere (#17117).
type operatorHoldSnapshot struct {
	rg            *RedundancyGroupState
	armed         bool
	at            time.Time
	state         NodeState
	weight        int
	restoreWeight bool
	// forcedSecondary records whether the snapshotted hold was an ISSU
	// drain pin (#16743), so the abort restores the pin with the hold.
	forcedSecondary bool
	override        transferOverride
	hasOverride     bool
	abortedReqID    uint64
	hasAborted      bool
	abortedFence    abortedPeerTransferFence
	hasAbortedFence bool
	generation      uint64
}

// snapshotOperatorHoldLocked captures the operator intent for rgID. The
// hold fields are armed only when ManualFailover is set (mirroring the
// peer-transfer snapshot sites); the override and aborted marker are
// captured independently. An RG removed from m.groups restores NOTHING:
// the restore requires the same RG incarnation for every arm (#17117
// fold; a removed+re-added RG must not inherit the old override). Caller holds m.mu.
func (m *Manager) snapshotOperatorHoldLocked(rgID int) operatorHoldSnapshot {
	snap := operatorHoldSnapshot{generation: m.failoverGen[rgID]}
	if rg, ok := m.groups[rgID]; ok {
		snap.rg = rg
		if rg.ManualFailover {
			snap.armed = true
			snap.at = rg.ManualFailoverAt
			snap.state = rg.State
			snap.weight = rg.Weight
			snap.forcedSecondary = rg.forcedSecondary
			// #10245/#16743: capture restoreWeight BEFORE the caller
			// clears the pin — debtDerivedWeightLocked honours
			// forcedSecondary (returns 0), so computing it after the
			// clear would compare 0 against the real debt weight and
			// mark a pinned hold as monitor-derived.
			snap.restoreWeight = rg.Weight != m.debtDerivedWeightLocked(rg)
		}
	}
	if override, ok := m.transferOverrides[rgID]; ok {
		snap.override, snap.hasOverride = override, true
	}
	if reqID, ok := m.abortedPeerTransferReqID[rgID]; ok {
		snap.abortedReqID, snap.hasAborted = reqID, true
		snap.abortedFence, snap.hasAbortedFence = m.abortedPeerTransferFence[rgID]
	}
	return snap
}

// restoreOperatorHoldLocked restores a snapshot taken by
// snapshotOperatorHoldLocked unless a ResetFailover (or an in-flight
// ForceSecondary supersede) bumped failoverGen after the snapshot — the
// newer operator decision wins and nothing is resurrected (#17117).
//
// Every arm is also gated on the RG incarnation (#18148/#17117-fold):
// the generation check alone cannot see a remove+re-add in the fence
// window, because UpdateConfig's removal purge DELETES the failoverGen
// entry (group_state.go) and the re-add seeds it back at 0. A snapshot
// taken at gen 0 then compares 0==0 on a FRESH incarnation and the
// override/aborted arms (which carry no RG pointer check) would
// resurrect the removed incarnation's no-expiry override onto the new
// RG — the #8435 self-promote/dual-primary class. So a non-nil snapshot
// pointer must still be the live group, and a nil-pointer snapshot
// restores nothing.
//
// The no-capture sites (empty operatorHoldSnapshot{} on the failed-send
// arm, or a hold entry for a peer-transfer caller whose RG still exists)
// preserve their historical behaviour: snapshot capture fills rg, and a
// wholly empty snapshot has no pointer and no arms, so it stays a no-op.
//
// Three cases:
//   - snapshot.rg == nil (no RG captured, e.g. the rg==nil fence entries
//     snapshotted before the peer-loss clears): restore nothing. The old
//     rg==nil override restore is REMOVED: with the purge deleting the
//     gen entry, "no RG at snapshot time" is indistinguishable from
//     "RG removed and re-added in the window", so restoring an override
//     for an absent id could install the removed incarnation's override
//     on a fresh RG.
//   - snapshot.rg != nil && m.groups[rgID] == snapshot.rg: same
//     incarnation; restore the armed hold (unless a newer hold stands)
//     plus the override/aborted arms exactly as before.
//   - snapshot.rg != nil && m.groups[rgID] != snapshot.rg (removed or
//     replaced): restore NOTHING — every arm is suppressed.
//
// Caller holds m.mu.
func (m *Manager) restoreOperatorHoldLocked(rgID int, snapshot operatorHoldSnapshot, eventReason string) {
	if m.failoverGen[rgID] != snapshot.generation {
		return
	}
	// Same-incarnation gate for ALL arms (#18148/#17117-fold): a
	// snapshot with no RG pointer carries no proven incarnation, and a
	// snapshot whose pointer is no longer the live group is stale.
	if snapshot.rg == nil {
		return
	}
	rg, ok := m.groups[rgID]
	if !ok || rg != snapshot.rg {
		return
	}
	if snapshot.hasOverride {
		// Restore the whole transferOverride (#17125): writing it
		// directly puts back the snapshotted reqID + previous peer
		// snapshot together, instead of re-deriving `previous` from
		// the peer view as it stands after the fence wait (the way
		// applyPeerTransferOutOverrideLocked would).
		m.transferOverrides[rgID] = snapshot.override
		if pg, ok := m.peerGroups[rgID]; ok {
			pg.State = StateSecondaryHold
			pg.StateOverriddenLocally = true
			pg.OverrideReason = "transfer-out override"
			m.peerGroups[rgID] = pg
			if rg := m.groups[rgID]; rg != nil {
				rg.PeerPriority = pg.Priority
			}
		}
	}
	if snapshot.hasAborted {
		m.abortedPeerTransferReqID[rgID] = snapshot.abortedReqID
		if snapshot.hasAbortedFence {
			m.abortedPeerTransferFence[rgID] = snapshot.abortedFence
		} else {
			delete(m.abortedPeerTransferFence, rgID)
		}
	}
	if !snapshot.armed {
		return
	}
	if rg.ManualFailover {
		return
	}
	oldState := rg.State
	rg.ManualFailover = true
	rg.forcedSecondary = snapshot.forcedSecondary
	// #16743: a forced hold's weight is pinned 0 regardless of the debt
	// comparison captured at snapshot time.
	if snapshot.restoreWeight || snapshot.forcedSecondary {
		rg.Weight = snapshot.weight
	}
	rg.ManualFailoverAt = snapshot.at
	rg.State = snapshot.state
	if oldState != rg.State {
		m.sendEvent(rg.GroupID, oldState, rg.State, eventReason)
	}
}

// clearAbortedPeerTransferLocked clears the request marker and its lifetime
// mode together. Caller holds m.mu.
func (m *Manager) clearAbortedPeerTransferLocked(rgID int) {
	delete(m.abortedPeerTransferReqID, rgID)
	delete(m.abortedPeerTransferFence, rgID)
}

// preActivateTransfer runs the #18559 make-before-break pre-activation for
// the data RGs (ID > 0) in rgIDs and returns the matching release, or nil
// when there is nothing to release: no hook, no data RG, or the activation
// failed. A failed activation is logged and the transfer proceeds without
// it — the pre-#18559 break-before-make sequence, never a refusal. Called
// WITHOUT m.mu: the hook performs dataplane I/O.
func (m *Manager) preActivateTransfer(activate func([]int) error, release func([]int), rgIDs []int) func() {
	if activate == nil {
		return nil
	}
	data := make([]int, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		if rgID > 0 {
			data = append(data, rgID)
		}
	}
	if len(data) == 0 {
		return nil
	}
	if err := activate(data); err != nil {
		slog.Warn("cluster: transfer pre-activation failed; proceeding break-before-make",
			"rgs", data, "err", err)
		if release != nil {
			release(data)
		}
		return nil
	}
	if release == nil {
		return nil
	}
	return func() { release(data) }
}

// RequestPeerFailover asks the peer to transfer the given RG out of primary,
// making the local node eligible to become primary. Used when
// "request chassis cluster failover redundancy-group N node <local>" is run.
func (m *Manager) RequestPeerFailover(rgID int) error {
	m.mu.Lock()
	rg, ok := m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	// Reserve this RG for the whole request. Without the reservation, a
	// concurrent request could consume the hold after this request clears it,
	// then a late abort could restore the wrong request's snapshot.
	if m.failoverInProgress[rgID] != 0 {
		m.mu.Unlock()
		return fmt.Errorf("failover already in progress for redundancy group %d, please wait", rgID)
	}
	if rg.State == StatePrimary {
		m.mu.Unlock()
		return fmt.Errorf("node is already primary for redundancy group %d", rgID)
	}
	if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
		readySince := "<zero>"
		if !rg.ReadySince.IsZero() {
			readySince = rg.ReadySince.Format(time.RFC3339Nano)
		}
		reasons := append([]string(nil), rg.ReadinessReasons...)
		m.mu.Unlock()
		return fmt.Errorf(
			"local redundancy group %d not ready for explicit failover ready=%t ready_since=%s reasons=%v",
			rgID,
			rg.Ready,
			readySince,
			reasons,
		)
	}
	owner := m.nextFailoverOwnerLocked()
	m.failoverInProgress[rgID] = owner
	fn := m.peerFailoverFn
	commitFn := m.peerFailoverCommitFn
	abortFn := m.peerFailoverAbortFn
	transferReadyFn := m.transferReadinessFn
	peerAlive := m.peerAlive
	localCommitReadyFn := m.localTransferCommitReadyFn
	preActivateFn, preReleaseFn := m.transferPreActivateFn, m.transferPreReleaseFn
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.releaseFailoverLocked(rgID, owner)
		m.mu.Unlock()
	}()

	if fn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer failover not available (sync not connected)")
	}
	if commitFn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer failover commit not available (sync not connected)")
	}
	if transferReadyFn != nil {
		ready, reasons := transferReadyFn(rgID)
		if !ready {
			return fmt.Errorf(
				"local redundancy group %d not transfer-ready for explicit failover reasons=%v",
				rgID,
				append([]string(nil), reasons...),
			)
		}
	}
	// #18559: open local forwarding before the owner demotes, so the
	// traffic it fabric-redirects after its #5640 fence has somewhere to go.
	// Deferred release AFTER the reservation release above is registered, so
	// it runs first on return: by then a successful transfer has applied
	// rg_active through the ordinary promotion and the release is a no-op.
	if release := m.preActivateTransfer(preActivateFn, preReleaseFn, []int{rgID}); release != nil {
		defer release()
	}
	reqID, err := fn(rgID)
	if err != nil {
		// #16592: the owner may already be holding without a successful
		// fence. Retain the abort marker before releasing our reservation
		// and send the bound abort. The local manual hold is unchanged.
		if reqID != 0 {
			m.abortRequestedPeerFailover(rgID, reqID, operatorHoldSnapshot{}, abortFn, true)
		}
		return err
	}
	var hold operatorHoldSnapshot
	m.mu.Lock()
	rg, ok = m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	// Preserve a local manual-failover hold until the peer has explicitly
	// acknowledged the transfer-out request. Preflight rejection or request-send
	// failure must not silently release the existing transfer-out state.
	if rg.ManualFailover {
		hold = m.snapshotOperatorHoldLocked(rgID)
		// The peer-transfer abort rolls the override back through its own
		// reqID-matched restorePeerTransferOutOverrideLocked; the hold
		// snapshot's override/aborted arms belong to the fence-abort
		// caller and must not replay here.
		hold.override, hold.hasOverride = transferOverride{}, false
		hold.abortedReqID, hold.hasAborted = 0, false
		hold.abortedFence, hold.hasAbortedFence = abortedPeerTransferFence{}, false
		rg.ManualFailover = false
		rg.forcedSecondary = false
		rg.ManualFailoverAt = time.Time{}
		m.recalcWeight(rg)
	}
	m.mu.Unlock()
	if err := m.commitRequestedPeerFailover(rgID, reqID); err != nil {
		// The commit applies the transfer override before running the
		// election. Roll back the reqID-matched override and restore the
		// preexisting local manual-failover hold on every commit failure.
		m.abortRequestedPeerFailover(rgID, reqID, hold, abortFn, false)
		return err
	}
	if localCommitReadyFn != nil {
		if err := localCommitReadyFn([]int{rgID}); err != nil {
			m.abortRequestedPeerFailover(rgID, reqID, hold, abortFn, false)
			return err
		}
	}
	if err := commitFn(rgID, reqID); err != nil {
		m.abortRequestedPeerFailover(rgID, reqID, hold, abortFn, false)
		return err
	}
	m.notePeerTransferCommitted(rgID)
	return nil
}

func (m *Manager) commitRequestedPeerFailover(rgID int, reqID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
		readySince := "<zero>"
		if !rg.ReadySince.IsZero() {
			readySince = rg.ReadySince.Format(time.RFC3339Nano)
		}
		return fmt.Errorf(
			"redundancy group %d lost takeover readiness before transfer commit ready=%t ready_since=%s reasons=%v",
			rgID,
			rg.Ready,
			readySince,
			append([]string(nil), rg.ReadinessReasons...),
		)
	}

	m.applyPeerTransferOutOverrideLocked(rgID, reqID)
	m.clearAbortedPeerTransferLocked(rgID)
	delete(m.peerTransferCommitGraceUntil, rgID)
	delete(m.localTransferOutHoldUntil, rgID)
	peerGroup := m.peerGroups[rgID]

	m.runElection()
	if rg.State != StatePrimary {
		return fmt.Errorf(
			"failed to commit redundancy group %d primary ownership local_state=%s peer_state=%s ready=%t reasons=%v",
			rgID,
			rg.State,
			peerGroup.State,
			rg.Ready,
			append([]string(nil), rg.ReadinessReasons...),
		)
	}
	return nil
}

func (m *Manager) abortRequestedPeerFailover(rgID int, reqID uint64, hold operatorHoldSnapshot, abortFn func(rgID int, reqID uint64) error, fenceUntilOwnerPrimary bool) {
	// #15164: record the aborted reqID BEFORE any election can re-run, so a
	// heartbeat that still advertises the owner's secondary-hold under this
	// request cannot re-promote us via "Peer transfer out". Then notify the
	// owner (best-effort, outside m.mu) so it restores promptly; its lease
	// remains the fallback if the frame is lost.
	// #17713: a failed pre-commit request retains its promotion fence through
	// ordinary-secondary owner-restoration heartbeats. Those heartbeats do not
	// prove ownership restoration when ordinary election leaves a higher-
	// priority requester as the only eligible primary. The marker resolves
	// only after a newer PRIMARY heartbeat follows an observed hold, a later
	// transfer is acknowledged, or reset/peer loss/RG removal ends the epoch.
	// Post-commit aborts use the legacy hold-only expiry because they belong to
	// a different transfer epoch.
	//
	// #16818: the election below must run UNCONDITIONALLY. The commit may
	// already have promoted this node, and the #16592 aborted-marker arm in
	// electRG is what demotes it ("Peer transfer aborted"). Re-running only
	// when a peer snapshot was restored left the outcome to that snapshot:
	// restoring the pre-request PRIMARY snapshot made the demotion a
	// dual-active decision a higher-priority requester wins, and restoring
	// the owner's hold snapshot (hold heartbeat seen before the commit)
	// ran no election at all — so RequestPeerFailover reported failure
	// while this node kept the RG. Demoting here, under the marker and
	// before the abort frame can restore the owner, also closes the race
	// where the restored heartbeat arrives before any election applied it.
	m.mu.Lock()
	m.abortedPeerTransferReqID[rgID] = reqID
	if fenceUntilOwnerPrimary {
		peerFence := abortedPeerTransferFence{}
		if peerGroup, ok := m.peerGroups[rgID]; ok {
			peerFence = abortedPeerTransferFence{
				heartbeatSession:  peerGroup.heartbeatSession,
				heartbeatSequence: peerGroup.heartbeatSequence,
				sawHold:           peerGroup.State == StateSecondaryHold,
			}
		}
		m.abortedPeerTransferFence[rgID] = peerFence
	} else {
		delete(m.abortedPeerTransferFence, rgID)
	}
	if m.restorePeerTransferOutOverrideLocked(rgID, reqID) {
		delete(m.peerTransferCommitGraceUntil, rgID)
	}
	m.restoreOperatorHoldLocked(rgID, hold, "Manual failover restored after failed peer transfer")
	m.runElection()
	m.mu.Unlock()
	if abortFn != nil {
		if err := abortFn(rgID, reqID); err != nil {
			slog.Warn("cluster: peer failover abort send failed; owner lease remains as fallback", "rg", rgID, "req_id", reqID, "err", err)
		}
	}
}

func (m *Manager) notePeerTransferCommitted(rgID int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.clearPeerTransferOutOverrideLocked(rgID)
	m.clearAbortedPeerTransferLocked(rgID)
	if rg := m.groups[rgID]; rg != nil {
		rg.transferCommitRolePinned = true
		rg.transferCommitRole = StatePrimary
	}
	m.peerTransferCommitGraceUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
	peerGroup, ok := m.peerGroups[rgID]
	if !ok {
		return
	}
	peerGroup.State = StateSecondaryHold
	m.peerGroups[rgID] = peerGroup
}

// =============================================================================
// Owner-side transfer-out lease (#5079).
//
// A peer-requested transfer-out demotes this node to secondary-hold BEFORE the
// requester runs its own post-ACK commit checks. If a requester-side step fails
// after the ACK, the requester rolls back only its LOCAL override
// (abortRequestedPeerFailover) and sends no abort frame — and if the requester
// crashes or the fabric drops, no commit ever arrives either. Without a bound
// the demoted owner sits in secondary-hold forever while its peer is a healthy
// secondary, stranding the cluster with no primary (both nodes secondary). The
// existing dual-resign guard in electRG does NOT rescue this case: it only
// clears ManualFailover when the peer itself is resigned (weight 0) or in
// secondary-hold, not when the requester aborted back to a healthy secondary.
//
// The lease is armed when a REMOTE failover request demotes the RG and is
// cleared on the matching commit (reqID-bound). If it expires with no commit,
// electRG restores the owner. A local operator ManualFailover / ISSU
// ForceSecondary clears any stale lease so their deliberate holds are never
// auto-restored.
// =============================================================================

// SetRemoteTransferOutLeaseDuration overrides how long an armed remote
// transfer-out lease survives without a commit before electRG restores the
// owner. The daemon sizes this above its configured local commit-ready settle
// window plus the commit round-trip so the lease never fires on an in-flight
// commit. Values below minRemoteTransferOutLease are floored.
func (m *Manager) SetRemoteTransferOutLeaseDuration(d time.Duration) {
	if d < minRemoteTransferOutLease {
		d = minRemoteTransferOutLease
	}
	m.mu.Lock()
	m.remoteTransferOutLease = d
	m.mu.Unlock()
}

// ArmRemoteTransferOutLease binds an auto-restore lease to each RG that a peer
// request has just demoted, so a requester-side post-ACK abort/crash cannot
// strand the owner secondary (#5079). Only RGs actually holding ManualFailover
// are armed — a demotion superseded by a concurrent reset (which cleared the
// hold) leaves no lease, so the owner is never spuriously restored.
func (m *Manager) ArmRemoteTransferOutLease(rgIDs []int, reqID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	until := time.Now().Add(m.remoteTransferOutLease)
	for _, rgID := range rgIDs {
		rg, ok := m.groups[rgID]
		if !ok || !rg.ManualFailover {
			continue
		}
		m.remoteTransferOutLeaseUntil[rgID] = until
		m.remoteTransferOutLeaseReqID[rgID] = reqID
		if m.remoteTransferOutLeaseChannel == nil {
			m.remoteTransferOutLeaseChannel = make(map[int]transferChannelBinding)
		}
		binding := m.captureTransferChannelLocked()
		m.remoteTransferOutLeaseChannel[rgID] = binding
		slog.Info("cluster: armed remote transfer-out lease",
			"rg", rgID, "req_id", reqID, "expires_in", m.remoteTransferOutLease.String(),
			"bound_to_sync_connection", binding.src != nil)
	}
}

// RemoteTransferOutStillHeld reports whether every RG in rgIDs is still parked
// for the peer's request reqID: the remote transfer-out lease is armed for
// reqID and the manual hold is still set, so the RG is not primary (#18521
// review round 3). The applied-ack is sent only while this holds
// (SessionSync.TransferOutStillHeld). It closes the window where the hold's
// connection binding broke during a slow demotion actuation, the 2s rescue
// re-promoted this owner, and the actuation barrier — which resolves on the
// queued demotion edge regardless of the Manager's later state — let
// "applied" go out anyway, promoting the requester beside it. What remains
// is the ack's own flight: a binding that breaks after the ack is sent, while
// the requester has not yet promoted and still advertises its hold, can let
// the rescue re-promote this owner until the requester's commit is refused
// (FinalizePeerTransferOut) and it aborts.
func (m *Manager) RemoteTransferOutStillHeld(rgIDs []int, reqID uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(rgIDs) == 0 {
		return false
	}
	// The hold is the whole test of "not primary": ManualFailover elects the
	// RG out of primary in the same critical section that sets it, and every
	// path that re-promotes it (the rescue, an abort, a reset) clears it.
	for _, rgID := range rgIDs {
		rg, ok := m.groups[rgID]
		cur, leased := m.remoteTransferOutLeaseReqID[rgID]
		if !ok || !leased || cur != reqID || !rg.ManualFailover {
			return false
		}
	}
	return true
}

// ClearRemoteTransferOutLease disarms the lease for an RG once the transfer-out
// is committed. It is reqID-bound: a stale/duplicate commit carrying an older
// request ID must not clear a newer request's lease. A commit for the current
// lease's reqID always clears it.
func (m *Manager) ClearRemoteTransferOutLease(rgID int, reqID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.remoteTransferOutLeaseReqID[rgID]; ok && cur != reqID {
		return
	}
	m.clearRemoteTransferOutLeaseLocked(rgID)
}

func (m *Manager) clearRemoteTransferOutLeaseLocked(rgID int) {
	delete(m.remoteTransferOutLeaseUntil, rgID)
	delete(m.remoteTransferOutLeaseReqID, rgID)
	delete(m.remoteTransferOutLeaseChannel, rgID)
}

// transferChannelBinding identifies the session-sync connection set a
// remote transfer-out request was handled on (#18521 review round 2): the
// published sync source and its connection-slot removal generation at the
// moment the lease was armed. src is nil when no connection was up.
type transferChannelBinding struct {
	src     peerSyncSource
	gen     uint64
	dropped bool // the binding was observed broken (logged once)
}

// captureTransferChannelLocked records the current transfer channel. It runs
// inside OnRemoteFailover, i.e. on the receive loop of the connection that
// delivered the request, so the connection set it captures contains that
// connection. Caller holds m.mu.
func (m *Manager) captureTransferChannelLocked() transferChannelBinding {
	if m.peerSync == nil || !m.peerSync.IsConnected() {
		return transferChannelBinding{}
	}
	return transferChannelBinding{src: m.peerSync, gen: m.peerSync.TransferChannelGen()}
}

// transferChannelIntactLocked reports whether the connection set captured
// when rgID's lease was armed is still the one installed: same published
// source, still connected, and no installed connection removed from its slot
// since (#18521 review round 2).
//
// This, and not "some connection is up", is the condition under which the
// requester's commit or abort can still reach us. Both frames are written once
// and never re-sent; a frame queued on a connection that was then torn down
// (a writer's write-timeout teardown, the receive watchdog, a supersede) is
// gone, and a FRESH connection cannot deliver it. Keying the hold on
// IsConnected let a redial that beat the owner's next election re-arm the
// lease-long hold while the requester sat in its restored hold: no primary
// for up to the whole lease. A broken binding returns the owner to the
// pre-#18521 floor — the 2s dual-resign rescue and the lease expiry — which
// fires only while the requester advertises secondary-hold or weight 0, so it
// does not re-promote the owner over a requester that already promoted itself
// and is waiting for its commit ACK on the new connection. It does fire while
// the requester is still in its pre-request hold waiting for our applied-ACK;
// RemoteTransferOutStillHeld then refuses that ACK (review round 3), leaving
// only the window of an ACK already in flight when the binding breaks.
//
// Removals only: an empty slot that fills (the other fabric connecting)
// removes nothing, so it keeps the binding. Caller holds m.mu.
func (m *Manager) transferChannelIntactLocked(rgID int) bool {
	b, ok := m.remoteTransferOutLeaseChannel[rgID]
	if !ok || b.dropped || b.src == nil {
		return false
	}
	if b.src == m.peerSync && m.peerSync.IsConnected() && m.peerSync.TransferChannelGen() == b.gen {
		return true
	}
	b.dropped = true
	m.remoteTransferOutLeaseChannel[rgID] = b
	slog.Info("cluster: the session-sync connection that carried the remote transfer-out request "+
		"is gone; its commit or abort can no longer arrive, so the owner hold falls back to the "+
		"dual-resign rescue and the lease expiry (#18521)",
		"rg", rgID, "req_id", m.remoteTransferOutLeaseReqID[rgID])
	return false
}

// AbortRemoteTransferOut restores this node after an abandoned transfer-out,
// including a failed/timed-out ACK (#15164/#16592). It is reqID-bound exactly
// like the lease clear: only the request that armed the current lease may
// abort it, so a stale abort cannot restore an owner demoted by a newer
// request. Restoring clears the manual hold, restores monitor-derived
// weight, and re-runs election promptly instead of waiting for lease
// expiry. A committed transfer has already cleared the lease, so a late
// abort after commit is a no-op.
func (m *Manager) AbortRemoteTransferOut(rgID int, reqID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	cur, leased := m.remoteTransferOutLeaseReqID[rgID]
	if !leased || cur != reqID {
		return nil
	}
	m.clearRemoteTransferOutLeaseLocked(rgID)
	if !rg.ManualFailover {
		return nil
	}
	rg.ManualFailover = false
	rg.forcedSecondary = false
	rg.ManualFailoverAt = time.Time{}
	m.manualFailoverRestoreWeightLocked(rg)
	slog.Info("cluster: remote transfer-out aborted by requester, restoring owner", "rg", rgID, "req_id", reqID)
	m.runElection()
	return nil
}

// AbortRemoteTransferOutBatch is the multi-RG form of AbortRemoteTransferOut.
func (m *Manager) AbortRemoteTransferOutBatch(rgIDs []int, reqID uint64) error {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return m.AbortRemoteTransferOut(ids[0], reqID)
	}
	for _, rgID := range ids {
		if err := m.AbortRemoteTransferOut(rgID, reqID); err != nil {
			return err
		}
	}
	return nil
}

// debtDerivedWeightLocked returns the monitor-derived weight for an RG without
// changing it. Caller must hold m.mu.
//
// #16743: while the ISSU drain pin is set this returns 0, so every restore
// path that recomputes weight through here (dual-resign guard, lease
// expiry, peer loss, remote-transfer abort) keeps the drained weight until
// the pin itself is cleared — ResetFailover clears the flag BEFORE its
// recalcWeight, so the operator reset still restores the real weight.
func (m *Manager) debtDerivedWeightLocked(rg *RedundancyGroupState) int {
	if rg.forcedSecondary {
		return 0
	}
	return rgWeightFromDebt(m.monitorDebtTotalLocked(rg))
}

// manualFailoverRestoreWeightLocked recomputes an RG's monitor-derived weight
// after ManualFailover is cleared. It is used by the dual-resign guard and the
// transfer-out lease expiry in electRG, and by handlePeerTimeout's peer-loss
// clear (#9640). It deliberately does NOT run election: in electRG
// recalcWeight would recurse back into electRG, and on peer loss its
// electSingleNode would promote every group before the disable-rg-confirmed
// fence. Caller holds m.mu.
func (m *Manager) manualFailoverRestoreWeightLocked(rg *RedundancyGroupState) {
	rg.Weight = m.debtDerivedWeightLocked(rg)
}

// FinalizePeerTransferOut completes a previously acknowledged transfer-out
// after the peer commits ownership on the sync channel.
func (m *Manager) FinalizePeerTransferOut(rgID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	if rg.State == StatePrimary {
		return fmt.Errorf("%w: redundancy group %d still primary locally", ErrRemoteFailoverRejected, rgID)
	}

	oldState := rg.State
	rg.ManualFailover = false
	rg.forcedSecondary = false
	rg.ManualFailoverAt = time.Time{}
	rg.State = StateSecondary
	rg.transferCommitRolePinned = true
	rg.transferCommitRole = StateSecondary
	// A completed transfer-out invalidates any stale inbound-transfer view
	// from the previous owner direction. If we keep forcing the peer into
	// secondary-hold here, the next heartbeat can immediately re-elect the
	// old owner during rapid failback/failover sequences.
	m.clearPeerTransferOutOverrideLocked(rgID)
	m.clearAbortedPeerTransferLocked(rgID)
	delete(m.peerTransferCommitGraceUntil, rgID)
	m.localTransferOutHoldUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
	if oldState != rg.State {
		m.sendEvent(rg.GroupID, oldState, rg.State, "Peer transfer committed")
	}
	return nil
}

// =============================================================================
// Multi-RG (batch) manual failover and transfer protocol.
//
// Folded in from the former failover_batch.go (#1541, plan v3) so the entire
// manual-failover locking domain — single-RG, batch, and the shared *Locked
// helpers — lives in one file. Gemini r2: "the entire manual-failover locking
// domain belongs in one file."
// =============================================================================

// IsSupportedClusterNodeID reports whether nodeID is a valid chassis node.
// Cluster failover targets are currently limited to the two chassis nodes.
func IsSupportedClusterNodeID(nodeID int) bool {
	return nodeID == 0 || nodeID == 1
}

func normalizeFailoverRGIDs(rgIDs []int) ([]int, error) {
	if len(rgIDs) == 0 {
		return nil, fmt.Errorf("no redundancy groups specified")
	}
	seen := make(map[int]struct{}, len(rgIDs))
	ids := make([]int, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		if _, ok := seen[rgID]; ok {
			continue
		}
		seen[rgID] = struct{}{}
		ids = append(ids, rgID)
	}
	sort.Ints(ids)
	return ids, nil
}

func failoverBatchKey(rgIDs []int) string {
	if len(rgIDs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rgIDs))
	for _, rgID := range rgIDs {
		parts = append(parts, strconv.Itoa(rgID))
	}
	return strings.Join(parts, ",")
}

// BatchFailoverResult reports, per redundancy group, what a batch request
// actually did (#8000).
//
// Superseded is not a failure list. A member lands there when a concurrent
// ResetFailover won the race for it (#5246) — the reset is the operator's newer
// intent and the skip is correct. What was missing is that the batch returned
// nil either way, so a caller could not tell a full handoff from a partial one,
// and the fence barrier armed for a skipped member was left for the applied-ack
// to time out on.
type BatchFailoverResult struct {
	// Applied are the RGs this request placed in SecondaryHold.
	Applied []int
	// Superseded are the RGs a concurrent reset claimed. No error, no change.
	Superseded []int
}

// Partial reports whether any member was superseded, i.e. the batch did NOT do
// what it was asked in full.
func (r BatchFailoverResult) Partial() bool { return len(r.Superseded) > 0 }

// ManualFailoverBatch forces multiple redundancy groups to transfer out of
// primary together. Used for full data-plane handoff so a paired move does not
// transiently pass through split ownership.
//
// #8000: returns the per-RG outcome. The error is reserved for a request that
// failed — an unknown member, a rejected pre-hook — and never for a supersede,
// which is a correct outcome the caller must still be able to see.
func (m *Manager) ManualFailoverBatch(rgIDs []int) (BatchFailoverResult, error) {
	var res BatchFailoverResult
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return res, err
	}
	if len(ids) == 1 {
		outcome, err := m.ManualFailover(ids[0])
		if err != nil {
			return res, err
		}
		if outcome == FailoverSuperseded {
			res.Superseded = append(res.Superseded, ids[0])
		} else {
			res.Applied = append(res.Applied, ids[0])
		}
		return res, nil
	}

	m.mu.Lock()
	resv, rerr := m.reserveLocked(ids, nil, false, false)
	if rerr != nil {
		m.mu.Unlock()
		return res, rerr
	}
	staleFn := m.peerConfigStaleFn
	m.mu.Unlock()

	if err := peerConfigStaleRefusal(staleFn, fmt.Sprintf("manual failover of redundancy groups %v", ids)); err != nil {
		m.mu.Lock()
		m.releaseReservationLocked(resv)
		m.mu.Unlock()
		return res, err
	}

	preHookErr := m.runPreHook(ids, "manual failover batch")

	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.releaseReservationLocked(resv)

	if preHookErr != nil {
		return res, preHookErr
	}

	// #7176: member removed during unlocked window must be reported before
	// any mutation; #17120: remove+re-add (pointer changed, gen may be 0)
	// is the same "barrier ran for another incarnation" case.
	missing, superseded, changed, changedSet := m.revalidateLocked(resv)
	if len(missing) > 0 {
		return res, fmt.Errorf("redundancy group %d not found", missing[0])
	}
	if changedSet {
		return res, fmt.Errorf("redundancy group %d not found", changed)
	}
	supersededSet := make(map[int]bool, len(superseded))
	for _, rgID := range superseded {
		supersededSet[rgID] = true
	}

	now := time.Now()
	for _, rgID := range ids {
		rg := m.groups[rgID]
		if supersededSet[rgID] {
			slog.Info("cluster: manual failover batch member superseded by reset, skipping", "rg", rgID)
			res.Superseded = append(res.Superseded, rgID)
			continue
		}
		oldState := rg.State
		m.clearRemoteTransferOutLeaseLocked(rgID)
		rg.transferCommitRolePinned = false
		res.Applied = append(res.Applied, rgID)
		rg.ManualFailover = true
		rg.ManualFailoverAt = now
		rg.State = StateSecondaryHold
		rg.FailoverCount++
		if oldState != rg.State {
			m.sendEvent(rg.GroupID, oldState, rg.State, "Manual failover batch")
		}
	}
	slog.Info("cluster: manual failover batch", "rgs", ids)
	return res, nil
}

// RequestPeerFailoverBatch asks the peer to transfer multiple redundancy
// groups out of primary and commits local ownership in one election pass.
func (m *Manager) RequestPeerFailoverBatch(rgIDs []int) error {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return m.RequestPeerFailover(ids[0])
	}

	m.mu.Lock()
	for _, rgID := range ids {
		rg, ok := m.groups[rgID]
		if !ok {
			m.mu.Unlock()
			return fmt.Errorf("redundancy group %d not found", rgID)
		}
		// Validate all members before claiming any ownership, so a rejected
		// batch never leaves a partial reservation behind.
		if m.failoverInProgress[rgID] != 0 {
			m.mu.Unlock()
			return fmt.Errorf("failover already in progress for redundancy groups %v, please wait", ids)
		}
		if rg.State == StatePrimary {
			m.mu.Unlock()
			return fmt.Errorf("node is already primary for redundancy groups %v", ids)
		}
		if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
			readySince := "<zero>"
			if !rg.ReadySince.IsZero() {
				readySince = rg.ReadySince.Format(time.RFC3339Nano)
			}
			reasons := append([]string(nil), rg.ReadinessReasons...)
			m.mu.Unlock()
			return fmt.Errorf(
				"local redundancy group %d not ready for explicit failover ready=%t ready_since=%s reasons=%v",
				rgID,
				rg.Ready,
				readySince,
				reasons,
			)
		}
	}
	batchOwners := make(map[int]uint64, len(ids))
	for _, rgID := range ids {
		owner := m.nextFailoverOwnerLocked()
		m.failoverInProgress[rgID] = owner
		batchOwners[rgID] = owner
	}
	fn := m.peerFailoverBatchFn
	commitFn := m.peerFailoverCommitBatchFn
	abortFn := m.peerFailoverAbortBatchFn
	transferReadyFn := m.transferReadinessFn
	peerAlive := m.peerAlive
	localCommitReadyFn := m.localTransferCommitReadyFn
	preActivateFn, preReleaseFn := m.transferPreActivateFn, m.transferPreReleaseFn
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		for _, rgID := range ids {
			m.releaseFailoverLocked(rgID, batchOwners[rgID])
		}
		m.mu.Unlock()
	}()

	if fn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer batch failover not available (sync not connected)")
	}
	if commitFn == nil {
		if !peerAlive {
			return fmt.Errorf("peer not alive — cannot request failover")
		}
		return fmt.Errorf("peer batch failover commit not available (sync not connected)")
	}
	if transferReadyFn != nil {
		for _, rgID := range ids {
			ready, reasons := transferReadyFn(rgID)
			if !ready {
				return fmt.Errorf(
					"local redundancy group %d not transfer-ready for explicit failover reasons=%v",
					rgID,
					append([]string(nil), reasons...),
				)
			}
		}
	}

	// #18559: batch form of the make-before-break pre-activation above.
	if release := m.preActivateTransfer(preActivateFn, preReleaseFn, ids); release != nil {
		defer release()
	}
	reqID, err := fn(ids)
	if err != nil {
		// #16592: batch form of the single-RG request-ack failure above.
		if reqID != 0 {
			m.abortRequestedPeerFailoverBatch(ids, reqID, nil, abortFn, true)
		}
		return err
	}

	holdSnapshots := make(map[int]operatorHoldSnapshot, len(ids))
	m.mu.Lock()
	for _, rgID := range ids {
		rg := m.groups[rgID]
		if rg != nil && rg.ManualFailover {
			snap := m.snapshotOperatorHoldLocked(rgID)
			// As in the single-RG twin: the batch abort rolls the override
			// back through its own reqID-matched restore; the fence-abort
			// override/aborted arms must not replay here.
			snap.override, snap.hasOverride = transferOverride{}, false
			snap.abortedReqID, snap.hasAborted = 0, false
			snap.abortedFence, snap.hasAbortedFence = abortedPeerTransferFence{}, false
			holdSnapshots[rgID] = snap
			rg.ManualFailover = false
			rg.forcedSecondary = false
			rg.ManualFailoverAt = time.Time{}
			m.recalcWeight(rg)
		}
	}
	m.mu.Unlock()

	if err := m.commitRequestedPeerFailoverBatch(ids, reqID); err != nil {
		m.abortRequestedPeerFailoverBatch(ids, reqID, holdSnapshots, abortFn, false)
		return err
	}
	if localCommitReadyFn != nil {
		if err := localCommitReadyFn(ids); err != nil {
			m.abortRequestedPeerFailoverBatch(ids, reqID, holdSnapshots, abortFn, false)
			return err
		}
	}
	if err := commitFn(ids, reqID); err != nil {
		m.abortRequestedPeerFailoverBatch(ids, reqID, holdSnapshots, abortFn, false)
		return err
	}
	m.notePeerTransferCommittedBatch(ids)
	return nil
}

func (m *Manager) commitRequestedPeerFailoverBatch(rgIDs []int, reqID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range rgIDs {
		rg, ok := m.groups[rgID]
		if !ok {
			return fmt.Errorf("redundancy group %d not found", rgID)
		}
		if !rg.IsReadyForTakeover(m.takeoverHoldTime) {
			readySince := "<zero>"
			if !rg.ReadySince.IsZero() {
				readySince = rg.ReadySince.Format(time.RFC3339Nano)
			}
			return fmt.Errorf(
				"redundancy group %d lost takeover readiness before transfer commit ready=%t ready_since=%s reasons=%v",
				rgID,
				rg.Ready,
				readySince,
				append([]string(nil), rg.ReadinessReasons...),
			)
		}
	}

	for _, rgID := range rgIDs {
		m.applyPeerTransferOutOverrideLocked(rgID, reqID)
		m.clearAbortedPeerTransferLocked(rgID)
		delete(m.peerTransferCommitGraceUntil, rgID)
		delete(m.localTransferOutHoldUntil, rgID)
	}

	m.runElection()
	for _, rgID := range rgIDs {
		rg := m.groups[rgID]
		peerGroup := m.peerGroups[rgID]
		if rg == nil || rg.State == StatePrimary {
			continue
		}
		return fmt.Errorf(
			"failed to commit redundancy groups %v primary ownership local_rg=%d local_state=%s peer_state=%s ready=%t reasons=%v",
			rgIDs,
			rgID,
			rg.State,
			peerGroup.State,
			rg.Ready,
			append([]string(nil), rg.ReadinessReasons...),
		)
	}
	return nil
}

func (m *Manager) abortRequestedPeerFailoverBatch(rgIDs []int, reqID uint64, holds map[int]operatorHoldSnapshot, abortFn func(rgIDs []int, reqID uint64) error, fenceUntilOwnerPrimary bool) {
	// #16818: batch form of abortRequestedPeerFailover — the election must
	// run unconditionally so the aborted-marker arm demotes every RG the
	// batch commit promoted, whatever snapshot the override restore left.
	// #17713: only failed pre-commit requests retain the marker through
	// restored secondary heartbeats; post-commit aborts use the legacy
	// hold-only expiry.
	m.mu.Lock()
	for _, rgID := range rgIDs {
		m.abortedPeerTransferReqID[rgID] = reqID
		if fenceUntilOwnerPrimary {
			peerFence := abortedPeerTransferFence{}
			if peerGroup, ok := m.peerGroups[rgID]; ok {
				peerFence = abortedPeerTransferFence{
					heartbeatSession:  peerGroup.heartbeatSession,
					heartbeatSequence: peerGroup.heartbeatSequence,
					sawHold:           peerGroup.State == StateSecondaryHold,
				}
			}
			m.abortedPeerTransferFence[rgID] = peerFence
		} else {
			delete(m.abortedPeerTransferFence, rgID)
		}
		if m.restorePeerTransferOutOverrideLocked(rgID, reqID) {
			delete(m.peerTransferCommitGraceUntil, rgID)
		}
	}
	for _, rgID := range rgIDs {
		m.restoreOperatorHoldLocked(rgID, holds[rgID], "Manual failover restored after failed peer transfer")
	}
	m.runElection()
	m.mu.Unlock()
	if abortFn != nil {
		if err := abortFn(rgIDs, reqID); err != nil {
			slog.Warn("cluster: peer failover batch abort send failed; owner lease remains as fallback", "rgs", rgIDs, "req_id", reqID, "err", err)
		}
	}
}

func (m *Manager) notePeerTransferCommittedBatch(rgIDs []int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range rgIDs {
		m.clearPeerTransferOutOverrideLocked(rgID)
		m.clearAbortedPeerTransferLocked(rgID)
		if rg := m.groups[rgID]; rg != nil {
			rg.transferCommitRolePinned = true
			rg.transferCommitRole = StatePrimary
		}
		m.peerTransferCommitGraceUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
		peerGroup, ok := m.peerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.State = StateSecondaryHold
		m.peerGroups[rgID] = peerGroup
	}
}

// FinalizePeerTransferOutBatch completes a previously acknowledged multi-RG
// transfer after the peer commits ownership on the sync channel.
func (m *Manager) FinalizePeerTransferOutBatch(rgIDs []int) error {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return m.FinalizePeerTransferOut(ids[0])
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range ids {
		rg, ok := m.groups[rgID]
		if !ok {
			return fmt.Errorf("redundancy group %d not found", rgID)
		}
		if rg.State == StatePrimary {
			return fmt.Errorf("%w: redundancy group %d still primary locally", ErrRemoteFailoverRejected, rgID)
		}
	}

	for _, rgID := range ids {
		rg := m.groups[rgID]
		oldState := rg.State
		rg.ManualFailover = false
		rg.forcedSecondary = false
		rg.ManualFailoverAt = time.Time{}
		rg.State = StateSecondary
		rg.transferCommitRolePinned = true
		rg.transferCommitRole = StateSecondary
		// Clear stale inbound-transfer markers from the previous direction
		// before we park this node as the old owner. Otherwise the next peer
		// heartbeat can still force the peer into secondary-hold and snap the
		// RG back during rapid alternating moves.
		m.clearPeerTransferOutOverrideLocked(rgID)
		m.clearAbortedPeerTransferLocked(rgID)
		delete(m.peerTransferCommitGraceUntil, rgID)
		m.localTransferOutHoldUntil[rgID] = time.Now().Add(m.transferCommitGracePeriodLocked())
		if oldState != rg.State {
			m.sendEvent(rg.GroupID, oldState, rg.State, "Peer transfer committed batch")
		}
	}
	return nil
}

// =============================================================================
// Transfer-commit state machine *Locked helpers.
//
// All callers (single-RG, batch, and the heartbeat-driven peer-state apply
// helper below) live in this file. heartbeat_manager.go::handlePeerTimeout
// calls suppressPeerTimeoutForTransferCommitLocked across the file boundary
// — that is the one cross-file dependency by design.
// =============================================================================

func (m *Manager) applyPeerTransferOutOverrideLocked(rgID int, reqID uint64) {
	previous, ok := m.peerGroups[rgID]
	m.transferOverrides[rgID] = transferOverride{
		reqID: reqID,
		previous: peerGroupSnapshot{
			state:   previous,
			present: ok,
		},
	}
	peerGroup := previous
	peerGroup.GroupID = rgID
	peerGroup.State = StateSecondaryHold
	// #7367: mark the substitution so `show chassis cluster status` can
	// distinguish this from a peer that actually reported secondary-hold.
	// The State value and every election consequence are unchanged.
	peerGroup.StateOverriddenLocally = true
	peerGroup.OverrideReason = "transfer-out override"
	m.peerGroups[rgID] = peerGroup
	if rg := m.groups[rgID]; rg != nil {
		rg.PeerPriority = peerGroup.Priority
	}
}

func (m *Manager) clearPeerTransferOutOverrideLocked(rgID int) {
	delete(m.transferOverrides, rgID)
}

func (m *Manager) restorePeerTransferOutOverrideLocked(rgID int, reqID uint64) bool {
	override, ok := m.transferOverrides[rgID]
	if !ok || override.reqID != reqID {
		return false
	}
	delete(m.transferOverrides, rgID)
	snapshot := override.previous
	if snapshot.present {
		// A fresh heartbeat can race this restore and overwrite peerGroups
		// with newer live state. If that happens we may briefly put the older
		// snapshot back here, but the next heartbeat corrects it again.
		m.peerGroups[rgID] = snapshot.state
	} else {
		delete(m.peerGroups, rgID)
	}
	if rg := m.groups[rgID]; rg != nil {
		if snapshot.present {
			rg.PeerPriority = snapshot.state.Priority
		} else {
			rg.PeerPriority = 0
		}
	}
	return true
}

// liveHeartbeatTiming returns the interval/threshold the RUNNING heartbeat
// is actually using, which is NOT necessarily the committed configuration.
// StartHeartbeat snapshots m.hbInterval/m.hbThreshold into the sender and
// receiver (heartbeat_manager.go), and UpdateConfig then rewrites the
// manager fields on every commit — but nothing restarts the heartbeat for a
// timing change, so after `set chassis cluster heartbeat-interval` the wire
// keeps the OLD cadence and the receiver keeps declaring the peer dead at
// the OLD threshold*interval until some other event (a VRF rebind, a comms
// restart) happens to rebuild it.
//
// #5081: every derived duration that has to cover dead-peer detection must
// therefore be sized from the live values, not the desired ones. The
// receiver's threshold/interval are written once in newHeartbeatReceiver and
// never mutated; only the m.hbReceiver pointer is, and that is written under
// m.mu, so this read is race-free.
//
// Falls back to the desired values when no heartbeat is running (standalone,
// pre-bringup, or between StopHeartbeat and StartHeartbeat) — there is no
// live cadence to be wrong about, and the next StartHeartbeat will adopt
// exactly these.
func (m *Manager) liveHeartbeatTimingLocked() (time.Duration, int) {
	if r := m.hbReceiver; r != nil && r.interval > 0 && r.threshold > 0 {
		return r.interval, r.threshold
	}
	return m.hbInterval, m.hbThreshold
}

func (m *Manager) transferCommitGracePeriodLocked() time.Duration {
	// #5081: size the transfer-commit grace from the LIVE dead-peer
	// detection window. Sizing it from the desired configuration under-runs
	// the window whenever a commit SHORTENS the configured timing: desired
	// 3x100ms yields a 10s floor while the running receiver still declares
	// death at 5x1000ms = 5s from the last frame, so the grace can expire
	// before the timeout it exists to suppress and a manual transfer takes
	// a spurious peer-death failover.
	interval, threshold := m.liveHeartbeatTimingLocked()
	grace := 2*time.Duration(threshold)*interval + transferCommitHeartbeatSlack
	if grace < minTransferCommitGracePeriod {
		grace = minTransferCommitGracePeriod
	}
	return grace
}

func (m *Manager) suppressPeerTimeoutForTransferCommitLocked(now time.Time) (bool, string) {
	activeRGs := make([]int, 0, len(m.localTransferOutHoldUntil))
	for rgID, until := range m.localTransferOutHoldUntil {
		if now.Before(until) {
			activeRGs = append(activeRGs, rgID)
			continue
		}
		delete(m.localTransferOutHoldUntil, rgID)
	}
	if len(activeRGs) == 0 {
		return false, ""
	}
	sort.Ints(activeRGs)
	return true, fmt.Sprintf("recent transfer commit grace active rgs=%v", activeRGs)
}

// applyTransferCommitOverridesOnPeerStateLocked applies pending peer
// transfer-out overrides and expires transfer-commit grace windows while
// handlePeerHeartbeat rebuilds the peer-groups map. Called once per heartbeat
// from heartbeat_manager.go::handlePeerHeartbeat, after newPeerGroups has been
// freshly populated from the heartbeat packet and before m.peerGroups is
// replaced.
//
// The three loops are lifted verbatim from the inline block that previously
// lived in handlePeerHeartbeat (cluster.go pre-#1541 lines 1516-1541).
// Encapsulating them here keeps the entire transfer-commit state machine
// (override map, grace windows, expiry, suppression) co-located in
// failover.go so reviewers can trace the "committed-failover-suppresses-
// stale-heartbeat" invariant by reading one file end-to-end.
//
// The helper takes newPeerGroups as the map being rebuilt (Go maps are
// reference types, so mutations on the parameter are visible to the caller)
// and now as the heartbeat reception timestamp. m.transferOverrides,
// m.peerTransferCommitGraceUntil, and m.localTransferOutHoldUntil are
// read/mutated through the *Manager receiver as before. Caller must hold
// m.mu write-locked (matching the existing handlePeerHeartbeat protocol).
func (m *Manager) applyTransferCommitOverridesOnPeerStateLocked(newPeerGroups map[int]PeerGroupState, now time.Time) {
	// #15164: post-commit abort markers live only while the peer still
	// advertises the hold they were recorded against. #17713 distinguishes a
	// failed pre-commit fence: an ordinary-secondary owner-restoration
	// heartbeat does not prove the owner reclaimed PRIMARY, so that marker
	// remains until a newer PRIMARY follows an observed hold, a committed new
	// transfer, reset, peer loss, or RG removal resolves the epoch.
	for rgID := range m.abortedPeerTransferReqID {
		peerGroup, ok := newPeerGroups[rgID]
		fence, fenced := m.abortedPeerTransferFence[rgID]
		if fenced {
			if ok && peerGroup.heartbeatSession != 0 &&
				(peerGroup.heartbeatSession != fence.heartbeatSession ||
					peerGroup.heartbeatSequence > fence.heartbeatSequence) {
				switch peerGroup.State {
				case StateSecondaryHold:
					fence.heartbeatSession = peerGroup.heartbeatSession
					fence.heartbeatSequence = peerGroup.heartbeatSequence
					fence.sawHold = true
					m.abortedPeerTransferFence[rgID] = fence
				case StatePrimary:
					if fence.sawHold {
						m.clearAbortedPeerTransferLocked(rgID)
					}
				}
			}
			continue
		}
		if !ok || peerGroup.State != StateSecondaryHold {
			m.clearAbortedPeerTransferLocked(rgID)
		}
	}
	for rgID := range m.transferOverrides {
		peerGroup, ok := newPeerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.GroupID = rgID
		peerGroup.State = StateSecondaryHold
		// #7367: mark the substitution so `show chassis cluster status` can
		// distinguish this from a peer that actually reported secondary-hold.
		// The State value and every election consequence are unchanged.
		peerGroup.StateOverriddenLocally = true
		peerGroup.OverrideReason = "transfer-out override"
		newPeerGroups[rgID] = peerGroup
	}
	for rgID, until := range m.peerTransferCommitGraceUntil {
		if !now.Before(until) {
			delete(m.peerTransferCommitGraceUntil, rgID)
			continue
		}
		peerGroup, ok := newPeerGroups[rgID]
		if !ok {
			continue
		}
		peerGroup.GroupID = rgID
		peerGroup.State = StateSecondaryHold
		// #7367: as above. Named separately from the transfer-out override
		// because a grace window expires on its own and an override does not.
		peerGroup.StateOverriddenLocally = true
		peerGroup.OverrideReason = "transfer-commit grace"
		newPeerGroups[rgID] = peerGroup
	}
	for rgID, until := range m.localTransferOutHoldUntil {
		if !now.Before(until) {
			delete(m.localTransferOutHoldUntil, rgID)
		}
	}
}
