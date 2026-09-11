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

// ManualFailover forces a redundancy group to transfer out of primary.
// Unlike ForceSecondary, this preserves the group's monitor-derived weight
// and advertises an explicit transfer-out state so the peer can claim
// primary without relying on weight-zero election semantics.
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

func (m *Manager) ManualFailover(rgID int) (FailoverOutcome, error) {
	m.mu.Lock()
	rg, ok := m.groups[rgID]
	if !ok {
		m.mu.Unlock()
		return FailoverApplied, fmt.Errorf("redundancy group %d not found", rgID)
	}
	if m.failoverInProgress[rgID] {
		m.mu.Unlock()
		return FailoverApplied, fmt.Errorf("failover already in progress for redundancy group %d, please wait", rgID)
	}
	m.failoverInProgress[rgID] = true
	// Snapshot the per-RG failover generation before releasing m.mu for the
	// pre-hook. A ResetFailover landing in the unlocked window bumps it, and
	// the post-relock re-check below then abandons the trailing SecondaryHold
	// write instead of clobbering the operator's reset (#5246).
	failoverGen := m.failoverGen[rgID]
	preHook := m.preManualFailoverFn
	retryTimeout := m.preManualFailoverRetryTimeout
	retryInterval := m.preManualFailoverRetryInterval
	m.mu.Unlock()

	var preHookErr error
	if preHook != nil {
		deadline := time.Now().Add(retryTimeout)
		for attempts := 1; ; attempts++ {
			if err := preHook(rgID); err != nil {
				if !IsRetryablePreFailoverError(err) {
					preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
					break
				}
				remaining := time.Until(deadline)
				if remaining <= 0 {
					preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
					break
				}
				sleep := retryInterval
				if sleep <= 0 {
					sleep = DefaultPreManualFailoverRetryInterval
				}
				if sleep > remaining {
					sleep = remaining
				}
				slog.Info("cluster: waiting to admit manual failover",
					"rg", rgID,
					"attempt", attempts,
					"remaining", remaining.String(),
					"err", err)
				time.Sleep(sleep)
				continue
			}
			break
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Always clear the in-progress flag under the same lock acquisition
	// that performs the state change, so there is no window where another
	// caller can slip in between flag-clear and state-commit.
	defer delete(m.failoverInProgress, rgID)

	if preHookErr != nil {
		return FailoverApplied, preHookErr
	}

	rg, ok = m.groups[rgID]
	if !ok {
		return FailoverApplied, fmt.Errorf("redundancy group %d not found", rgID)
	}
	// If a ResetFailover ran during the unlocked pre-hook window it bumped
	// this RG's failover generation. The trailing SecondaryHold write below
	// would otherwise silently clobber the operator's reset (#5246). Detect
	// the supersede and abandon the write, leaving the reset's restored state
	// intact. failoverInProgress is cleared by the deferred delete above.
	if m.failoverGen[rgID] != failoverGen {
		slog.Info("cluster: manual failover superseded by reset, abandoning", "rg", rgID)
		// #8000: report the supersede rather than a bare nil. The caller needs
		// it for two things a plain success cannot express — telling the
		// operator the RG did NOT move, and dropping the fence barrier it armed,
		// which nothing will now actuate.
		return FailoverSuperseded, nil
	}
	oldState := rg.State
	// A fresh manual failover supersedes any prior remote transfer-out lease on
	// this RG. The remote path re-arms via ArmRemoteTransferOutLease after this
	// returns; a local operator failover leaves it cleared so its deliberate
	// hold is never auto-restored (#5079).
	m.clearRemoteTransferOutLeaseLocked(rgID)
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
// Returns an error if the peer is not alive (no peer to take over).
func (m *Manager) ForceSecondary() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.peerAlive {
		return fmt.Errorf("peer not alive — cannot force secondary without active peer")
	}

	for _, rg := range m.groups {
		if rg.State == StateDisabled {
			continue
		}
		oldState := rg.State
		// ISSU force-secondary is a deliberate drain; drop any remote
		// transfer-out lease so it is never auto-restored (#5079).
		m.clearRemoteTransferOutLeaseLocked(rg.GroupID)
		rg.Weight = 0
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

// ResetFailover clears manual failover and resumes normal election.
func (m *Manager) ResetFailover(rgID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rg, ok := m.groups[rgID]
	if !ok {
		return fmt.Errorf("redundancy group %d not found", rgID)
	}
	// A rejoin (manual `request ... reset`, or the kernel-roll orchestrator's
	// `xpfd upgrade kernel rejoin`) means this node is verified and re-entering
	// the cluster — drop the kernel-upgrade election hold too, SYNCHRONOUSLY, so
	// the node is election-eligible the instant rejoin returns. Otherwise the
	// hold would persist until the daemon's 5s reconcile tick, and the kernel-
	// roll driver — which advances to drain the PEER as soon as rejoin returns —
	// could leave BOTH nodes secondary for up to 5s (r2 Codex HIGH never-both-
	// down). Cleared inline (we already hold m.mu); the recalcWeight election
	// below then lets the node reclaim its role.
	if m.kernelUpgradeHold {
		m.kernelUpgradeHold = false
		slog.Info("cluster: kernel-upgrade hold cleared by failover reset (rejoin)", "rg", rgID)
	}
	rg.ManualFailover = false
	rg.ManualFailoverAt = time.Time{}
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
	fn := m.peerFailoverFn
	commitFn := m.peerFailoverCommitFn
	transferReadyFn := m.transferReadinessFn
	peerAlive := m.peerAlive
	localCommitReadyFn := m.localTransferCommitReadyFn
	m.mu.Unlock()

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
	reqID, err := fn(rgID)
	if err != nil {
		return err
	}
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
		rg.ManualFailover = false
		rg.ManualFailoverAt = time.Time{}
		m.recalcWeight(rg)
	}
	m.mu.Unlock()
	if err := m.commitRequestedPeerFailover(rgID, reqID); err != nil {
		// The commit applies peerTransferOutOverride BEFORE running the
		// election, so an election that fails to promote us leaves the
		// override armed. It has no expiry — applyTransferCommitOverrides-
		// OnPeerStateLocked re-forces the peer to secondary-hold on EVERY
		// subsequent heartbeat — so electRG's "Peer transfer out" arm
		// self-promotes this node as soon as local weight recovers, giving a
		// persistent dual-primary. Roll back exactly as the batch path does
		// (#6527). The rollback is reqID-matched and a no-op on the two
		// error returns that precede the override, so it is safe on every
		// commit failure.
		m.abortRequestedPeerFailover(rgID, reqID)
		return err
	}
	if localCommitReadyFn != nil {
		if err := localCommitReadyFn([]int{rgID}); err != nil {
			m.abortRequestedPeerFailover(rgID, reqID)
			return err
		}
	}
	if err := commitFn(rgID, reqID); err != nil {
		m.abortRequestedPeerFailover(rgID, reqID)
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

func (m *Manager) abortRequestedPeerFailover(rgID int, reqID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.restorePeerTransferOutOverrideLocked(rgID, reqID) {
		return
	}
	delete(m.peerTransferCommitGraceUntil, rgID)
	m.runElection()
}

func (m *Manager) notePeerTransferCommitted(rgID int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.clearPeerTransferOutOverrideLocked(rgID)
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
		slog.Info("cluster: armed remote transfer-out lease",
			"rg", rgID, "req_id", reqID, "expires_in", m.remoteTransferOutLease.String())
	}
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
}

// manualFailoverRestoreWeightLocked recomputes an RG's monitor-derived weight
// after ManualFailover is cleared. It is used by the dual-resign guard and the
// transfer-out lease expiry in electRG, and by handlePeerTimeout's peer-loss
// clear (#9640). It deliberately does NOT run election: in electRG
// recalcWeight would recurse back into electRG, and on peer loss its
// electSingleNode would promote every group before the disable-rg-confirmed
// fence. Caller holds m.mu.
func (m *Manager) manualFailoverRestoreWeightLocked(rg *RedundancyGroupState) {
	totalLost := 0
	for _, iface := range rg.MonitorFails {
		key := monitorKey{rgID: rg.GroupID, iface: iface}
		totalLost += m.monitorWeights[key]
	}
	rg.Weight = rgWeightFromDebt(totalLost)
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
	if rg.State == StateSecondary && !rg.ManualFailover {
		return nil
	}

	oldState := rg.State
	rg.ManualFailover = false
	rg.ManualFailoverAt = time.Time{}
	rg.State = StateSecondary
	// A completed transfer-out invalidates any stale inbound-transfer view
	// from the previous owner direction. If we keep forcing the peer into
	// secondary-hold here, the next heartbeat can immediately re-elect the
	// old owner during rapid failback/failover sequences.
	delete(m.peerTransferOutOverride, rgID)
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
		// The single-member batch delegates, so the batch's own contract
		// depends on the singular path reporting its outcome too — which is why
		// #8000 could not be fixed on the batch alone.
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
	for _, rgID := range ids {
		if _, ok := m.groups[rgID]; !ok {
			m.mu.Unlock()
			return res, fmt.Errorf("redundancy group %d not found", rgID)
		}
		if m.failoverInProgress[rgID] {
			m.mu.Unlock()
			return res, fmt.Errorf("failover already in progress for redundancy groups %v, please wait", ids)
		}
	}
	batchGen := make(map[int]uint64, len(ids))
	for _, rgID := range ids {
		m.failoverInProgress[rgID] = true
		// Snapshot each member's failover generation before releasing m.mu
		// for the pre-hook so a ResetFailover on a member during the unlocked
		// window is detected and its reset preserved (#5246).
		batchGen[rgID] = m.failoverGen[rgID]
	}
	preHook := m.preManualFailoverFn
	retryTimeout := m.preManualFailoverRetryTimeout
	retryInterval := m.preManualFailoverRetryInterval
	m.mu.Unlock()

	var preHookErr error
	if preHook != nil {
		for _, rgID := range ids {
			deadline := time.Now().Add(retryTimeout)
			for attempts := 1; ; attempts++ {
				if err := preHook(rgID); err != nil {
					if !IsRetryablePreFailoverError(err) {
						preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
						break
					}
					remaining := time.Until(deadline)
					if remaining <= 0 {
						preHookErr = fmt.Errorf("pre-failover prepare for redundancy group %d: %w", rgID, err)
						break
					}
					sleep := retryInterval
					if sleep <= 0 {
						sleep = DefaultPreManualFailoverRetryInterval
					}
					if sleep > remaining {
						sleep = remaining
					}
					slog.Info("cluster: waiting to admit manual failover batch",
						"rgs", ids,
						"rg", rgID,
						"attempt", attempts,
						"remaining", remaining.String(),
						"err", err)
					time.Sleep(sleep)
					continue
				}
				break
			}
			if preHookErr != nil {
				break
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		for _, rgID := range ids {
			delete(m.failoverInProgress, rgID)
		}
	}()

	if preHookErr != nil {
		return res, preHookErr
	}

	// #7176 (C179-065): a member REMOVED from config during the unlocked
	// pre-hook window must be reported, not silently skipped. The singular
	// ManualFailover returns "redundancy group %d not found" for exactly this
	// condition after its own re-lock (see above); the batch used to `continue`,
	// so the same condition on the same path reported full success. There is no
	// contract behind the batch's side of that split — it is the one place the
	// two genuinely diverge — and reporting it makes them agree.
	//
	// Resolved BEFORE any member is mutated, and the resolved pointers are what
	// the commit loop iterates: the whole commit half runs under one lock, so
	// the pre-scan is atomic with the writes and an unknown member can never
	// leave the batch half-applied.
	//
	// The SUPERSEDE skip below deliberately keeps its `continue`. That is #5246
	// working as designed — the reset wins — and it is pinned by name in
	// failover_races_5245_5246_test.go ("ManualFailover should return without
	// error when superseded"). The singular path does the same thing, so it is
	// not a batch defect. The operator-facing consequence of reporting success
	// for a partially-applied BATCH is real and is tracked separately by #8000;
	// it needs an API change, not a silent reversal of a pinned contract.
	resolved := make([]*RedundancyGroupState, 0, len(ids))
	for _, rgID := range ids {
		rg := m.groups[rgID]
		if rg == nil {
			return res, fmt.Errorf("redundancy group %d not found", rgID)
		}
		resolved = append(resolved, rg)
	}

	now := time.Now()
	for i, rgID := range ids {
		rg := resolved[i]
		// A ResetFailover on this member during the unlocked window bumped
		// its failover generation — its reset wins; skip the SecondaryHold
		// write so we don't clobber it (#5246).
		if m.failoverGen[rgID] != batchGen[rgID] {
			// #8000: record it. The skip itself is #5246 working as designed
			// and stays exactly as it was; what changes is that the caller can
			// now SEE it, instead of the batch reporting a full handoff and
			// leaving the applied-ack to time out on a barrier nothing will
			// actuate.
			slog.Info("cluster: manual failover batch member superseded by reset, skipping", "rg", rgID)
			res.Superseded = append(res.Superseded, rgID)
			continue
		}
		oldState := rg.State
		// Fresh batch failover supersedes any prior remote transfer-out lease;
		// the remote path re-arms after this returns (#5079).
		m.clearRemoteTransferOutLeaseLocked(rgID)
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
	fn := m.peerFailoverBatchFn
	commitFn := m.peerFailoverCommitBatchFn
	transferReadyFn := m.transferReadinessFn
	peerAlive := m.peerAlive
	localCommitReadyFn := m.localTransferCommitReadyFn
	m.mu.Unlock()

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

	reqID, err := fn(ids)
	if err != nil {
		return err
	}

	m.mu.Lock()
	for _, rgID := range ids {
		rg := m.groups[rgID]
		if rg != nil && rg.ManualFailover {
			rg.ManualFailover = false
			rg.ManualFailoverAt = time.Time{}
			m.recalcWeight(rg)
		}
	}
	m.mu.Unlock()

	if err := m.commitRequestedPeerFailoverBatch(ids, reqID); err != nil {
		m.abortRequestedPeerFailoverBatch(ids, reqID)
		return err
	}
	if localCommitReadyFn != nil {
		if err := localCommitReadyFn(ids); err != nil {
			m.abortRequestedPeerFailoverBatch(ids, reqID)
			return err
		}
	}
	if err := commitFn(ids, reqID); err != nil {
		m.abortRequestedPeerFailoverBatch(ids, reqID)
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

func (m *Manager) abortRequestedPeerFailoverBatch(rgIDs []int, reqID uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range rgIDs {
		delete(m.peerTransferCommitGraceUntil, rgID)
		m.restorePeerTransferOutOverrideLocked(rgID, reqID)
	}
	m.runElection()
}

func (m *Manager) notePeerTransferCommittedBatch(rgIDs []int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rgID := range rgIDs {
		m.clearPeerTransferOutOverrideLocked(rgID)
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
		if rg.State == StateSecondary && !rg.ManualFailover {
			continue
		}
		oldState := rg.State
		rg.ManualFailover = false
		rg.ManualFailoverAt = time.Time{}
		rg.State = StateSecondary
		// Clear stale inbound-transfer markers from the previous direction
		// before we park this node as the old owner. Otherwise the next peer
		// heartbeat can still force the peer into secondary-hold and snap the
		// RG back during rapid alternating moves.
		delete(m.peerTransferOutOverride, rgID)
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
	m.peerTransferOutOverride[rgID] = reqID
	m.peerTransferOutPrevious[rgID] = peerGroupSnapshot{
		state:   previous,
		present: ok,
	}
	peerGroup := previous
	peerGroup.GroupID = rgID
	peerGroup.State = StateSecondaryHold
	m.peerGroups[rgID] = peerGroup
	if rg := m.groups[rgID]; rg != nil {
		rg.PeerPriority = peerGroup.Priority
	}
}

func (m *Manager) clearPeerTransferOutOverrideLocked(rgID int) {
	delete(m.peerTransferOutOverride, rgID)
	delete(m.peerTransferOutPrevious, rgID)
}

func (m *Manager) restorePeerTransferOutOverrideLocked(rgID int, reqID uint64) bool {
	currentReqID, ok := m.peerTransferOutOverride[rgID]
	if !ok || currentReqID != reqID {
		return false
	}
	delete(m.peerTransferOutOverride, rgID)
	snapshot, hadSnapshot := m.peerTransferOutPrevious[rgID]
	delete(m.peerTransferOutPrevious, rgID)
	if hadSnapshot && snapshot.present {
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
// and now as the heartbeat reception timestamp. m.peerTransferOutOverride,
// m.peerTransferCommitGraceUntil, and m.localTransferOutHoldUntil are
// read/mutated through the *Manager receiver as before. Caller must hold
// m.mu write-locked (matching the existing handlePeerHeartbeat protocol).
func (m *Manager) applyTransferCommitOverridesOnPeerStateLocked(newPeerGroups map[int]PeerGroupState, now time.Time) {
	for rgID := range m.peerTransferOutOverride {
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
