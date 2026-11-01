package cluster

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// #18715: an aborted transfer can leave a redundancy group with no primary.
//
// A requester whose transfer request fails before the commit keeps a FENCED
// abort marker (#16592/#17713) that blocks every election arm until the old
// owner proves it reclaimed the group: a PRIMARY heartbeat after an observed
// hold. An owner that does not re-promote never sends one. Two shapes reach
// that state: a requester that outranks the owner (ordinary election keeps the
// restored owner secondary; TestFailedFenceRestorationKeepsHigherPriorityRequesterFenced17713
// pins that outcome), and an owner in dataplane-arm debt (#12164, a wedged
// helper: #18701), which yields to the healthier requester. Both nodes then
// sit secondary until an operator resets the requester.
//
// The requester retries the transfer through the ordinary request sequence.
// The retry commits only on the owner's applied ack, and an owner acks only
// after it has confirmed its own dataplane inactive for the group (the
// ownerless accept below, and the #5640/#6371 fence on the ordinary path), so
// a retry can never create a second owner. An owner that predates #18715
// rejects the request for a group it does not own; the requester then keeps
// retrying with backoff and nothing else changes.

// abortedTransferRetryQuietFloor is the least time the retry condition must
// hold before the first attempt. The quiet period is the larger of this and
// two heartbeat timeouts (see abortedTransferRetryQuietLocked). It lets the
// abort's own restoration play out first: the abort frame reaches the owner,
// its election runs, and an owner that CAN re-promote advertises PRIMARY
// within one heartbeat interval, which resolves the marker and cancels the
// retry. It is also longer than a heartbeat timeout, so a peer that is dying
// is declared lost (which clears the marker) before this node retries into it,
// and longer than the owner's 2 s dual-resign rescue and the requester's 3 s
// commit-ready window, so a retry never races either.
var abortedTransferRetryQuietFloor = 5 * time.Second

// abortedTransferRetryQuietOverride replaces the whole quiet period when set
// (tests only; production never sets it).
var abortedTransferRetryQuietOverride time.Duration

// The retry backs off from abortedTransferRetryBackoffMin to
// abortedTransferRetryBackoffMax and never gives up while the condition holds:
// an ownerless group is an outage. At the minimum spacing a retry costs the
// owner one transfer request, one session-sync barrier and one helper
// rg_active write every 5 s (at most 0.2/s), inside the control-socket budget
// (CLAUDE.md: callers above 1/s starve session installs).
var (
	abortedTransferRetryBackoffMin = 5 * time.Second
	abortedTransferRetryBackoffMax = 30 * time.Second
)

// errAbortedTransferRetryStale refuses a retry whose epoch has ended.
var errAbortedTransferRetryStale = errors.New(
	"transfer retry superseded: the aborted-transfer marker it belongs to has cleared or changed, or an operator acted on the redundancy group (#18715)")

// abortedTransferRetry is one RG's retry chain. It belongs to one aborted
// transfer epoch: the marker's reqID and the RG's operator epoch at the time
// the condition was first seen. A failed attempt re-arms the marker under a
// new reqID, and the chain adopts it because the chain itself caused it.
// Anything else that changes either value ends the chain.
type abortedTransferRetry struct {
	reqID    uint64
	opEpoch  uint64
	since    time.Time
	nextAt   time.Time
	backoff  time.Duration
	attempts int
	inFlight bool
	reason   string
	lastErr  string
}

// noteOperatorFailoverLocked records that an operator (or the peer, through a
// transfer request this node is serving) issued a failover or reset for the
// RGs. It ends any retry chain for them: a stale retry must never override a
// newer operator decision. Every caller invokes it once the command is
// ADMITTED (it won the failover reservation; a reset has none and is always
// admitted once the RG exists), so a command refused at admission, such as
// "failover already in progress" while a retry attempt holds the reservation,
// leaves the chain intact. A command admitted and then failing later (in its
// pre-hook, say) has still moved the epoch. Caller holds m.mu.
func (m *Manager) noteOperatorFailoverLocked(rgIDs ...int) {
	if m.operatorEpoch == nil {
		m.operatorEpoch = make(map[int]uint64)
	}
	for _, rgID := range rgIDs {
		m.operatorEpoch[rgID]++
		m.cancelAbortedTransferRetryLocked(rgID, "operator failover or reset")
	}
}

// cancelAbortedTransferRetryLocked ends rgID's retry chain. An in-flight
// attempt finds the chain gone when it finishes and does nothing more; its
// own admission check refuses to commit once the epoch has moved. Caller
// holds m.mu.
func (m *Manager) cancelAbortedTransferRetryLocked(rgID int, reason string) {
	chain := m.abortedTransferRetries[rgID]
	delete(m.abortedTransferRetries, rgID)
	if chain == nil {
		return
	}
	if chain.attempts > 0 {
		slog.Info("cluster: transfer retry cancelled (#18715)",
			"rg", rgID, "reason", reason, "attempts", chain.attempts)
		return
	}
	slog.Debug("cluster: pending transfer retry cancelled before its first attempt",
		"rg", rgID, "reason", reason)
}

func (m *Manager) cancelAllAbortedTransferRetriesLocked(reason string) {
	for rgID := range m.abortedTransferRetries {
		m.cancelAbortedTransferRetryLocked(rgID, reason)
	}
}

// abortedTransferRetryQuietLocked is how long the condition must hold before
// the first attempt: two heartbeat timeouts, floored. Caller holds m.mu.
func (m *Manager) abortedTransferRetryQuietLocked() time.Duration {
	if abortedTransferRetryQuietOverride > 0 {
		return abortedTransferRetryQuietOverride
	}
	interval, threshold := m.liveHeartbeatTimingLocked()
	quiet := 2 * interval * time.Duration(threshold)
	if quiet < abortedTransferRetryQuietFloor {
		quiet = abortedTransferRetryQuietFloor
	}
	return quiet
}

// abortedTransferRetryConditionLocked reports whether rg is in the ownerless
// shape the retry exists for, judged on this node: it holds an aborted-
// transfer marker, neither node is primary, and this node can serve the RG
// (election-ready, no arm debt, no hold of its own). When both nodes are sick
// a retry achieves nothing, so an unready requester does not retry. Caller
// holds m.mu.
func (m *Manager) abortedTransferRetryConditionLocked(rg *RedundancyGroupState) (uint64, string, bool) {
	reqID, aborted := m.abortedPeerTransferReqID[rg.GroupID]
	if !aborted || rg.State == StatePrimary || rg.State == StateDisabled || !m.peerAlive {
		return 0, "", false
	}
	pg, ok := m.peerGroups[rg.GroupID]
	if !ok || pg.State == StatePrimary {
		return 0, "", false
	}
	if rg.ManualFailover || rg.forcedSecondary || m.kernelUpgradeHold || rg.Weight <= 0 ||
		m.dataplaneArmDebtLocked(rg.GroupID) > 0 || !rg.IsReadyForTakeover(m.takeoverHoldTime) {
		return 0, "", false
	}
	reason := fmt.Sprintf("transfer %d aborted and the peer has not taken the group back (peer %s, weight %d)",
		reqID, pg.State, pg.Weight)
	return reqID, reason, true
}

// evaluateAbortedTransferRetriesLocked advances every RG's retry chain. It
// runs after each admitted peer heartbeat's election: the condition is a
// property of the peer view, and while the peer is alive heartbeats arrive
// every interval; once they stop the peer is lost, which clears the marker and
// cancels the chain. Caller holds m.mu.
func (m *Manager) evaluateAbortedTransferRetriesLocked(now time.Time) {
	if m.abortedTransferRetries == nil {
		m.abortedTransferRetries = make(map[int]*abortedTransferRetry)
	}
	for rgID, rg := range m.groups {
		chain := m.abortedTransferRetries[rgID]
		if chain != nil && chain.inFlight {
			continue // the attempt settles its own chain when it returns
		}
		reqID, reason, ok := m.abortedTransferRetryConditionLocked(rg)
		if !ok {
			if chain != nil {
				m.cancelAbortedTransferRetryLocked(rgID, "the redundancy group is no longer ownerless here")
			}
			continue
		}
		if chain != nil && (chain.reqID != reqID || chain.opEpoch != m.operatorEpoch[rgID]) {
			m.cancelAbortedTransferRetryLocked(rgID, "a new transfer epoch began")
			chain = nil
		}
		if chain == nil {
			m.abortedTransferRetries[rgID] = &abortedTransferRetry{
				reqID:   reqID,
				opEpoch: m.operatorEpoch[rgID],
				since:   now,
				backoff: abortedTransferRetryBackoffMin,
				reason:  reason,
			}
			continue
		}
		chain.reason = reason
		due := chain.nextAt
		if due.IsZero() {
			due = chain.since.Add(m.abortedTransferRetryQuietLocked())
		}
		if now.Before(due) || m.failoverInProgress[rgID] != 0 {
			continue
		}
		m.fireAbortedTransferRetryLocked(rgID, chain, now)
	}
}

func (m *Manager) fireAbortedTransferRetryLocked(rgID int, chain *abortedTransferRetry, now time.Time) {
	chain.inFlight = true
	chain.attempts++
	if chain.attempts == 1 {
		slog.Warn("cluster: an earlier failover of this redundancy group to this node was aborted, "+
			"and the peer has not taken the group back, so neither node is primary for it; "+
			"retrying the transfer to this node (it completes only once the peer confirms its "+
			"dataplane inactive for the group) (#18715)",
			"rg", rgID, "aborted_req_id", chain.reqID, "reason", chain.reason,
			"ownerless_for", now.Sub(chain.since).Round(time.Millisecond))
		if m.history != nil {
			m.history.Record(EventRG, rgID, "Transfer retry: "+chain.reason)
		}
	} else {
		slog.Debug("cluster: transfer retry attempt",
			"rg", rgID, "attempt", chain.attempts, "aborted_req_id", chain.reqID, "last_err", chain.lastErr)
	}
	run := func() { m.runAbortedTransferRetry(rgID, chain) }
	if m.abortedTransferRetryLaunchFn != nil {
		m.abortedTransferRetryLaunchFn(run)
		return
	}
	go run()
}

// runAbortedTransferRetry is one attempt. Called WITHOUT m.mu.
func (m *Manager) runAbortedTransferRetry(rgID int, chain *abortedTransferRetry) {
	// Runs under m.mu at the reservation and again in the commit's critical
	// section: the attempt goes ahead only while its epoch is current.
	admit := func() error {
		if m.abortedTransferRetries[rgID] != chain || m.operatorEpoch[rgID] != chain.opEpoch {
			return errAbortedTransferRetryStale
		}
		if cur, ok := m.abortedPeerTransferReqID[rgID]; !ok || cur != chain.reqID {
			return errAbortedTransferRetryStale
		}
		return nil
	}
	err := m.requestPeerFailover(rgID, admit, false)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.abortedTransferRetries[rgID] != chain {
		return // cancelled while in flight
	}
	chain.inFlight = false
	if err == nil {
		delete(m.abortedTransferRetries, rgID)
		slog.Info("cluster: transfer retry committed; this node is now primary for the redundancy group (#18715)",
			"rg", rgID, "attempts", chain.attempts)
		if m.history != nil {
			m.history.Record(EventRG, rgID, fmt.Sprintf("Transfer retry committed after %d attempt(s)", chain.attempts))
		}
		return
	}
	chain.lastErr = err.Error()
	cur, ok := m.abortedPeerTransferReqID[rgID]
	if !ok || m.operatorEpoch[rgID] != chain.opEpoch {
		delete(m.abortedTransferRetries, rgID)
		return
	}
	// The attempt's own abort re-armed the marker under its reqID.
	chain.reqID = cur
	if chain.attempts > 1 {
		chain.backoff *= 2
		if chain.backoff > abortedTransferRetryBackoffMax {
			chain.backoff = abortedTransferRetryBackoffMax
		}
	}
	chain.nextAt = time.Now().Add(chain.backoff)
	slog.Debug("cluster: transfer retry failed; backing off",
		"rg", rgID, "attempt", chain.attempts, "err", err, "next_in", chain.backoff)
}

// abortedTransferRetryStatusLocked renders each RG's pending retry for
// `show chassis cluster status`. Caller holds m.mu (read).
func (m *Manager) abortedTransferRetryStatusLocked(now time.Time) map[int]string {
	if len(m.abortedTransferRetries) == 0 {
		return nil
	}
	out := make(map[int]string, len(m.abortedTransferRetries))
	for rgID, chain := range m.abortedTransferRetries {
		due := chain.nextAt
		if due.IsZero() {
			due = chain.since.Add(m.abortedTransferRetryQuietLocked())
		}
		var when string
		switch {
		case chain.inFlight:
			when = "attempt in flight"
		case !now.Before(due) && m.failoverInProgress[rgID] != 0:
			// Due, but evaluate does not fire while another failover
			// holds the RG's reservation.
			when = "deferred (failover in progress)"
		case chain.nextAt.IsZero():
			when = fmt.Sprintf("first attempt in %s", maxDuration(0, due.Sub(now)).Round(100*time.Millisecond))
		default:
			when = fmt.Sprintf("next attempt in %s", maxDuration(0, due.Sub(now)).Round(100*time.Millisecond))
		}
		s := fmt.Sprintf("pending (%s; %d attempt(s), %s)", chain.reason, chain.attempts, when)
		if chain.lastErr != "" {
			s += "; last error: " + chain.lastErr
		}
		out[rgID] = s
	}
	return out
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// ownerlessTransferFreshness is how recent the peer heartbeat must be for the
// ownerless accept: two heartbeat intervals. The peer sends a frame every
// interval, so a view within two intervals has missed at most one frame, and
// a peer that promoted before its last-but-one frame shows as primary in it.
// An older view may predate a promotion, and accepting a delayed request from
// an old epoch on it would install a hold this node does not need. The window
// that remains (a promotion after the peer's latest frame) is closed on the
// requester: it drops an applied ack whose reqID is not the one it is waiting
// on, and the hold's lease then restores this node.
func (m *Manager) ownerlessTransferFreshnessLocked() time.Duration {
	interval, _ := m.liveHeartbeatTimingLocked()
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	return 2 * interval
}

// ownerlessTransferAdmitLocked is the #18715 owner-side exception: a transfer
// request for an RG this node does NOT own is accepted only when the group is
// ownerless from this node's view too: this node is not primary, the RG is
// enabled, and the latest peer heartbeat is fresh and shows the peer not
// primary. Caller holds m.mu.
func (m *Manager) ownerlessTransferAdmitLocked(rg *RedundancyGroupState, now time.Time) error {
	if rg.State == StatePrimary {
		return fmt.Errorf("%w: redundancy group %d is primary here; the ordinary transfer path applies", ErrRemoteFailoverRejected, rg.GroupID)
	}
	if rg.State == StateDisabled {
		return fmt.Errorf("%w: redundancy group %d is disabled", ErrRemoteFailoverRejected, rg.GroupID)
	}
	if !m.peerAlive || m.lastPeerHeartbeatAt.IsZero() {
		return fmt.Errorf("%w: redundancy group %d: no live peer heartbeat", ErrRemoteFailoverRejected, rg.GroupID)
	}
	if age, limit := now.Sub(m.lastPeerHeartbeatAt), m.ownerlessTransferFreshnessLocked(); age > limit {
		return fmt.Errorf("%w: redundancy group %d: the latest peer heartbeat is %s old (limit %s), too stale to prove the group is ownerless",
			ErrRemoteFailoverRejected, rg.GroupID, age.Round(time.Millisecond), limit)
	}
	pg, ok := m.peerGroups[rg.GroupID]
	if !ok {
		return fmt.Errorf("%w: redundancy group %d: the peer reports no state for it", ErrRemoteFailoverRejected, rg.GroupID)
	}
	if pg.State == StatePrimary {
		return fmt.Errorf("%w: redundancy group %d is primary on the peer", ErrRemoteFailoverRejected, rg.GroupID)
	}
	return nil
}

// ManualFailoverOwnerless serves a peer's transfer request reqID for an RG this
// node does not own (#18715). It installs the same hold ManualFailover does, and
// only when ownerlessTransferAdmitLocked passes in the critical section that
// installs it. The caller must still confirm the local dataplane inactive for
// the RG before it acks the request applied; this call only parks the RG.
//
// The RG may already be held: an operator Manual hold, or the ISSU drain pin
// (ForceSecondary). Every exit from a transfer-out clears both, so the hold
// found here is recorded and given back when the transfer ends without a
// commit (abort, lease expiry). A commit spends an ordinary hold, as any
// completed transfer-out does, but keeps the drain pin: a drained node stays
// drained after handing the RG off. Refusing the accept on a drained node
// instead would put the ownerless trap back during ISSU, where convergence
// matters most.
func (m *Manager) ManualFailoverOwnerless(rgID int, reqID uint64) (FailoverOutcome, error) {
	return m.manualFailoverWith(rgID, m.ownerlessTransferAdmitLocked, func(*RedundancyGroupState) {
		m.noteOwnerlessPriorHoldLocked(rgID, reqID)
	})
}

// ownerlessPriorHold is the hold an ownerless accept found in place.
type ownerlessPriorHold struct {
	reqID uint64
	snap  operatorHoldSnapshot
}

// noteOwnerlessPriorHoldLocked records rgID's current hold, if any, for the
// ownerless transfer reqID. Only the hold arms are kept: the transfer-override
// and aborted-marker arms belong to other protocols.
//
// When the RG is still parked by an EARLIER transfer-out that has not ended
// (its lease is armed: the requester's abort frame was lost, so only the lease
// can end it), the hold in place is that transfer's, not a prior one. The
// earlier transfer's recorded prior hold, if any, carries over to reqID;
// snapshotting the transfer's own hold instead would turn it into a "prior"
// hold that an abort then gives back. Called before the earlier lease is
// cleared. Caller holds m.mu.
func (m *Manager) noteOwnerlessPriorHoldLocked(rgID int, reqID uint64) {
	if m.ownerlessPriorHolds == nil {
		m.ownerlessPriorHolds = make(map[int]ownerlessPriorHold)
	}
	if _, leased := m.remoteTransferOutLeaseReqID[rgID]; leased {
		if rg := m.groups[rgID]; rg != nil && rg.ManualFailover {
			if p, ok := m.ownerlessPriorHolds[rgID]; ok {
				p.reqID = reqID
				m.ownerlessPriorHolds[rgID] = p
			}
			return
		}
	}
	snap := m.snapshotOperatorHoldLocked(rgID)
	snap.override, snap.hasOverride = transferOverride{}, false
	snap.abortedReqID, snap.hasAborted = 0, false
	snap.abortedFence, snap.hasAbortedFence = abortedPeerTransferFence{}, false
	if !snap.armed {
		delete(m.ownerlessPriorHolds, rgID)
		return
	}
	m.ownerlessPriorHolds[rgID] = ownerlessPriorHold{reqID: reqID, snap: snap}
}

// takeOwnerlessPriorHoldLocked removes rgID's recorded prior hold and returns
// it when it belongs to transfer reqID. Caller holds m.mu.
func (m *Manager) takeOwnerlessPriorHoldLocked(rgID int, reqID uint64) (operatorHoldSnapshot, bool) {
	p, ok := m.ownerlessPriorHolds[rgID]
	if !ok {
		return operatorHoldSnapshot{}, false
	}
	delete(m.ownerlessPriorHolds, rgID)
	if p.reqID != reqID {
		return operatorHoldSnapshot{}, false
	}
	return p.snap, true
}
