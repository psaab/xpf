package cluster

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

// #19140: peer-driven takeover of an RG whose owner lost a RETH member's XDP
// shim.
//
// The owner never yields on this debt. It charges RethMemberShimMonitorIface,
// which carries no weight, and advertises the charge as a reserved monitor
// marker on every heartbeat (memberShimWireMonitorsLocked). That is all the
// owner does. The debt is deliberately NOT the arm floor (weight 1): election
// treats a peer at that floor as unable to serve and promotes over it whatever
// its own readiness ("peer yielded at the arm-debt floor"), which would move
// the RG outside the transfer protocol to a node that may not be able to
// forward it, the handoff this design exists to remove.
//
// The HEALTHY peer acts. A secondary that sees its primary peer carrying the
// marker requests the RG through the ordinary transfer protocol
// (requestPeerFailover): the same matured-readiness gate as an operator
// transfer, the live transfer-readiness callback, the #18559 make-before-break
// pre-activation, the owner's #5640 fence before its applied ack, and the
// commit-time readiness re-check. So the node about to take over judges its
// OWN readiness at the moment it acts, and no cached readiness crosses the
// wire. That is what four rounds of an owner-side yield on the peer's
// advertised readiness could not provide (docs/log/19140.md): every stamp on
// that advertisement only moved the staleness down one layer.
//
// Throttling: one chain per RG, one attempt in flight, a quiet period before
// the first attempt and exponential backoff after a refusal. The chain lives
// for the owner's debt episode (the marker on the peer's latest frame), so a
// requester condition that flaps between attempts cannot reset the backoff.
//
// A requester with member-shim debt of its own, or at or below the arm floor
// (arm debt, startup-sync hold, or worse), never requests, so two equally
// broken nodes leave the RG where it is. A peer that predates #19140 never
// sends the marker and never requests, so the owner keeps the RG: the
// conservative default.
//
// A committed takeover is an ordinary completed transfer, so it pins both
// roles (transferCommitRolePinned): the old owner stays secondary while the
// new owner is primary, even under preempt and even after its debt clears. The
// RG returns only through the same mechanisms as after an operator transfer:
// an operator reset or failover, or this takeover running the other way when
// the new owner is charged in turn. A debtor never preempts on its own anyway:
// #19110 makes its shim-less member a takeover-readiness reason.

// memberShimTakeoverQuietOverride replaces the quiet period when set (tests).
var memberShimTakeoverQuietOverride time.Duration

// The backoff after a refused or failed attempt, like the #18715 retry: at the
// minimum spacing an attempt costs the owner one transfer request, one session
// sync barrier and one helper rg_active write every 5 s (at most 0.2/s),
// inside the control-socket budget.
var (
	memberShimTakeoverBackoffMin = 5 * time.Second
	memberShimTakeoverBackoffMax = 30 * time.Second
)

var (
	// errMemberShimTakeoverStale refuses an attempt whose chain ended or
	// whose operator epoch moved.
	errMemberShimTakeoverStale = errors.New(
		"member-shim takeover superseded: the chain ended or an operator acted on the redundancy group (#19140)")
	// errMemberShimOwnerRecovered abandons an attempt, before anything is
	// sent, when the owner no longer advertises the debt.
	errMemberShimOwnerRecovered = errors.New(
		"member-shim takeover abandoned: the owner no longer carries RETH member-shim debt (#19140)")
)

// memberShimTakeover is one RG's request chain on the requester.
type memberShimTakeover struct {
	opEpoch  uint64
	since    time.Time
	nextAt   time.Time
	backoff  time.Duration
	attempts int
	inFlight bool
	lastErr  string
}

// armFloorWeight is the weight of a node carrying a floor debt (arm,
// startup-sync hold). Monitor debt only lowers weight, so a node at or below it
// either has a floor debt or something worse.
const armFloorWeight = maxRedundancyGroupWeight - DataplaneArmMonitorCost

// memberShimWireMonitorsLocked is the owner's marker: one reserved monitor
// entry per RG charged with member-shim debt. Caller holds m.mu.
func (m *Manager) memberShimWireMonitorsLocked() []HeartbeatMonitor {
	var out []HeartbeatMonitor
	ids := make([]int, 0, len(m.groups))
	for id := range m.groups {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if id == 0 || !m.memberShimDebtLocked(id) {
			continue
		}
		out = append(out, HeartbeatMonitor{
			RGID:      wireRGID(id),
			Weight:    clampWireWeight(RethMemberShimMonitorCost),
			Up:        false,
			Interface: RethMemberShimMonitorIface,
		})
	}
	return out
}

// peerCarriesMemberShimDebtLocked reports whether the peer's latest heartbeat
// carries the member-shim marker for rgID. Caller holds m.mu.
func (m *Manager) peerCarriesMemberShimDebtLocked(rgID int) bool {
	for _, mon := range m.peerMonitors {
		if mon.Interface == RethMemberShimMonitorIface && !mon.Up && mon.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}

// memberShimEpisodeLocked reports whether the owner's debt episode that a
// chain belongs to is still running, judged from this node: the peer is alive,
// its latest frame carries the marker, and this node does not own the RG.
// Caller holds m.mu.
func (m *Manager) memberShimEpisodeLocked(rg *RedundancyGroupState) bool {
	if rg.GroupID == 0 || !m.peerAlive || rg.State == StatePrimary {
		return false
	}
	return m.peerCarriesMemberShimDebtLocked(rg.GroupID)
}

// memberShimTakeoverReadyLocked reports whether this node may request rg now,
// and why not. It is the requester's own state, read live under m.mu; the
// transfer re-checks readiness at its reservation and commit. Caller holds
// m.mu.
func (m *Manager) memberShimTakeoverReadyLocked(rg *RedundancyGroupState) (bool, string) {
	pg, ok := m.peerGroups[rg.GroupID]
	switch {
	case !ok || pg.State != StatePrimary:
		return false, "the peer is not primary"
	case rg.State != StateSecondary:
		return false, "this node is " + rg.State.String()
	case rg.ManualFailover || rg.forcedSecondary || m.kernelUpgradeHold:
		return false, "this node holds an operator or upgrade hold"
	case m.memberShimDebtLocked(rg.GroupID):
		return false, "this node carries member-shim debt of its own"
	case rg.Weight <= armFloorWeight:
		return false, "this node is at the arm floor (arm debt, startup-sync hold, or worse)"
	case !rg.IsReadyForTakeover(m.takeoverHoldTime):
		return false, "this node is not takeover-ready"
	}
	if _, aborted := m.abortedPeerTransferReqID[rg.GroupID]; aborted {
		return false, "an aborted transfer is pending (#18715 owns it)"
	}
	if m.failoverInProgress[rg.GroupID] != 0 {
		return false, "a transfer is in progress"
	}
	return true, ""
}

func (m *Manager) memberShimTakeoverQuietLocked() time.Duration {
	if memberShimTakeoverQuietOverride > 0 {
		return memberShimTakeoverQuietOverride
	}
	interval, threshold := m.liveHeartbeatTimingLocked()
	return 2 * interval * time.Duration(threshold)
}

// cancelMemberShimTakeoverLocked ends rgID's chain. An in-flight attempt finds
// it gone when it returns and does nothing more, and its commit-time admission
// refuses. UpdateConfig's RG-removal loop calls it (the #8435 incarnation
// boundary). Caller holds m.mu.
func (m *Manager) cancelMemberShimTakeoverLocked(rgID int, reason string) {
	chain, ok := m.memberShimTakeovers[rgID]
	delete(m.memberShimTakeovers, rgID) // the key goes even if its value is nil
	if !ok || chain == nil {
		return
	}
	if chain.attempts > 0 {
		slog.Info("cluster: RETH member-shim takeover request chain ended (#19140)",
			"rg", rgID, "reason", reason, "attempts", chain.attempts, "last_err", chain.lastErr)
	}
}

func (m *Manager) cancelAllMemberShimTakeoversLocked(reason string) {
	for rgID := range m.memberShimTakeovers {
		m.cancelMemberShimTakeoverLocked(rgID, reason)
	}
}

// evaluateMemberShimTakeoversLocked advances every RG's chain. It runs after
// each admitted peer heartbeat's election, next to the #18715 retry: both read
// the post-election roles. Caller holds m.mu.
func (m *Manager) evaluateMemberShimTakeoversLocked(now time.Time) {
	for rgID, rg := range m.groups {
		chain := m.memberShimTakeovers[rgID]
		if chain != nil && chain.inFlight {
			continue // the attempt settles its own chain when it returns
		}
		if !m.memberShimEpisodeLocked(rg) {
			m.cancelMemberShimTakeoverLocked(rgID, "the peer no longer owns the RG with member-shim debt")
			continue
		}
		if chain != nil && chain.opEpoch != m.operatorEpoch[rgID] {
			m.cancelMemberShimTakeoverLocked(rgID, "an operator acted on the redundancy group")
			chain = nil
		}
		if chain == nil {
			if m.memberShimTakeovers == nil {
				m.memberShimTakeovers = make(map[int]*memberShimTakeover)
			}
			m.memberShimTakeovers[rgID] = &memberShimTakeover{
				opEpoch: m.operatorEpoch[rgID],
				since:   now,
				backoff: memberShimTakeoverBackoffMin,
			}
			continue
		}
		due := chain.nextAt
		if due.IsZero() {
			due = chain.since.Add(m.memberShimTakeoverQuietLocked())
		}
		if now.Before(due) {
			continue
		}
		if ok, _ := m.memberShimTakeoverReadyLocked(rg); !ok {
			continue // the episode goes on; this node may qualify later
		}
		m.fireMemberShimTakeoverLocked(rgID, chain)
	}
}

func (m *Manager) fireMemberShimTakeoverLocked(rgID int, chain *memberShimTakeover) {
	chain.inFlight = true
	chain.attempts++
	if chain.attempts == 1 {
		slog.Warn("cluster: the peer owns this redundancy group with a RETH data member that has "+
			"no XDP shim (member-shim debt); this node is healthy and takeover-ready, so it requests "+
			"the RG through the transfer protocol (#19140)", "rg", rgID)
		if m.history != nil {
			m.history.Record(EventRG, rgID, "Member-shim takeover: requesting the RG from the peer")
		}
	} else {
		slog.Debug("cluster: member-shim takeover attempt",
			"rg", rgID, "attempt", chain.attempts, "last_err", chain.lastErr)
	}
	run := func() { m.runMemberShimTakeover(rgID, chain) }
	if m.memberShimTakeoverLaunchFn != nil {
		m.memberShimTakeoverLaunchFn(run)
		return
	}
	go run()
}

// runMemberShimTakeover is one attempt. Called WITHOUT m.mu.
func (m *Manager) runMemberShimTakeover(rgID int, chain *memberShimTakeover) {
	// The admission runs under m.mu at the reservation and again in the
	// commit's critical section. Both times the chain and the operator epoch
	// must be current. Only the reservation, before anything is sent, also
	// requires the owner to still advertise the debt: once the owner has
	// fenced and acked, completing the transfer to this ready node is the
	// lesser disruption, and aborting would bounce the RG through the
	// owner's fence twice.
	reserving := true
	admit := func() error {
		if m.memberShimTakeovers[rgID] != chain || m.operatorEpoch[rgID] != chain.opEpoch {
			return errMemberShimTakeoverStale
		}
		if reserving {
			reserving = false
			if !m.peerCarriesMemberShimDebtLocked(rgID) {
				return errMemberShimOwnerRecovered
			}
		}
		return nil
	}
	err := m.requestPeerFailover(rgID, admit, false)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.memberShimTakeovers[rgID] != chain {
		return // cancelled while in flight
	}
	chain.inFlight = false
	if err == nil {
		delete(m.memberShimTakeovers, rgID)
		slog.Info("cluster: member-shim takeover committed; this node is now primary for the redundancy group (#19140)",
			"rg", rgID, "attempts", chain.attempts)
		if m.history != nil {
			m.history.Record(EventRG, rgID, fmt.Sprintf("Member-shim takeover committed after %d attempt(s)", chain.attempts))
		}
		return
	}
	chain.lastErr = err.Error()
	if errors.Is(err, errMemberShimTakeoverStale) || errors.Is(err, errMemberShimOwnerRecovered) {
		delete(m.memberShimTakeovers, rgID)
		slog.Info("cluster: member-shim takeover abandoned (#19140)", "rg", rgID, "err", err)
		return
	}
	if chain.attempts > 1 {
		chain.backoff *= 2
		if chain.backoff > memberShimTakeoverBackoffMax {
			chain.backoff = memberShimTakeoverBackoffMax
		}
	}
	chain.nextAt = time.Now().Add(chain.backoff)
	slog.Debug("cluster: member-shim takeover refused; backing off",
		"rg", rgID, "attempt", chain.attempts, "err", err, "next_in", chain.backoff)
}
