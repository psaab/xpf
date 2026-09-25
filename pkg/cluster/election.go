package cluster

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// EffectivePriority calculates the effective priority for a node.
// effective = base_priority * (weight / 255)
// Returns an integer value scaled to avoid floating-point issues.
// Higher value = higher priority = more likely to be primary.
func EffectivePriority(basePriority, weight int) int {
	if weight <= 0 {
		return 0
	}
	return basePriority * weight / 255
}

// electionResult is the outcome of a per-RG election.
type electionResult int

const (
	electLocalPrimary   electionResult = iota // local node should be primary
	electLocalSecondary                       // local node should be secondary
	electNoChange                             // no state change needed
)

// elect performs election for a single RG considering peer state.
// It implements the full Junos-style election logic:
//   - If peer is lost, local becomes primary (if weight > 0)
//   - If peer is alive, compare effective priorities
//   - Preempt: higher effective priority wins immediately
//   - Non-preempt: incumbent stays unless weight drops to 0
//   - Split-brain (both primary): lower node ID wins
func (m *Manager) electRG(rg *RedundancyGroupState, peerGroup *PeerGroupState) (electionResult, string) {
	// Skip disabled groups entirely.
	if rg.State == StateDisabled {
		return electNoChange, ""
	}

	// #1930 INC-2: a node booted as a kernel-upgrade CANDIDATE holds SECONDARY
	// unconditionally until the promotion gate verifies the dataplane. Unlike
	// ManualFailover (which the isolated-node path below auto-clears after 2s so
	// a lone node can reclaim primary), this hold is NOT auto-cleared — a
	// candidate with a broken dataplane must NEVER become primary even if it
	// can't see the peer, or it would blackhole traffic (r2 AGY Critical). It is
	// cleared only by promote/rejoin/revert (KernelUpgradeHoldClear).
	if m.kernelUpgradeHold {
		return electNoChange, ""
	}

	clearedManualFailover := false

	// ManualFailover normally blocks election (stays secondary-hold until
	// reset). Exception: if the peer has also explicitly transferred out or
	// already resigned with weight 0, both nodes can end up parked as
	// non-owners. Clear ManualFailover and restore normal election after a
	// short guard window so one node can reclaim primary.
	//
	// Time guard: only clear after 2s to prevent re-promoting a node that
	// JUST transferred out. Without this, the resigned node sees stale peer
	// transfer-out or weight=0 state and immediately re-elects itself as
	// primary, defeating the handoff.
	if rg.ManualFailover {
		// Owner-side transfer-out lease (#5079). A peer-requested transfer-out
		// demoted us BEFORE the requester ran its own post-ACK commit checks. If
		// the requester aborted after the ACK — or crashed / lost the fabric — it
		// sent no commit AND no abort, and it may have rolled back to a HEALTHY
		// secondary, a state the dual-resign guard below never rescues (that guard
		// needs the peer resigned or itself in secondary-hold). Once the lease
		// expires with no commit, restore ourselves so a failed coordinated
		// failover cannot leave both nodes secondary. A committed transfer clears
		// the lease first (reqID-bound), so this never fires on a real handoff.
		if until, leased := m.remoteTransferOutLeaseUntil[rg.GroupID]; leased && !time.Now().Before(until) {
			slog.Warn("cluster: remote transfer-out lease expired without commit, restoring",
				"rg", rg.GroupID, "req_id", m.remoteTransferOutLeaseReqID[rg.GroupID])
			m.clearRemoteTransferOutLeaseLocked(rg.GroupID)
			rg.ManualFailover = false
			rg.ManualFailoverAt = time.Time{}
			m.manualFailoverRestoreWeightLocked(rg)
			clearedManualFailover = true
			// Fall through to normal priority/tie-break election below.
		} else {
			peerResigned := peerGroup != nil && peerGroup.Weight <= 0
			peerTransferOut := peerGroup != nil && peerGroup.State == StateSecondaryHold
			if !peerResigned && !peerTransferOut {
				return electNoChange, ""
			}
			if time.Since(rg.ManualFailoverAt) < 2*time.Second {
				return electNoChange, ""
			}
			// The peer has also yielded for >2s. Clear manual failover and
			// restore weight so normal election can promote one node.
			slog.Info("cluster: clearing manual failover (peer also yielded)",
				"rg", rg.GroupID,
				"peer_state", peerGroup.State.String(),
				"peer_weight", peerGroup.Weight)
			rg.ManualFailover = false
			rg.ManualFailoverAt = time.Time{}
			// Recalculate weight (recalcWeight calls runElection which would
			// recurse back to electRG).
			m.manualFailoverRestoreWeightLocked(rg)
			clearedManualFailover = true
		}
	}

	localWeight := rg.Weight
	localPriority := rg.LocalPriority

	// No peer info — single-node election.
	if peerGroup == nil {
		if !m.peerAlive {
			// Non-preempt in cluster mode: don't claim primary on fresh
			// boot before hearing from the peer. Wait for heartbeat
			// timeout to confirm peer is truly down.
			if !rg.Preempt && !m.peerEverSeen && !m.peerConfirmedAbsent && rg.State == StateSecondary && m.controlInterface != "" {
				return electNoChange, ""
			}
			// Peer lost (was alive, now timed out) or preempt mode.
			if localWeight > 0 && rg.State != StatePrimary {
				return electLocalPrimary, "Peer lost"
			}
			if localWeight <= 0 && rg.State != StateSecondary {
				return electLocalSecondary, "Local weight 0"
			}
			return electNoChange, ""
		}
		// Peer alive but no group info for this RG — we take primary.
		if localWeight > 0 && rg.State != StatePrimary {
			return electLocalPrimary, "Peer has no RG info"
		}
		return electNoChange, ""
	}

	peerWeight := peerGroup.Weight
	peerPriority := peerGroup.Priority

	localEff := EffectivePriority(localPriority, localWeight)
	peerEff := EffectivePriority(peerPriority, peerWeight)

	// Weight 0 → always secondary.
	if localWeight <= 0 {
		if rg.State != StateSecondary {
			return electLocalSecondary, "Local weight 0"
		}
		return electNoChange, ""
	}

	// Peer weight 0 → we should be primary.
	if peerWeight <= 0 {
		if rg.State != StatePrimary {
			return electLocalPrimary, "Peer weight 0"
		}
		return electNoChange, ""
	}

	// An explicit peer transfer-out should hand ownership to us without
	// mutating the peer's monitor-derived weight. If both sides had been in
	// manual transfer-out and we just cleared our own guard, fall through to
	// normal priority/tie-break election instead of unconditionally claiming
	// primary on both nodes.
	if peerGroup.State == StateSecondaryHold && !clearedManualFailover {
		if rg.State != StatePrimary {
			return electLocalPrimary, "Peer transfer out"
		}
		return electNoChange, ""
	}

	// Preempt enabled: higher effective priority wins.
	// This takes priority over split-brain detection since preempt explicitly
	// requests priority-based election.
	if rg.Preempt {
		if localEff > peerEff {
			if rg.State != StatePrimary {
				return electLocalPrimary, "Preempt: higher priority"
			}
			if peerGroup.State == StatePrimary {
				// A preempt-enabled dual-active winner can already be
				// primary, so there is no state transition to trigger the
				// direct-VIP GARP/NA refresh. Reuse the reaffirm reason used
				// by the non-preempt dual-active path.
				return electNoChange, "Dual-active: winner stays"
			}
		} else if localEff < peerEff {
			if rg.State != StateSecondary {
				return electLocalSecondary, "Preempt: lower priority"
			}
		} else {
			// Tie: lower node ID wins.
			if m.nodeID < m.peerNodeID {
				if rg.State != StatePrimary {
					return electLocalPrimary, "Lower node ID wins tie"
				}
				if peerGroup.State == StatePrimary {
					return electNoChange, "Dual-active: winner stays"
				}
			} else if m.nodeID > m.peerNodeID {
				if rg.State != StateSecondary {
					return electLocalSecondary, "Higher node ID loses tie"
				}
			} else {
				// Same node ID → INVALID cluster (duplicate node-id, #4549
				// F11). No asymmetric tie-break exists, so fail CLOSED to
				// SECONDARY rather than leaving the incumbent primary — if
				// both nodes are primary the previous "no change" left the
				// split-brain unresolved. Surfaced loudly for the operator.
				m.warnDuplicateNodeIDLocked()
				if rg.State != StateSecondary {
					return electLocalSecondary, "Preempt: duplicate node-id yields (invalid config)"
				}
			}
		}
		return electNoChange, ""
	}

	// Non-preempt: incumbent stays unless weight drops to 0.
	// If we are currently secondary and peer is primary, we stay secondary.
	// If we are currently primary, we stay primary (peer can't preempt us).
	// If neither is primary (both secondary, e.g. initial state), use priority.
	if rg.State == StatePrimary {
		if peerGroup.State == StatePrimary {
			// DUAL-ACTIVE: resolve by effective priority, then node ID.
			if localEff < peerEff {
				return electLocalSecondary, "Dual-active: lower priority yields"
			}
			if localEff == peerEff && m.nodeID > m.peerNodeID {
				return electLocalSecondary, "Dual-active: higher node ID yields"
			}
			// Same effective priority AND same node ID is an INVALID cluster
			// (two chassis sharing a node-id, #4549 F11). No asymmetric
			// discriminator remains — both nodes run this identical code and
			// would compute the same result, so no single primary can be
			// deterministically elected. Fail CLOSED: yield to SECONDARY so we
			// never leave both nodes primary (a dual-primary split-brain =
			// duplicate VIP / ARP conflict). Surfaced loudly so the operator
			// fixes the duplicate node-id.
			if localEff == peerEff && m.nodeID == m.peerNodeID {
				m.warnDuplicateNodeIDLocked()
				return electLocalSecondary, "Dual-active: duplicate node-id yields (invalid config)"
			}
			return electNoChange, "Dual-active: winner stays"
		}
		return electNoChange, "" // non-preempt: incumbent stays
	}

	if peerGroup.State == StatePrimary {
		// Peer is primary and we're not — stay secondary.
		if rg.State != StateSecondary {
			return electLocalSecondary, "Peer is primary"
		}
		return electNoChange, ""
	}

	// Neither is primary (initial state) — use effective priority to decide.
	if localEff > peerEff {
		return electLocalPrimary, "Higher priority"
	} else if localEff < peerEff {
		if rg.State != StateSecondary {
			return electLocalSecondary, "Lower priority"
		}
	} else {
		// Tie: lower node ID wins.
		if m.nodeID < m.peerNodeID {
			return electLocalPrimary, "Lower node ID wins tie"
		}
		// Same node ID → duplicate-node-id misconfig (#4549 F11). The
		// higher-node-ID-loses fall-through already yields to SECONDARY here
		// (fail closed — both nodes stay secondary, no split-brain), but the
		// misconfig is otherwise silent, so surface it.
		if m.nodeID == m.peerNodeID {
			m.warnDuplicateNodeIDLocked()
		}
		if rg.State != StateSecondary {
			return electLocalSecondary, "Higher node ID loses tie"
		}
	}
	return electNoChange, ""
}

// warnDuplicateNodeIDLocked emits a rate-limited (>=30s) error when the peer
// advertises the local node's own node-id. Two chassis sharing a node-id is an
// invalid cluster configuration: the HA protocol carries no per-node identity
// other than the node-id, so election has no asymmetric discriminator to elect
// a single primary — the condition cannot be resolved at runtime and both nodes
// fail closed to SECONDARY. The only remedy is correcting /etc/xpf/node-id on
// one chassis. Must be called with m.mu held.
func (m *Manager) warnDuplicateNodeIDLocked() {
	now := time.Now()
	if !m.lastDupNodeIDWarn.IsZero() && now.Sub(m.lastDupNodeIDWarn) < 30*time.Second {
		return
	}
	m.lastDupNodeIDWarn = now
	slog.Error("cluster: duplicate node-id detected — the peer advertises the "+
		"same node-id as this node; this is an INVALID cluster configuration "+
		"(two chassis cannot share a node-id). Election has no way to resolve "+
		"it, so both nodes fail closed to SECONDARY. Correct /etc/xpf/node-id "+
		"on one node.",
		"node_id", m.nodeID)
	if m.history != nil {
		m.history.Record(EventRG, -1, "duplicate node-id: invalid cluster configuration")
	}
}

// NoteDuplicateNodeIDHeartbeat records that a heartbeat arrived carrying the
// local node's own node-id. On a unicast point-to-point control link a node
// never receives its own frame, so a same-cluster frame with our node-id is a
// peer misconfigured with a duplicate node-id — an invalid cluster (#4549 F11).
// The receiver still discards the frame (it cannot be told apart from a stray
// loopback and a duplicate-node-id cluster is unresolvable at runtime), but the
// rate-limited warning surfaces the misconfiguration for the operator. Takes
// m.mu.
func (m *Manager) NoteDuplicateNodeIDHeartbeat() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warnDuplicateNodeIDLocked()
}

// runElection evaluates all RGs using current peer state and applies transitions.
// Must be called with m.mu held.
func (m *Manager) runElection() {
	for _, rg := range m.groups {
		var peerGroup *PeerGroupState
		if pg, ok := m.peerGroups[rg.GroupID]; ok {
			peerGroup = &pg
		}

		result, reason := m.electRG(rg, peerGroup)

		// Readiness gate: block NEW promotions to primary if the RG
		// hasn't been ready for takeoverHoldTime. This does NOT demote
		// an already-primary node. Only applies in cluster mode
		// (controlInterface configured) — standalone nodes skip the gate.
		degradedReason := ""
		if result == electLocalPrimary && rg.State != StatePrimary && m.controlInterface != "" {
			// #7939: through the SHARED verdict, so this path gets the degraded
			// fallback electSingleNode already had. Before this, a stuck
			// readiness term here left the RG secondary on both nodes with no
			// way out — see readinessGateVerdictLocked.
			promote, degReason := m.readinessGateVerdictLocked(rg)
			if promote {
				degradedReason = degReason
			} else if yieldReason, unowned := peerYieldedOwnership(peerGroup); unowned {
				// #9452: the peer is ALIVE and reports it is NOT the owner, so
				// holding this RG secondary leaves it owned by NEITHER node.
				// Promote DEGRADED and say so loudly — see
				// peerYieldedOwnership for why this is not the cold-boot case
				// the gate exists for.
				degradedReason = fmt.Sprintf(
					"Promoted DEGRADED: %s while this node is not ready (%s); "+
						"holding secondary would leave redundancy group %d owned by neither node",
					yieldReason, readinessReasonText(rg), rg.GroupID)
			} else {
				slog.Info("cluster: election blocked by readiness gate",
					"rg", rg.GroupID, "ready", rg.Ready,
					"readySince", rg.ReadySince,
					"holdTime", m.takeoverHoldTime,
					"reasons", rg.ReadinessReasons)
				continue
			}
		}

		oldState := rg.State

		switch result {
		case electLocalPrimary:
			rg.State = StatePrimary
		case electLocalSecondary:
			rg.State = StateSecondary
		case electNoChange:
			// Dual-active winner: state unchanged but emit ownership
			// reaffirm event so daemon can send GARPs to refresh
			// upstream ARP/NDP caches.
			if reason == "Dual-active: winner stays" {
				select {
				case m.eventCh <- ClusterEvent{
					GroupID:       rg.GroupID,
					OldState:      StatePrimary,
					NewState:      StatePrimary,
					DualActiveWin: true,
				}:
				default:
					// Full channel. The dual-active reaffirm is the ONLY
					// signal that drives the daemon's post-split-brain
					// GARP/NA refresh (daemon_ha.go: DualActiveWin ->
					// scheduleDirectAnnounce). A silent drop here blackholes
					// that refresh — peers keep the losing node's MAC in their
					// ARP/NDP caches after the winner is elected (#4867).
					//
					// Match sendEvent's reliable drop handling: log and fire
					// the generic reconcile fallback (onEventDrop ->
					// triggerReconcile). But the reconcile alone does NOT
					// cover this event — the direct-VIP ownership reconcile
					// only re-announces on an ownership CHANGE
					// (announce = !prev || added>0), and a dual-active winner
					// is already the steady owner, so triggerReconcile would
					// not re-drive the announce. Also invoke the dedicated
					// reaffirm-drop callback (onDualActiveWinDrop ->
					// scheduleDirectAnnounce) so the GARP/NA refresh genuinely
					// survives the drop. Both callbacks run with m.mu held and
					// must not re-enter the manager lock or block inline.
					slog.Warn("cluster: event channel full, dropping dual-active reaffirm event; invoking reconcile + re-announce fallback",
						"rg", rg.GroupID)
					if m.onEventDrop != nil {
						m.onEventDrop()
					}
					if m.onDualActiveWinDrop != nil {
						m.onDualActiveWinDrop(rg.GroupID)
					}
				}
				m.history.Record(EventRG, rg.GroupID, "dual-active resolved: winner reaffirm")
			}
			continue
		}

		if oldState != rg.State {
			// Track failover count for primary→non-primary transitions.
			if oldState == StatePrimary {
				rg.FailoverCount++
			}
			// #7939: a promotion that only happened because the degraded
			// timeout expired must be MARKED and said loudly, exactly as
			// electSingleNode does. The RG is forwarding while not ready, which
			// is the right trade against both nodes staying secondary — but it
			// is not a normal promotion and must not read as one in the event
			// stream or in `show chassis cluster status`.
			if degradedReason != "" && rg.State == StatePrimary {
				rg.DegradedPromoted = true
				reason = degradedReason
				// #9452: NOT "after degraded timeout". This site now has two
				// causes — the #7161/#7939 timeout, and a live peer that has
				// yielded the RG — and naming one of them in the message makes
				// the message wrong half the time. The CAUSE is in `reason`,
				// which is the field that actually varies. electSingleNode's
				// twin still has exactly one cause and still names it.
				slog.Warn("cluster: promoting NOT-READY RG",
					"rg", rg.GroupID, "reason", degradedReason)
			}
			m.sendEvent(rg.GroupID, oldState, rg.State, reason)
		}
	}
}

// electSingleNode performs election when no heartbeat peer is present.
// In single-node mode, the local node is always primary if weight > 0.
// Non-preempt exception: if the peer has never been seen (fresh boot),
// stay secondary and wait for the heartbeat timeout to confirm the peer
// is truly absent before claiming primary.
func (m *Manager) electSingleNode() {
	// #1930 INC-2 r2 AGY Critical: a kernel-upgrade candidate boot holds
	// SECONDARY unconditionally — and the single-node path is exactly where an
	// isolated candidate would otherwise auto-promote (no peer to hold it back).
	// The hold is NOT auto-cleared (unlike ManualFailover), so an isolated
	// candidate with a broken dataplane never claims primary. Cleared only by
	// promote/rejoin/revert.
	if m.kernelUpgradeHold {
		return
	}
	for _, rg := range m.groups {
		if rg.State == StateDisabled || rg.ManualFailover {
			continue
		}
		// Non-preempt in cluster mode: don't claim primary on fresh boot
		// before hearing from the peer. The peer may be running as
		// primary — wait for heartbeat timeout to confirm it's truly
		// down. controlInterface != "" indicates cluster mode (heartbeat
		// configured); standalone nodes always elect immediately.
		if !rg.Preempt && !m.peerEverSeen && !m.peerConfirmedAbsent && rg.State == StateSecondary && m.controlInterface != "" {
			continue
		}
		// Readiness gate: block new promotions in cluster mode until
		// interfaces + VRRP are confirmed ready for holdTime. Does not gate
		// standalone mode (no controlInterface).
		//
		// #7161: the gate applies on a COLD BOOT (`!peerEverSeen`) but is
		// bypassed on a genuine peer LOSS (`peerEverSeen && !peerAlive`). The
		// two cases differ for a real reason:
		//
		//   - peer LOSS: an established cluster had a working primary and it
		//     died. A survivor that refuses takeover is a TOTAL OUTAGE, and it
		//     may be the only node that can forward. Fail open.
		//   - cold BOOT: there is no established forwarding to preserve, and a
		//     not-ready node that promotes FORWARDS NOTHING ANYWAY — it claims
		//     the VIPs and the RG while unable to serve them, and denies the
		//     peer a clean takeover. Promoting buys nothing.
		//
		// The prior rationale here read "sync readiness is impossible without a
		// peer". That argued for bypassing a term that is not in this
		// conjunction: `IsReadyForTakeover` consults local interfaces
		// (Monitor.RGInterfaceReady), local VRRP (RGVRRPReady /
		// checkNoRethTakeoverReadiness) and the local userspace dataplane
		// (checkUserspaceTakeoverReadinessFor) — all determinable with no peer —
		// and `fabricReady` is already forced true when the peer is down.
		//
		// peerEverSeen remains false on a confirmed-absent cold boot, so this
		// gate still applies after the non-preempt hold is released. Only a
		// genuine peer loss (ever seen, now dead) bypasses readiness.
		degradedReason := ""
		if rg.State != StatePrimary && rg.Weight > 0 && m.controlInterface != "" &&
			(m.peerAlive || !m.peerEverSeen) {
			// #7939: the same shared verdict runElection uses. Written out
			// separately here before, which is how the two drifted apart.
			promote, reason := m.readinessGateVerdictLocked(rg)
			if !promote {
				continue
			}
			degradedReason = reason
		}
		oldState := rg.State
		if rg.Weight > 0 {
			rg.State = StatePrimary
		} else {
			rg.State = StateSecondary
		}
		if oldState != rg.State {
			reason := "Only node present"
			if degradedReason != "" && rg.State == StatePrimary {
				rg.DegradedPromoted = true
				reason = degradedReason
				slog.Warn("cluster: promoting NOT-READY RG after degraded timeout",
					"rg", rg.GroupID, "reason", degradedReason)
			}
			m.sendEvent(rg.GroupID, oldState, rg.State, reason)
		}
	}
}

// SetMonitorWeight updates the weight contribution of an interface monitor.
// down=true subtracts weight; down=false restores it.
//
// #6549: this is the CHOKEPOINT that bounds election debt. Together with
// reconcileMonitorDebtsLocked it owns both of the only two writes into
// m.monitorWeights, so clamping here closes the debt domain against EVERY
// producer — including one added later that forgets to bound its own value.
//
// Each producer ALSO bounds the weight where it computes it, because each
// reports that weight somewhere the chokepoint cannot reach (a heartbeat
// monitor entry, a rendered status, an event ledger) and a producer-side
// clamp is the only way the reported value matches the applied one. So this
// is a genuine second belt, not the sole defense:
//
//   - pkg/cluster/monitor.go pollInterfaceMonitors — interface-monitor link
//     transitions. Clamps its own copy, which also feeds the heartbeat
//     monitor section.
//   - pkg/cluster/monitor.go ipTargetWeight / desiredRGIPDebts —
//     ip-monitoring target and aggregate debts. Those bound the value before
//     it reaches the cumulative global-threshold sum, which this chokepoint
//     could not protect: a masked threshold installs NO debt, so
//     SetMonitorWeight is never called at all.
//   - pkg/routing/monitor.go monitorManager.Apply — the statuses
//     pkg/daemon/daemon_apply_tail.go feeds back in on EVERY commit / boot
//     Load / peer SyncApply. Before either clamp existed, that raw value
//     landed here six lines after UpdateConfig had already clamped the same
//     debt, so the apply tail OVERWROTE the clamp and could restore a
//     correctly-demoted group to primary with every monitored link down. The
//     poll path cannot repair it: pollInterfaceMonitors re-fires
//     SetMonitorWeight only on a dampened state TRANSITION, and a link that
//     was already down before the apply produces none, so the raw debt
//     persists indefinitely.
func (m *Manager) SetMonitorWeight(rgID int, iface string, down bool, weight int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rg, ok := m.groups[rgID]
	if !ok {
		return
	}

	// Bound the debt to the [0,255] domain the heartbeat weight fields carry.
	// A negative weight is negative DEBT: it credits weight back and cancels a
	// sibling monitor's real failure (fail-open); an over-255 one diverges the
	// local weight from the advertised one (dual primary). Both reach runtime
	// because the tolerant load / peer-sync compile path downgrades the commit
	// gate to a warning (#1960 no-brick).
	//
	// CLAMP DIRECTION — negative maps to 0, deliberately. This was contested in
	// review (clamping to 255 was argued as the fail-CLOSED choice, since an
	// inert monitor can leave a node primary behind a dead link) and settled on
	// 0. Recorded here so it is not re-litigated:
	//
	//   - 0 is an already-legal, operator-reachable state. An interface-monitor
	//     with no `weight` token compiles to exactly 0 and means "monitor this,
	//     contribute no debt". Clamping onto 0 maps invalid input onto an
	//     existing semantic; clamping onto 255 maps it onto a DIFFERENT existing
	//     semantic ("maximally fatal") that the operator never asked for.
	//   - The decisive asymmetry is the peer-push path. The reason this class is
	//     hardened at runtime at all is that configs arrive over HA config-sync.
	//     Under clamp-255, a typo'd `-100` pushed from the peer makes the
	//     RECEIVING node instantly resign its redundancy group the moment that
	//     link flaps — turning the config-sync channel into a remote HA
	//     denial-of-service. Inert-plus-WARN beats auto-resignation there.
	//   - The local authoring path can never produce this at all
	//     (validateChassisClusterStrict hard-rejects it at commit), so the only
	//     ways here are a pre-fix persisted config or a peer push — exactly the
	//     cases where the above holds.
	//
	// Over-255 saturates to 255: that preserves operator intent, and 255 is
	// already the maximum meaningful debt since the group starts there.
	requested := weight
	weight, clamped := config.ClampInterfaceMonitorWeight(weight)

	key := monitorKey{rgID: rgID, iface: iface}

	if down {
		if clamped {
			// Debt-install frequency (a dampened transition, an ip-debt diff,
			// or a config apply), not per-poll-tick — safe at Warn.
			//
			// In practice every current producer bounds the weight before it
			// gets here, so reaching this branch means a producer skipped its
			// own clamp — which is exactly what makes it worth logging. Do NOT
			// read a missing warning here as "no out-of-range weight was
			// configured": the interface-monitor class is reported by
			// reconcileMonitorDebtsLocked against the config that carried it,
			// and the ip-monitoring class is bounded upstream in ipTargetWeight
			// / desiredRGIPDebts. Those are the places to look first.
			slog.Warn("cluster: monitor debt weight out of range, clamped",
				"rg", rgID, "interface", iface,
				"requested", requested, "effective", weight,
				"issue", "#6549")
		}
		// Record the monitor weight and add to failure list.
		m.monitorWeights[key] = weight
		found := false
		for _, f := range rg.MonitorFails {
			if f == iface {
				found = true
				break
			}
		}
		if !found {
			rg.MonitorFails = append(rg.MonitorFails, iface)
			sort.Strings(rg.MonitorFails)
			slog.Warn("cluster: interface monitor failure",
				"rg", rgID, "interface", iface, "weight", weight)
		}
	} else {
		// Remove from failures and delete stored weight.
		delete(m.monitorWeights, key)
		for i, f := range rg.MonitorFails {
			if f == iface {
				rg.MonitorFails = append(rg.MonitorFails[:i], rg.MonitorFails[i+1:]...)
				slog.Info("cluster: interface monitor recovered",
					"rg", rgID, "interface", iface)
				break
			}
		}
	}

	m.recalcWeight(rg)
}

// maxRedundancyGroupWeight is the full (no-debt) redundancy-group weight AND
// the largest value the weight domain admits. It is both the Junos starting
// weight and the ceiling of the single-byte heartbeat weight field
// (HeartbeatGroup.Weight is uint8, heartbeat.go).
const maxRedundancyGroupWeight = 255

// DataplaneArmMonitorIface is the synthetic interface-monitor name the daemon
// uses to express "this node's dataplane is not ready to serve" as
// redundancy-group weight debt (#7178, #9842).
//
// It is deliberately not a legal Junos or Linux interface name, so it can never
// collide with a configured `track-interface` entry, and it is exported so the
// daemon writes ONE agreed key rather than a string literal on each side.
const DataplaneArmMonitorIface = "__dataplane-arm__"

// DataplaneArmMonitorCost is the weight debt a dataplane that is not ready to
// serve contributes: enough to lose to any peer that IS ready, but NOT enough
// to reach weight 0.
//
// #7178/#9842: the floor is the design, not an implementation detail. A node
// whose dataplane failed to arm, or whose arm has not yet yielded a kernel-
// proven XDP link, forwards no transit (#5275/#9725 close kernel forwarding)
// while deliberately keeping management up, so on a cluster the right answer
// is "let the peer have it" — which a large debt achieves, because the election
// is RELATIVE and a ready peer at 255 outbids this node at 1.
//
// But driving the weight to 0 would also demote a STANDALONE node that has no
// ready dataplane, and there nothing else picks up the VIPs. Landing at 1 keeps
// a lone node primary and lets a healthy peer win, from one rule rather than a
// special case.
//
// The floor of 1 also mirrors the VRRP `track-interface priority-cost` clamp of
// [1,254]: that machinery already settled that "demoted" means the bottom of
// the range, never out of it.
const DataplaneArmMonitorCost = maxRedundancyGroupWeight - 1

// rgWeightFromDebt converts a redundancy group's accumulated monitor debt into
// its effective weight, bounded to [0, maxRedundancyGroupWeight].
//
// The floor has always been enforced (a debt larger than 255 resigns the group
// at weight 0). #6549 adds the CEILING, which is what keeps the local weight
// and the advertised weight from diverging: buildHeartbeat marshals the weight
// as `uint8(rg.Weight)` while the local election reads the raw int, so a weight
// above 255 truncates on the wire (355 -> 99) and the two nodes compute
// different effective priorities from identical state — both can elect primary,
// putting a duplicate VIP and duplicate RETH virtual MAC on the LAN. A NEGATIVE
// debt is the way that happens in practice: an interface-monitor weight is
// operator-supplied and the tolerant load / peer-sync compile path only WARNS
// on an out-of-range one (#1960 no-brick), so `weight -100` on a down monitor
// reaches here as totalLost == -100.
//
// Bounding here rather than only at the marshal boundary is deliberate: a
// marshal-side clamp would still leave the local view (355) disagreeing with
// the advertised one (255). The weight domain itself has to be closed, and it
// is closed for EVERY debt source — interface monitors, ip-monitoring targets,
// and any future SetMonitorWeight caller — not just the configured one.
func rgWeightFromDebt(totalLost int) int {
	w := maxRedundancyGroupWeight - totalLost
	if w < 0 {
		return 0
	}
	if w > maxRedundancyGroupWeight {
		return maxRedundancyGroupWeight
	}
	return w
}

// recalcWeight recalculates the effective weight for a redundancy group
// and triggers re-election if needed.
func (m *Manager) recalcWeight(rg *RedundancyGroupState) {
	totalLost := 0
	for _, iface := range rg.MonitorFails {
		key := monitorKey{rgID: rg.GroupID, iface: iface}
		totalLost += m.monitorWeights[key]
	}
	oldWeight := rg.Weight
	rg.Weight = rgWeightFromDebt(totalLost)
	if oldWeight != rg.Weight {
		slog.Info("cluster: weight changed",
			"rg", rg.GroupID, "old", oldWeight, "new", rg.Weight)
	}
	if m.peerAlive {
		m.runElection()
	} else {
		m.electSingleNode()
	}
}

// reconcileMonitorDebtsLocked realigns each RG's installed interface-monitor
// debt with the COMPLETE current desired monitor set (#5080). It is the
// stale-debt half of the reconcile invariant: UpdateConfig otherwise only
// swaps the desired monitor slice, so a debt installed for a monitor that the
// operator later REMOVES or CHANGES (interface renamed) would persist,
// stranding a healthy node secondary even though the failed monitor is gone.
//
// Two corrections are applied against m.monitorWeights (which holds exactly the
// set of currently-failed monitors, kept in sync with each RG's MonitorFails):
//
//   - Removed/changed keys — a monitor whose (rgID, iface) is no longer desired
//     has its debt cleared (weight deleted, name dropped from MonitorFails).
//   - Changed weights — a still-failed monitor whose configured weight changed
//     has its debt re-derived to the new weight. The interface stays down, so
//     no dampening transition would re-fire SetMonitorWeight; the reconcile
//     must apply it here.
//
// Each affected RG's effective weight is then recomputed from its now-current
// debt set. The caller (UpdateConfig) re-runs the election after this returns,
// so no election is triggered here. Must be called with m.mu held.
//
// This reconcile touches INTERFACE-monitor debt ONLY. IP-monitoring debt lives
// in the same m.monitorWeights / rg.MonitorFails structure (installed by
// SetMonitorWeight from the ip-monitor path under "ip:<addr>" and the aggregate
// ipAggregateMonitorName) but is owned by the Monitor's reconcileRGIPDebts,
// which drives it to the desired set every poll. `desired` here is built only
// from InterfaceMonitors, so ip keys are skipped in the removal loop
// (isIPMonitorName) — deleting them would wipe LIVE ip-monitoring debt on any
// unrelated config change and fail open (#5080 fold).
func (m *Manager) reconcileMonitorDebtsLocked(cfg *config.ClusterConfig) {
	// Build the complete desired interface-monitor key→weight map.
	desired := make(map[monitorKey]int)
	for _, rg := range cfg.RedundancyGroups {
		for _, im := range rg.InterfaceMonitors {
			// #6549: bound the configured debt. The strict commit path already
			// rejected an out-of-range weight (validateChassisClusterStrict);
			// the tolerant load / peer-sync path only WARNS (#1960 no-brick),
			// so a persisted or peer-pushed config can still carry one here.
			w, clamped := config.ClampInterfaceMonitorWeight(im.Weight)
			if clamped {
				// Config-apply frequency, not per-poll — safe at Warn.
				slog.Warn("cluster: interface-monitor weight out of range, clamped",
					"rg", rg.ID, "interface", im.Interface,
					"configured", im.Weight, "effective", w,
					"issue", "#6549")
			}
			desired[monitorKey{rgID: rg.ID, iface: im.Interface}] = w
		}
	}

	affected := make(map[int]struct{})

	// Clear debt for monitors no longer desired (removed, or the monitored
	// interface was changed to a different name).
	for key := range m.monitorWeights {
		// IP-monitor debts share monitorWeights / MonitorFails with
		// interface-monitor debts but are OWNED by reconcileRGIPDebts, which
		// drives them to the desired set on every poll and clears removed ones
		// (whole-RG teardown at RG removal handles a dropped RG). `desired`
		// here is built only from InterfaceMonitors, so an ip key would always
		// look "no longer desired" — deleting it would wipe a LIVE ip-monitoring
		// debt on any unrelated config change, recompute the RG weight without
		// it, and fail open (a node with a dead monitored uplink could win
		// election). Skip every ip key (#5080 fold).
		// #8338: skip every key this reconciler does not OWN, not just the IP
		// class. The previous shape exempted only `isIPMonitorName`, so the
		// reserved `__dataplane-arm__` debt — which is never in `desired`,
		// because `desired` is built solely from `InterfaceMonitors` — was
		// deleted by every commit that reached here. `applyDataplaneReadyTrack`
		// is edge-triggered from the three ready-transition helpers, so a commit
		// taken while the node was ALREADY unready reinstalled nothing: the
		// node kept forwarding nothing and lost the penalty that expressed it,
		// and could then win an election and hold the RG as a blackhole.
		//
		// Ownership is now POSITIVE. A future reserved debt is safe by default
		// rather than requiring someone to remember a third exemption here.
		if isReservedMonitorName(key.iface) {
			continue
		}
		if _, ok := desired[key]; ok {
			continue
		}
		delete(m.monitorWeights, key)
		if rg, ok := m.groups[key.rgID]; ok {
			for i, f := range rg.MonitorFails {
				if f == key.iface {
					rg.MonitorFails = append(rg.MonitorFails[:i], rg.MonitorFails[i+1:]...)
					break
				}
			}
			affected[key.rgID] = struct{}{}
		}
	}

	// Reapply a changed weight for a monitor that is still failed.
	for key, w := range desired {
		if cur, ok := m.monitorWeights[key]; ok && cur != w {
			m.monitorWeights[key] = w
			affected[key.rgID] = struct{}{}
		}
	}

	// Recompute the effective weight of each affected RG from its now-current
	// debt set (mirrors recalcWeight's arithmetic without re-electing).
	for rgID := range affected {
		rg, ok := m.groups[rgID]
		if !ok {
			continue
		}
		totalLost := 0
		for _, iface := range rg.MonitorFails {
			totalLost += m.monitorWeights[monitorKey{rgID: rgID, iface: iface}]
		}
		oldWeight := rg.Weight
		rg.Weight = rgWeightFromDebt(totalLost)
		if oldWeight != rg.Weight {
			slog.Info("cluster: monitor debt reconciled on config change",
				"rg", rgID, "old", oldWeight, "new", rg.Weight)
		}
	}
}

// readinessGateVerdictLocked is the ONE readiness-gate decision, shared by both
// election paths.
//
// #7939: it exists because the two paths had separate copies and they diverged.
// #7161 put the degraded-promotion fallback in electSingleNode only. runElection
// — the path taken whenever `peerAlive` is true, which is where a cluster spends
// its life — kept a bare gate with no fallback, so #7161's guarantee that "a
// readiness bug can never cost the cluster both nodes" held on the path a
// cluster is almost never on and not on the path it is almost always on.
//
// That was observed live, not derived: after a routine cluster-deploy, RG1 sat
// SECONDARY ON BOTH NODES indefinitely with `userspace XSK liveness not proven`,
// logging twice a second for minutes. It could not self-heal, because proving
// XSK liveness requires traffic and traffic requires a primary — the gate was
// holding shut the only thing that could open it. It recovered only when traffic
// was driven through the cluster by hand.
//
// Note what the divergence did to the fallback's own contract. #7161 required a
// fallback NOT gated on any peer condition, precisely so it would fire when the
// peer situation is what is wrong. Living only in electSingleNode gated it on a
// peer condition anyway — just at the placement level rather than inside the
// timer — which is the #110 shape one layer up: a fallback that cannot fire in
// the case it exists for.
//
// Returns (promote, degradedReason). promote=false means hold this RG secondary
// and the caller must not advance it. A non-empty degradedReason means promote
// ANYWAY and say so loudly — the RG is not ready, and staying secondary is worse.
//
// Caller must hold m.mu.
func (m *Manager) readinessGateVerdictLocked(rg *RedundancyGroupState) (bool, string) {
	if rg.IsReadyForTakeover(m.takeoverHoldTime) {
		return true, ""
	}
	if reason, ok := m.degradedPromoteDueLocked(rg); ok {
		return true, reason
	}
	m.armDegradedTimerLocked(rg)
	return false, ""
}

// peerYieldedOwnership reports whether the peer is ALIVE and telling us it is
// NOT the owner of this redundancy group, plus the operator-facing phrasing for
// why. When it is true, holding the local node secondary leaves the RG owned by
// NEITHER node.
//
// #9452: this is the THIRD case in the readiness gate's taxonomy and it was
// missing. electSingleNode's own comment already distinguishes the two the gate
// knew about, and the distinction is sound:
//
//   - peer LOSS: fail OPEN. An established cluster had a working primary and it
//     died; a survivor that refuses takeover is a total outage.
//   - cold BOOT: HOLD. There is no established forwarding to preserve, and a
//     not-ready node that promotes forwards nothing anyway while denying the
//     peer a clean takeover.
//
// Neither describes a peer that is up, reachable, and has just DEMOTED ITSELF.
// The cold-boot argument does not apply — there IS established forwarding, and
// it stops the instant the peer steps down. And unlike peer LOSS there is no
// split-brain hazard to weigh against promoting: the peer is not claiming the
// RG, it is telling us it gave it up. So this case fails OPEN like peer loss,
// not shut like a cold boot.
//
// MEASURED, not derived. `request chassis cluster failover redundancy-group N`
// demotes the local primary immediately and the peer's promotion then went
// through the bare gate. Issued inside the bounded #7162 30s startup promotion
// hold on a node that had just rejoined after a crash, that left RG0/RG1/RG2
// owned by NEITHER node for the REMAINDER of the hold — 19s on the #9452
// reproduction, and up to the full 30s — while the CLI had already reported
// "Manual failover triggered for redundancy group N". Nothing answered
// proxy-ARP for the pool-NAT address in that window.
//
// The iperf3 average over the same run also fell from 22.5 to 18.1 Gbit/s, and
// that is NOT this defect. The arithmetic invited the conclusion — ~25s of a
// 120s stream carrying nothing is about the right shortfall — and the fix
// refuted it: with the ownership gap closed to 0-1s, two runs came back at 18.9
// and 20.3 against a [21.4, 23.6] green band. Closing the gap bought well under
// what the theory predicted, and the 1.4 spread between two identical runs is
// itself a third of the remaining gap. A separate signal, tracked as #9484,
// and recorded here because the coincidence is convincing.
//
// Note the two arms are the two ways a live peer can report non-ownership, and
// both are safe for the same reason. StateSecondaryHold is an explicit
// transfer-out. Weight 0 is a resignation, and election forces a weight-0 node
// SECONDARY unconditionally (see the localWeight <= 0 branch in electRG), so a
// peer advertising it cannot be primary. A peer that is merely SECONDARY with
// weight > 0 is NOT included: that is the cold-boot shape, where both nodes are
// coming up and the gate must still hold.
func peerYieldedOwnership(peerGroup *PeerGroupState) (string, bool) {
	if peerGroup == nil {
		// No peer group info is peer LOSS or a peer that has not reported this
		// RG. Both are the electSingleNode / degraded-timer domain, not this
		// one — and a partitioned peer may still be forwarding as primary, so
		// promoting a not-ready node here would risk a dual-active.
		return "", false
	}
	if peerGroup.State == StateSecondaryHold {
		return "peer transferred out (secondary-hold)", true
	}
	if peerGroup.Weight <= 0 {
		return "peer resigned (weight 0)", true
	}
	return "", false
}

// readinessReasonText renders an RG's readiness reasons for an operator-facing
// message, with a non-empty fallback so a promotion reason never reads as an
// empty parenthesis when readiness was never reported at all.
func readinessReasonText(rg *RedundancyGroupState) string {
	if len(rg.ReadinessReasons) > 0 {
		return strings.Join(rg.ReadinessReasons, ", ")
	}
	return "readiness not reported"
}

// degradedPromoteDueLocked reports whether the #7161 cold-boot readiness gate
// has held this RG secondary for longer than degradedPromoteTimeout, and the
// operator-facing reason if so.
//
// It reads only rg.NotReadySince and the clock. It consults NO peer condition —
// that is the point. #110's armSyncReadyTimer bails its callback on
// !d.syncPeerConnected, so its fallback never fires in exactly the peer-absent
// case it exists for; a fallback gated on the condition it compensates for is
// not a fallback.
//
// Caller must hold m.mu.
func (m *Manager) degradedPromoteDueLocked(rg *RedundancyGroupState) (string, bool) {
	if m.degradedPromoteTimeout <= 0 || rg.NotReadySince.IsZero() {
		return "", false
	}
	held := time.Since(rg.NotReadySince)
	if held < m.degradedPromoteTimeout {
		return "", false
	}
	why := readinessReasonText(rg)
	return fmt.Sprintf(
		"Promoted DEGRADED after %s not ready (%s); forwarding may be impaired",
		held.Round(time.Second), why), true
}

// armDegradedTimerLocked stamps when the cold-boot gate first declined this RG
// and schedules the wakeup that lets the degraded fallback actually fire.
//
// Both halves live HERE, at the decline site, rather than in SetRGReady. A
// cold-boot RG starts not-ready and may never see a readiness TRANSITION, so
// arming from SetRGReady's transition branch would leave the fallback unarmed in
// precisely the case it exists for. The decline site, by construction, runs
// exactly when the fallback is needed.
//
// Caller must hold m.mu.
func (m *Manager) armDegradedTimerLocked(rg *RedundancyGroupState) {
	if m.degradedPromoteTimeout <= 0 {
		return
	}
	if rg.NotReadySince.IsZero() {
		rg.NotReadySince = time.Now()
	}
	if rg.degradedTimer != nil {
		return
	}
	remaining := m.degradedPromoteTimeout - time.Since(rg.NotReadySince)
	if remaining < 0 {
		remaining = 0
	}
	rgID := rg.GroupID
	rg.degradedTimer = time.AfterFunc(remaining, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		// Quiesced manager (#4716) and stale-RG (#5245) guards, matching
		// holdTimer: a timer that had already fired races config teardown.
		if m.stopped {
			return
		}
		cur, ok := m.groups[rgID]
		if !ok || cur != rg {
			return
		}
		rg.degradedTimer = nil
		if rg.Ready {
			return
		}
		slog.Warn("cluster: degraded-promotion timeout expired, re-evaluating election",
			"rg", rgID, "not_ready_for", time.Since(rg.NotReadySince).Round(time.Second))
		// Deliberately NOT branched on m.peerAlive. This fallback exists for the
		// peer-absent case; routing it through runElection when a peer appeared
		// meanwhile is still correct, because runElection has its own gate.
		if m.peerAlive {
			m.runElection()
		} else {
			m.electSingleNode()
		}
	})
}

// clearDegradedStateLocked cancels the fallback once the RG is ready again, so a
// later decline starts a fresh continuous-not-ready window rather than inheriting
// a stale one. Caller must hold m.mu.
func (m *Manager) clearDegradedStateLocked(rg *RedundancyGroupState) {
	rg.NotReadySince = time.Time{}
	// #7942: DegradedPromoted had TWO setters (electSingleNode and, since
	// #7939, runElection) and NO clearer, so once an RG was promoted while not
	// ready it reported that for the life of the process — including after it
	// became ready and was re-promoted normally. The flag answers "is this RG
	// forwarding while not ready", which is a statement about NOW, not a
	// permanent record of something that once happened.
	//
	// This is the natural home for the reset: this function already runs on the
	// become-ready edge, which is exactly when the claim stops being true.
	//
	// Latent rather than live when found — the field has no production reader
	// yet, only tests — but that is precisely why it needed fixing now. A field
	// with two setters and no reset is correct only until someone renders it,
	// and then it reads "degraded" on a healthy cluster.
	rg.DegradedPromoted = false
	if rg.degradedTimer != nil {
		rg.degradedTimer.Stop()
		rg.degradedTimer = nil
	}
}
