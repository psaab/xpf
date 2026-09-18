package cluster

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// UpdateConfig synchronizes redundancy group definitions from config.
// Called during config apply. Preserves runtime state for existing groups.
func (m *Manager) UpdateConfig(cfg *config.ClusterConfig) {
	if cfg == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[int]bool)
	for _, rg := range cfg.RedundancyGroups {
		seen[rg.ID] = true
		existing, ok := m.groups[rg.ID]
		if !ok {
			pri := clampNodePriority(rg.ID, rg.NodePriorities[m.nodeID])
			initialWeight := maxRedundancyGroupWeight
			var initialMonitorFails []string
			if cfg.ControlInterface != "" {
				initialWeight = rgWeightFromDebt(DataplaneArmMonitorCost)
				initialMonitorFails = []string{DataplaneArmMonitorIface}
			}
			existing = &RedundancyGroupState{
				GroupID:       rg.ID,
				LocalPriority: pri,
				Weight:        initialWeight,
				State:         StateSecondary,
				Preempt:       rg.Preempt,
				MonitorFails:  initialMonitorFails,
			}
			m.groups[rg.ID] = existing
			if cfg.ControlInterface != "" {
				m.monitorWeights[monitorKey{rgID: rg.ID, iface: DataplaneArmMonitorIface}] =
					DataplaneArmMonitorCost
				slog.Info("cluster: new redundancy group",
					"rg", rg.ID, "priority", pri, "preempt", rg.Preempt,
					"weight", existing.Weight, "reason", "dataplane XDP attachment not yet proven")
			} else {
				slog.Info("cluster: new redundancy group",
					"rg", rg.ID, "priority", pri, "preempt", rg.Preempt)
			}
		} else {
			existing.LocalPriority = clampNodePriority(rg.ID, rg.NodePriorities[m.nodeID])
			existing.Preempt = rg.Preempt
		}
	}

	// Remove groups no longer in config and their monitor weights.
	for id, rg := range m.groups {
		if !seen[id] {
			// Stop the armed takeover-hold timer before dropping the group
			// so its AfterFunc closure cannot fire an election against
			// removed state (#5245). Mirrors the readiness.go not-ready
			// clear site and Stop(): stop + nil the field under m.mu (held
			// here). AfterFunc's Stop() does not block on an in-flight
			// callback; if a fired callback is already parked on m.mu it
			// runs after we unlock, but the readiness.go closure's
			// staleness guard makes it a no-op once the group is gone.
			if rg.holdTimer != nil {
				rg.holdTimer.Stop()
				rg.holdTimer = nil
			}
			// #7161: the degraded fallback is torn down with the hold timer —
			// both pin the Manager until they fire.
			if rg.degradedTimer != nil {
				rg.degradedTimer.Stop()
				rg.degradedTimer = nil
			}
			for k := range m.monitorWeights {
				if k.rgID == id {
					delete(m.monitorWeights, k)
				}
			}
			// Purge the per-RG GARP count so a same-id re-add that omits an
			// explicit gratuitous-arp-count does not inherit this incarnation's
			// stale count (#6027). garpCounts is only WRITTEN when the config
			// sets a positive count, so a re-add with no explicit count relies
			// on the map entry being absent to fall back to the default. The
			// third same-id-re-add map-lifecycle gap in this loop after #5990
			// (ip-monitor ipState/ipDebts/ipThresholdState).
			delete(m.garpCounts, id)
			// #8435: the FOURTH same-id-re-add map-lifecycle gap in this loop.
			//
			// peerTransferOutOverride is armed between
			// `commitRequestedPeerFailover` succeeding and
			// `notePeerTransferCommitted`, bounded by failoverAckTimeout (20s).
			// A stale override surviving an RG's removal meant a same-id re-add
			// inside that window SELF-PROMOTED TO PRIMARY -- reproduced at
			// master, with a control (identical remove+re-add without the
			// override stays secondary) that makes it a defect rather than an
			// observation.
			//
			// Narrow: a ~20s window per operator `request chassis cluster
			// failover`, requiring a config commit that removes and re-adds that
			// RG inside it. A race, not a steady state -- but the outcome is
			// dual-primary.
			delete(m.peerTransferOutOverride, id)
			// #8435, found by the struct-enumerated guard rather than named in
			// the issue: two more per-RG hold deadlines survived the boundary.
			//
			// Both fail SAFE where peerTransferOutOverride fails unsafe -- a
			// stale hold parks something in SECONDARY, where a stale override
			// promotes to PRIMARY -- and both self-expire on a timer. That is
			// why only the override produced a reproduced dual-primary, and it
			// is not a reason to leave them: they are deadlines protecting a
			// transition of an RG that no longer exists, and a same-id re-add
			// inheriting one is held in secondary for a window it never earned.
			delete(m.peerTransferCommitGraceUntil, id)
			delete(m.localTransferOutHoldUntil, id)
			// The rest of the per-RG failover-lifecycle authority. Every one of
			// these was found by the struct-enumerated guard, not by reading the
			// loop -- which is the point of enumerating rather than remembering.
			//
			// `failoverInProgress` is the sharpest: it exists so "a second
			// request for the same RG is rejected immediately". Its owner
			// token must be purged so a same-id re-add starts with no stale
			// reservation, while an old request's token-matched cleanup cannot
			// touch a newer reservation on the fresh incarnation.
			//
			// Purging `failoverGen` is the SAFE direction and worth stating,
			// because resetting a generation counter usually is not. The
			// supersede check is `gen != captured -> abandon`. Deleting the
			// entry makes a later read return 0, so an operation that captured
			// a non-zero generation on the OLD incarnation sees a mismatch and
			// abandons. Keeping the counter would let it match and clobber.
			delete(m.failoverInProgress, id)
			delete(m.failoverGen, id)
			delete(m.peerTransferOutPrevious, id)
			delete(m.remoteTransferOutLeaseUntil, id)
			delete(m.remoteTransferOutLeaseReqID, id)
			delete(m.groups, id)
		}
	}

	// Update heartbeat parameters.
	// #8642: `> 0` cannot see wrap — the residue is positive by construction.
	// A wrapped heartbeat interval is a 64ns ticker on the HA control channel,
	// which is CLAUDE.md's "adding a new control socket request at >1/s will
	// starve session installs" with the rate set to ~1.5e7/s. Out-of-range
	// falls back to the existing default rather than clamping to the maximum.
	if d := config.MillisToDuration(cfg.HeartbeatInterval, 0); d > 0 {
		m.hbInterval = d
	}
	if cfg.HeartbeatThreshold > 0 {
		m.hbThreshold = cfg.HeartbeatThreshold
	}
	if cfg.ControlInterface != "" {
		m.controlInterface = cfg.ControlInterface
	}

	// #4107: plumb the control-channel PSK. Reveal() reads the cleartext
	// secret; it is stored as raw bytes and NEVER logged. Empty clears it
	// (reverts to legacy dual-accept). The slice is replaced, not mutated, so
	// the RLock read in controlLinkAuthKey() stays race-free.
	if k := cfg.ControlLinkAuthKey.Reveal(); k != "" {
		m.controlAuthKey = []byte(k)
	} else {
		m.controlAuthKey = nil
	}
	// #6630: the additional ACCEPTED key. Clearing it is the operator's
	// explicit FINALIZE step — the retired key stops being accepted on the
	// next commit, so the overlap is bounded by an operator action rather
	// than being permanent.
	if k := cfg.ControlLinkAuthKeyAlt.Reveal(); k != "" {
		m.controlAuthKeyAlt = []byte(k)
	} else {
		m.controlAuthKeyAlt = nil
	}

	// Update peer fencing config.
	m.peerFencing = cfg.PeerFencing

	// Update takeover hold time. Zero or negative resets to the default
	// immediate-takeover behavior.
	if cfg.TakeoverHoldTime < 0 {
		slog.Warn("cluster: invalid negative takeover hold time, using default immediate takeover",
			"takeover_hold_time_ms", cfg.TakeoverHoldTime)
	}
	// #8642: as above. A wrapped hold collapses to ~64ns, so takeover becomes
	// immediate on exactly the configuration that asked for it not to be.
	if d := config.MillisToDuration(cfg.TakeoverHoldTime, 0); d > 0 {
		m.takeoverHoldTime = d
	} else {
		m.takeoverHoldTime = DefaultTakeoverHoldTime
	}

	// Store GARP counts and update monitor groups.
	for _, rg := range cfg.RedundancyGroups {
		if rg.GratuitousARPCount > 0 {
			m.garpCounts[rg.ID] = rg.GratuitousARPCount
		}
	}
	// Reconcile installed interface-monitor debt against the new desired
	// monitor set BEFORE electing, so a monitor the operator just removed or
	// changed cannot strand this node with stale weight debt (#5080).
	m.reconcileMonitorDebtsLocked(cfg)

	if m.monitor != nil {
		m.monitor.UpdateGroups(cfg.RedundancyGroups)
	}

	// Election: use peer-aware if peer is alive, otherwise single-node.
	if m.peerAlive {
		m.runElection()
	} else {
		m.electSingleNode()
	}
}

// GroupStates returns a snapshot of all redundancy group states.
func (m *Manager) GroupStates() []RedundancyGroupState {
	m.mu.RLock()
	states := make([]RedundancyGroupState, 0, len(m.groups))
	for _, rg := range m.groups {
		cp := *rg
		if len(rg.MonitorFails) > 0 {
			cp.MonitorFails = make([]string, len(rg.MonitorFails))
			copy(cp.MonitorFails, rg.MonitorFails)
		}
		if len(rg.ReadinessReasons) > 0 {
			cp.ReadinessReasons = make([]string, len(rg.ReadinessReasons))
			copy(cp.ReadinessReasons, rg.ReadinessReasons)
		}
		states = append(states, cp)
	}
	fn := m.transferReadinessFn
	m.mu.RUnlock()

	if fn != nil {
		for i := range states {
			ready, reasons := fn(states[i].GroupID)
			states[i].TransferReady = ready
			if len(reasons) > 0 {
				states[i].TransferReadinessReasons = append([]string(nil), reasons...)
			}
		}
	} else {
		for i := range states {
			states[i].TransferReady = true
		}
	}

	sort.Slice(states, func(i, j int) bool {
		return states[i].GroupID < states[j].GroupID
	})
	return states
}

// DataGroupIDs returns the configured non-control redundancy groups in
// ascending order. RG0 is reserved for control-plane ownership and is omitted.
func (m *Manager) DataGroupIDs() []int {
	m.mu.RLock()
	ids := make([]int, 0, len(m.groups))
	for rgID := range m.groups {
		if rgID == 0 {
			continue
		}
		ids = append(ids, rgID)
	}
	m.mu.RUnlock()
	sort.Ints(ids)
	return ids
}

// GroupState returns the state for a specific redundancy group, or nil if not found.
func (m *Manager) GroupState(rgID int) *RedundancyGroupState {
	m.mu.RLock()
	rg, ok := m.groups[rgID]
	if !ok {
		m.mu.RUnlock()
		return nil
	}
	cp := *rg
	if len(rg.MonitorFails) > 0 {
		cp.MonitorFails = make([]string, len(rg.MonitorFails))
		copy(cp.MonitorFails, rg.MonitorFails)
	}
	if len(rg.ReadinessReasons) > 0 {
		cp.ReadinessReasons = make([]string, len(rg.ReadinessReasons))
		copy(cp.ReadinessReasons, rg.ReadinessReasons)
	}
	fn := m.transferReadinessFn
	m.mu.RUnlock()
	if fn != nil {
		cp.TransferReady, cp.TransferReadinessReasons = fn(rgID)
		if len(cp.TransferReadinessReasons) > 0 {
			cp.TransferReadinessReasons = append([]string(nil), cp.TransferReadinessReasons...)
		}
	} else {
		cp.TransferReady = true
	}
	return &cp
}

// SetGroupStateForTesting forces an RG's local state without running an
// election. Test-only, mirroring SetPeerDHCPLeasesForTesting; not for
// production callers.
//
// It exists because the #6889 reconciliation is defined against the manager's
// AUTHORITATIVE RG0 state, and the divergence it corrects is precisely the one
// an election would never produce on its own — a state reached while the event
// announcing it was dropped. Driving a real election would reproduce the state
// and the delivered event together, which is the case that was never broken.
func (m *Manager) SetGroupStateForTesting(rgID int, st NodeState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rg, ok := m.groups[rgID]; ok {
		rg.State = st
	}
}

// IsLocalPrimary returns true if this node is primary for the given RG.
func (m *Manager) IsLocalPrimary(rgID int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if rg, ok := m.groups[rgID]; ok {
		return rg.State == StatePrimary
	}
	return false
}

// LocalGroupPrimary reports whether this node is primary for rgID, and whether
// the manager knows the group at all.
//
// #8640: this exists as a distinct accessor because its caller is the
// proxy-ARP responder, which runs PER INBOUND ARP FRAME on a socket any host on
// the segment can drive. `GroupState` is the natural-looking call and is wrong
// there: it copies the whole RedundancyGroupState, allocates for MonitorFails
// and ReadinessReasons when either is non-empty, and invokes
// `transferReadinessFn` — an arbitrary readiness computation — outside the
// lock. That is a per-frame allocation and callback on an attacker-drivable
// path. `IsLocalPrimary` avoids all of it but collapses "unknown group" into
// `false`, which the responder must distinguish: unknown has to fall back to
// the older signal rather than suppress.
//
// So: one RLock, one map lookup, no allocation, no callback, and the two facts
// the caller actually needs.
func (m *Manager) LocalGroupPrimary(rgID int) (primary bool, known bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg, ok := m.groups[rgID]
	if !ok {
		return false, false
	}
	return rg.State == StatePrimary, true
}

// IsPeerPrimary reports whether the PEER node is primary for the given RG,
// per the last heartbeat-advertised peer group state. It returns false when the
// peer is not alive, the RG is unknown to the peer, or the peer is in any
// non-primary state (secondary, secondary-hold, election, disabled, lost).
//
// MonitorInterface uses this to proxy a locally-present RETH ONLY when the peer
// actually OWNS the RG. Proxying merely because the LOCAL node is not primary
// lets two non-primary nodes (both-secondary / election / sync-hold) forward
// the request to each other in an A->B->A loop that storms
// connections/streams/goroutines (#5497).
func (m *Manager) IsPeerPrimary(rgID int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.peerAlive {
		return false
	}
	if pg, ok := m.peerGroups[rgID]; ok {
		return pg.State == StatePrimary
	}
	return false
}

// IsLocalPrimaryAny returns true if this node is primary for any RG.
func (m *Manager) IsLocalPrimaryAny() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rg := range m.groups {
		if rg.State == StatePrimary {
			return true
		}
	}
	return false
}

// LocalPriorities returns a map of redundancy group ID to VRRP priority.
// Primary RGs get priority 200, all others get 100.
func (m *Manager) LocalPriorities() map[int]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[int]int, len(m.groups))
	for _, rg := range m.groups {
		if rg.State == StatePrimary {
			result[rg.GroupID] = 200
		} else {
			result[rg.GroupID] = 100
		}
	}
	return result
}

// clampNodePriority bounds a configured redundancy-group node priority into the
// range the #4880 commit gate enforces, warning once per apply when it has to.
//
// #8597 (muse-004 K17): this closes the priority domain where pkg/cluster reads
// it, exactly as ClampInterfaceMonitorWeight closes the weight domain — see
// that helper's doc for why the strict gate alone is not enough (the tolerant
// Store.Load / Store.SyncApply ingress downgrades it to a warning per #1960, so
// a persisted or peer-pushed config carries the raw value in).
//
// BOTH assignment sites in UpdateConfig go through it. The new-group and
// existing-group branches are two copies of one decision, and a clamp applied
// to only one of them would leave a config that is re-applied (rather than
// first applied) still installing the raw value — the more common path on a
// running box, not the rarer one.
//
// With the domain closed here, the uint16 wire cast in buildHeartbeat is an
// identity and clampWirePriority is a last belt rather than the fix, which is
// the same relationship clampWireWeight documents for the weight field.
func clampNodePriority(rgID, pri int) int {
	bounded, clamped := config.ClampRedundancyGroupNodePriority(pri)
	if clamped {
		slog.Warn("cluster: redundancy-group node priority out of range; clamping",
			"rg", rgID, "configured", pri, "effective", bounded,
			"range", fmt.Sprintf("%d..%d",
				config.MinRedundancyGroupNodePriority, config.MaxRedundancyGroupNodePriority),
			"issue", "#8597")
	}
	return bounded
}
