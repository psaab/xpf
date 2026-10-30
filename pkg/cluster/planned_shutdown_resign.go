package cluster

import (
	"log/slog"
	"sort"
)

// planned_shutdown_resign.go — an orderly daemon stop hands every redundancy
// group to the peer explicitly instead of letting it discover the loss.
//
// Before this, a private-RG node that was asked to stop (systemctl stop /
// restart, a package upgrade) said nothing to its peer. Its only on-wire
// signal was the #12164 dataplane-arm floor (weight 1) that the fail-closed
// stop installs, and that signal is too weak to move ownership in the shapes
// that matter:
//
//   - RG0 never yields on arm debt (#12164 N5: config authority);
//   - a data RG yields on arm debt only to a peer reporting Primary or
//     Secondary, so a peer parked in secondary-hold by an earlier manual
//     failover (the state `request chassis cluster failover` leaves on the
//     node that gave the RG away) is not a valid target; and
//   - that holding peer's ManualFailover arm releases only for a peer at
//     weight 0 or in secondary-hold, never for one at the floor.
//
// So the peer waited for heartbeat loss — the heartbeat threshold PLUS the
// session-sync recency window (#17056), which a stopping node's own sync
// backlog keeps fresh while the peer drains it (up to the 5 s cap). The
// stopping node's helper is gone within ~0.5 s of the stop signal, so that
// whole window was a blackhole: 3.3-3.4 s on the loss cluster, the 7 and 8
// lost pings per `test-restart-connectivity` cycle.
//
// The resign is a full-cost reserved election debt, the same mechanism
// HelperCrashLoopMonitorIface uses: weight 0 locally (electRG's "Local weight
// 0" arm demotes this node) and weight 0 on the wire. The peer arms that act
// on weight 0 already exist — "Peer weight 0", the ManualFailover dual-resign
// release, and peerYieldedOwnership for a not-ready receiver — so the peer
// needs no new code and an older peer honours it too. The explicit wire
// marker below additionally lets a current peer release its #18521 transfer
// lease hold and its 2s dual-resign guard on the resign frame; see
// pkg/cluster/README.md. The debt is a
// reserved monitor name, so a config apply cannot reconcile it away, and it
// composes additively, so no later monitor recalc on the way out can lift the
// weight back above 0.

// PlannedShutdownMonitorIface is the reserved election-debt key an orderly
// daemon stop installs on every redundancy group. It is not a legal Junos or
// Linux interface name, so it cannot collide with a configured monitor.
const PlannedShutdownMonitorIface = "__planned-shutdown__"

// PlannedShutdownMonitorCost is the full weight: a stopping node resigns
// rather than sitting at the #12164 floor, because it will not serve again
// in this process and a floor-weight owner is exactly the shape a holding
// peer cannot take over from.
const PlannedShutdownMonitorCost = maxRedundancyGroupWeight

// ResignForPlannedShutdown installs the planned-shutdown resign debt on every
// redundancy group, re-runs election (this node demotes itself), and sends a
// heartbeat at once so the peer learns now rather than on the next tick. It
// returns how many groups it newly resigned; repeat calls are no-ops.
//
// It never blocks on the peer: there is no barrier and no acknowledgement,
// because the caller is a shutdown sequence bounded by TimeoutStopSec.
//
// With no live peer it does NOTHING. There is nobody to hand the groups to,
// and the demotion is not inert: the daemon's cluster-event watcher runs on
// the never-cancelled daemon context, so it is live during the shutdown
// sequence and would act on the RG0 primary->secondary event —
// ConfirmPendingOnDemotion (#4378) would make a pending `commit confirmed`
// permanent on a lone node whose operator is rebooting it precisely to get
// the rollback (#12171), and the demotion would also terminate the RG's
// IPsec SAs that survive an ordinary lone-node restart. A lone node keeps
// ownership through its stop exactly as before #18540.
//
// RESIDUAL, stated rather than implied: "no live peer" means peerAlive, and a
// peer that died within the loss-detection window still reads as alive —
// roughly 0.5-2.1 s at defaults, up to the 5 s sync-suppression cap
// (heartbeat_suppress.go). A stop inside that window still resigns, the
// still-live watcher sees the RG0 demotion, and a pending commit-confirmed is
// confirmed exactly as above. Closing it would need a fresher liveness proof
// than the one peer-loss detection itself uses; it is not attempted here.
func (m *Manager) ResignForPlannedShutdown() int {
	m.mu.Lock()
	if m.stopped {
		// Stop has already closed the heartbeat sender, so the peer can
		// no longer hear a resign. Installing the debt now would only
		// make a misordered shutdown look as if it had handed over.
		m.mu.Unlock()
		slog.Warn("cluster: planned-shutdown resign requested after the cluster manager stopped; " +
			"the peer cannot hear it and will take over only on heartbeat loss")
		return 0
	}
	if !m.peerAlive {
		m.mu.Unlock()
		slog.Info("cluster: planned shutdown with no live peer; keeping redundancy-group ownership " +
			"through the stop (nothing to hand over, and a demotion would confirm a pending " +
			"commit-confirmed)")
		return 0
	}
	ids := make([]int, 0, len(m.groups))
	for id := range m.groups {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	resigned := 0
	for _, id := range ids {
		rg := m.groups[id]
		key := monitorKey{rgID: id, iface: PlannedShutdownMonitorIface}
		if _, already := m.monitorWeights[key]; already {
			continue
		}
		m.monitorWeights[key] = PlannedShutdownMonitorCost
		rg.MonitorFails = append(rg.MonitorFails, PlannedShutdownMonitorIface)
		sort.Strings(rg.MonitorFails)
		m.recalcWeight(rg)
		resigned++
	}
	m.mu.Unlock()

	if resigned > 0 {
		slog.Info("cluster: planned shutdown, resigning every redundancy group so the peer takes over now",
			"groups", resigned)
	}
	m.kickHeartbeat()
	return resigned
}

// kickHeartbeat asks the running heartbeat sender to transmit a frame now.
// It is a non-blocking hint: the sender coalesces kicks and keeps its
// regular cadence, and a stopped or never-started sender ignores it.
func (m *Manager) kickHeartbeat() {
	m.mu.RLock()
	sender := m.hbSender
	m.mu.RUnlock()
	if sender != nil {
		sender.kick()
	}
}

// The planned-shutdown resign is also announced EXPLICITLY on the wire, as a
// reserved entry in the heartbeat's monitor section: one per resigned RG,
// Interface = PlannedShutdownMonitorIface, Up = false. Weight 0 alone cannot
// carry it: a transfer requester may sit at weight 0 momentarily inside its
// commit window (#18521), and the owner's lease hold must survive that. A
// leaving peer, though, will never commit, so the hold — and the 2s
// dual-resign guard — only delay a takeover to heartbeat loss. An older peer
// stores the entry as one more peer monitor (display only) and still acts on
// the weight 0 through its existing arms.

// plannedShutdownWireMonitorsLocked returns the reserved monitor entries this
// node advertises for every RG it resigned for a planned shutdown. Caller must
// hold m.mu (read).
func (m *Manager) plannedShutdownWireMonitorsLocked() []HeartbeatMonitor {
	var out []HeartbeatMonitor
	ids := make([]int, 0, len(m.groups))
	for id := range m.groups {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if _, ok := m.monitorWeights[monitorKey{rgID: id, iface: PlannedShutdownMonitorIface}]; !ok {
			continue
		}
		out = append(out, HeartbeatMonitor{
			RGID:      wireRGID(id),
			Weight:    clampWireWeight(PlannedShutdownMonitorCost),
			Up:        false,
			Interface: PlannedShutdownMonitorIface,
		})
	}
	return out
}

// peerLeavingForPlannedShutdownLocked reports whether the peer's latest
// heartbeat resigned rgID for a planned shutdown: the reserved monitor entry
// for that RG AND an advertised weight of 0 (an entry without the resign is
// inconsistent and ignored). Caller must hold m.mu.
func (m *Manager) peerLeavingForPlannedShutdownLocked(rgID int, peerGroup *PeerGroupState) bool {
	if peerGroup == nil || peerGroup.Weight > 0 {
		return false
	}
	for _, mon := range m.peerMonitors {
		if mon.Interface == PlannedShutdownMonitorIface && !mon.Up && mon.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}
