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
// needs no new code and an older peer honours it too. A peer whose hold is
// under its 2 s guard, that carries an aborted-transfer marker, or (with
// #18525) holds a live remote transfer-out lease, still takes over only on
// heartbeat loss; see pkg/cluster/README.md. The debt is a
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
