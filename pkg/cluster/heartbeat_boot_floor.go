package cluster

// heartbeat_boot_floor.go — ending the cold-boot heartbeat floor once
// bring-up is PROVEN over (#18549).
//
// heartbeatStartupGrace (30 s, #4386) suppresses seen-then-lost for a
// cold-start receiver, because the boot-time config apply (VRF binding, FRR
// reload, fabric creation, RETH MAC down/up, the boot VRF-rebind restart of
// #9722/#17764) can drop control-link heartbeats for 10-15+ s. It was purely
// time-based. A rejoined node reached `Takeover ready: yes` about 2 s after
// its heartbeat started, but for the remaining ~28 s it could not notice its
// peer dying. test-double-failover crashed the peer ~20 s after the rejoin, and
// the takeover waited for the grace to run out: 13 s of outage on loss, 5 s on
// tcp. In both runs, peer loss was declared exactly 30.0 s after
// `heartbeat started`.
//
// The floor now ends early when two pieces of evidence agree that the boot
// disruption is behind this node:
//
//  1. The inbound bulk sync completed (syncBulkPrimed, which is never
//     timeout-released). That is a full TCP bulk exchange over the same
//     control link the heartbeats use, finished after bring-up.
//  2. The peer was then heard for at least heartbeatBootStableWindow with no
//     heartbeat gap of interval*threshold or more. The window is measured
//     from the later of the bulk completion and the start of the current
//     gap-free run, and it ends at the LAST ADMITTED frame. Silence never
//     counts as stability.
//
// Only the boot floor is ended: a restart receiver's own 5 s restart grace
// (#9722) still applies, as does the never-seen arm (#4386/#11566/#16751). A
// disruption that starts AFTER the proof is a steady-state disruption: a
// heartbeat restart arms its own restart grace, and handlePeerTimeout's
// sync-recency guard covers a live peer whose heartbeats are briefly lost.
// That is exactly what a node that booted long ago gets.

import "time"

// heartbeatBootStableWindow is how long the peer must be heard without a gap
// after the inbound bulk completes before the cold-boot floor may end early.
// It reuses the restart path's bind-retry window: the longest heartbeat
// outage a receiver replacement is expected to cause.
const heartbeatBootStableWindow = heartbeatRestartGrace

// notePeerHeartbeatAdmittedLocked extends or restarts the gap-free run of
// admitted peer heartbeats. Caller must hold m.mu (write).
func (m *Manager) notePeerHeartbeatAdmittedLocked(nowMono int64) {
	interval, threshold := m.liveHeartbeatTimingLocked()
	gap := int64(interval) * int64(threshold)
	if gap <= 0 {
		gap = int64(DefaultHeartbeatInterval) * DefaultHeartbeatThreshold
	}
	if m.peerHBLastAdmitMono == 0 || nowMono-m.peerHBLastAdmitMono >= gap {
		m.peerHBSteadySinceMono = nowMono
	}
	m.peerHBLastAdmitMono = nowMono
}

// resetPeerHeartbeatRunLocked forgets the gap-free run (peer loss). Caller
// must hold m.mu (write).
func (m *Manager) resetPeerHeartbeatRunLocked() {
	m.peerHBSteadySinceMono = 0
	m.peerHBLastAdmitMono = 0
}

// bootFloorProvenOver reports whether the cold-boot floor may end early: the
// inbound bulk completed and the peer was then heard gap-free for at least
// heartbeatBootStableWindow.
func (m *Manager) bootFloorProvenOver() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return bootFloorProof(m.syncBulkPrimed, m.syncBulkPrimedAtMono,
		m.peerHBSteadySinceMono, m.peerHBLastAdmitMono, heartbeatBootStableWindow)
}

// bootFloorProof is the pure decision behind bootFloorProvenOver.
func bootFloorProof(primed bool, primedAt, steadySince, lastAdmit int64, window time.Duration) bool {
	if !primed || primedAt == 0 || steadySince == 0 || lastAdmit == 0 {
		return false
	}
	from := steadySince
	if primedAt > from {
		from = primedAt
	}
	return lastAdmit-from >= int64(window)
}
