package cluster

import (
	"fmt"
	"log/slog"
	"time"
)

// heartbeat_suppress.go — the peer-heartbeat-timeout suppression policy
// (#17056, formerly split across the pkg/daemon boundary as #1792/#12165).
//
// The policy, its 5s continuous-suppression cap stamp, and the reset event
// (heartbeat admission) all live here under Manager.mu:
//
//   - syncSuppressesPeerTimeoutLocked decides, under m.mu, whether recent
//     session-sync traffic suppresses a heartbeat timeout. It reads the
//     published SessionSync through race-free atomics (IsConnected /
//     LastPeerReceiveAge), so holding m.mu across the decision cannot
//     deadlock and handlePeerTimeout never drops the lock for it.
//   - hbSuppressStart is a plain field under m.mu (CLOCK_MONOTONIC nanos,
//     0 = inactive). Heartbeat admission clears it in the same critical
//     section (handlePeerHeartbeat), and a fresh sync connection clears it
//     via resetSyncSuppressionLocked at publish time (SetPeerSyncSource).
//   - The daemon publishes exactly one reference — SetPeerSyncSource(ss|nil)
//     at publish/stop — replacing the three former daemon hooks that joined
//     the guard, the recovery notification and the never-seen probe.
//
// Timing contract (unchanged from #1792): suppress only while inbound peer
// sync traffic is at most maxPeerSyncSilence (2s) old, and never for more
// than maxSyncSuppressDuration (5s) of continuous suppression. Both the
// recency age and the cap stamp are CLOCK_MONOTONIC (#1792), so wall-clock
// steps neither extend nor cut the window.

// maxPeerSyncSilence is the recency window: inbound peer sync traffic older
// than this no longer proves the peer alive for heartbeat-timeout
// suppression.
const maxPeerSyncSilence = 2 * time.Second

// maxSyncSuppressDuration caps continuous heartbeat-timeout suppression.
// During graceful shutdown the peer may send bulk sync that keeps
// LastPeerReceiveAge fresh for tens of seconds while heartbeats have
// already stopped; after 5s of continuous suppression the heartbeat
// timeout must fire and trigger failover.
const maxSyncSuppressDuration = 5 * time.Second

// peerSyncSource is the minimal session-sync surface the suppression and
// never-seen policies read. *SessionSync satisfies it; tests may inject a
// fake. All methods are lock-free atomic reads that never call back into
// Manager, so they are safe to call under m.mu.
type peerSyncSource interface {
	IsConnected() bool
	LastPeerReceiveAge() (time.Duration, bool)
	PeerRecentlyActiveWithinSilenceWindow() bool
}

// SetPeerSyncSource publishes the session-sync object whose receive
// recency drives heartbeat-timeout suppression and never-seen absence
// confirmation, or nil when cluster comms stop. It replaces the three
// daemon hooks that used to join this policy across the package boundary
// (#17056). Publishing a non-nil source resets the suppression cap stamp:
// a fresh connection starts a fresh continuous-suppression window (the
// pre-move daemon reset the stamp in its OnPeerConnected handler).
func (m *Manager) SetPeerSyncSource(ss *SessionSync) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ss == nil {
		m.peerSync = nil
	} else {
		m.peerSync = ss
	}
	m.resetSyncSuppressionLocked()
}

// SyncSourceInstalled reports whether a peer sync source is published.
// It lets the daemon wiring tests bind SetPeerSyncSource the way
// InstalledHooks binds the remaining callbacks (#7280): the comparison
// happens here against the typed field, only a bool crosses the boundary.
func (m *Manager) SyncSourceInstalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerSync != nil
}

// resetSyncSuppressionLocked ends the current continuous-suppression
// window: a later heartbeat-only gap receives its own 5s cap (#12165).
// Caller must hold m.mu.
func (m *Manager) resetSyncSuppressionLocked() {
	m.hbSuppressStart = 0
}

// notePeerHeartbeatRecoveredLocked is the heartbeat-admission reset: an
// admitted peer heartbeat ends the current continuous-suppression window
// in the same critical section that marks the peer alive (#12165).
// Caller must hold m.mu.
func (m *Manager) notePeerHeartbeatRecoveredLocked() {
	m.resetSyncSuppressionLocked()
}

// syncSuppressesPeerTimeoutLocked reports whether recent session-sync
// traffic suppresses a heartbeat timeout, stamping the start of a new
// continuous-suppression window when one begins. Caller must hold m.mu.
func (m *Manager) syncSuppressesPeerTimeoutLocked(nowMono int64) (bool, string) {
	ss := m.peerSync
	if ss == nil || !ss.IsConnected() {
		m.hbSuppressStart = 0 // reset when sync disconnected
		return false, ""
	}
	age, ok := ss.LastPeerReceiveAge()
	if !ok || age > maxPeerSyncSilence {
		m.hbSuppressStart = 0 // reset when sync goes quiet
		return false, ""
	}
	if m.hbSuppressStart == 0 {
		m.hbSuppressStart = nowMono
	}
	if hbSuppressCapExceeded(m.hbSuppressStart, nowMono, maxSyncSuppressDuration) {
		return false, ""
	}
	return true, fmt.Sprintf("session sync connected with recent peer traffic age=%s", age.Truncate(10*time.Millisecond))
}

// peerSyncFreshLocked reports whether the published sync source proves the
// peer recently active within the full sync silence window. It backs
// never-seen absence confirmation (#11566/#11682): an idle ACK-only peer
// may have up to one read-deadline cadence between inbound sync frames, so
// this uses the sync layer's full silence window, not the shorter 2s
// heartbeat-suppression window. Caller must hold m.mu (the source read is
// a fast lock-free probe that never re-enters Manager).
func (m *Manager) peerSyncFreshLocked() bool {
	ss := m.peerSync
	return ss != nil && ss.IsConnected() && ss.PeerRecentlyActiveWithinSilenceWindow()
}

// hbSuppressCapExceeded reports whether continuous heartbeat-timeout
// suppression that began at startMono has lasted longer than capDur by
// nowMono. Both timestamps are CLOCK_MONOTONIC nanos (MonotonicNanos), so
// the cap is immune to wall-clock steps (#1792). Split out so tests can
// inject timestamps and exercise step scenarios directly.
func hbSuppressCapExceeded(startMono, nowMono int64, capDur time.Duration) bool {
	return time.Duration(nowMono-startMono) > capDur
}

// logSyncSuppressedTimeout records a suppressed heartbeat timeout at debug
// level, matching the pre-move daemon-guard log site.
func logSyncSuppressedTimeout(reason string) {
	slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
}
