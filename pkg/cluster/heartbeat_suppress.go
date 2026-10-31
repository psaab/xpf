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
//     section (handlePeerHeartbeat); publishing a sync source clears it
//     (SetPeerSyncSource), and every per-connection OnPeerConnected
//     dispatch on that source clears it again via the OnPeerReconnected
//     binding SetPeerSyncSource installs — so a reconnect on the same
//     SessionSync object gets a fresh 5s window, as the pre-move daemon
//     reset on every onSessionSyncPeerConnected did.
//   - The daemon publishes exactly one reference — SetPeerSyncSource(ss|nil)
//     at publish/stop — replacing the three former daemon hooks that joined
//     the guard, the recovery notification and the never-seen probe. The
//     per-connection binding above is installed by that publish, inside
//     pkg/cluster; it is not a fourth daemon hook.
//
// Timing contract (#1792): suppress only while inbound peer sync traffic is
// at most maxPeerSyncSilence (2s) old, and never for more than
// maxSyncSuppressDuration (5s) of continuous suppression. Both the recency
// age and the cap stamp are CLOCK_MONOTONIC (#1792), so wall-clock steps
// neither extend nor cut the window. #18561 adds, for a peer that answers
// sync-level heartbeats, the liveness probe: one probe at the first missed
// heartbeat, and no suppression on the timeout tick unless a sync frame
// newer than it has arrived (peerAnsweredLivenessProbeLocked).

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
	// TransferChannelGen is the connection-slot removal generation
	// (#18521 review round 2): it moves whenever an installed connection
	// leaves its fabric slot, so an unchanged value means every connection
	// installed at capture time is still installed. Lock-free.
	TransferChannelGen() uint64
}

// SetPeerSyncSource publishes the session-sync object whose receive
// recency drives heartbeat-timeout suppression and never-seen absence
// confirmation, or nil when cluster comms stop. It replaces the three
// daemon hooks that used to join this policy across the package boundary
// (#17056). Publishing a non-nil source resets the suppression cap stamp:
// a fresh comms epoch starts a fresh continuous-suppression window. The
// publish alone cannot provide the pre-move per-CONNECTION reset — the
// same SessionSync object reconnects without being republished — so
// SetPeerSyncSource also binds ss.OnPeerReconnected to
// resetPeerSyncSuppression: every per-connection OnPeerConnected dispatch
// (handleNewConnection when it cold-primes, and the BulkStart reboot
// switch when it announces) then resets the stamp on this Manager, which
// is the moved-policy equivalent of the pre-move daemon resetting
// hbSuppressStart on every onSessionSyncPeerConnected. Unpublishing (nil)
// clears the binding this Manager installed, but only if it is still ours,
// so a replaced source's binding is never clobbered.
func (m *Manager) SetPeerSyncSource(ss *SessionSync) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.peerSync.(*SessionSync); ok && prev != ss {
		clearPeerReconnectBinding(prev, m)
	}
	if ss == nil {
		m.peerSync = nil
	} else {
		ss.OnPeerReconnected = m.resetPeerSyncSuppression
		ss.peerReconnectOwner = m
		m.peerSync = ss
	}
	m.resetSyncSuppressionLocked()
}

// ClearPeerSyncSourceIfCurrent removes ss only when it is still this
// Manager's published source. A delayed teardown must not unpublish a
// successor's source after the daemon has already replaced the session.
func (m *Manager) ClearPeerSyncSourceIfCurrent(ss *SessionSync) bool {
	if ss == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.peerSync.(*SessionSync)
	if !ok || current != ss {
		return false
	}
	clearPeerReconnectBinding(ss, m)
	m.peerSync = nil
	m.resetSyncSuppressionLocked()
	return true
}

// resetPeerSyncSuppression is the per-connection reset bound to
// SessionSync.OnPeerReconnected at publish time (#17056). It runs on the
// SessionSync goroutine that dispatches OnPeerConnected, outside any
// SessionSync lock, and takes only m.mu.
func (m *Manager) resetPeerSyncSuppression() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetSyncSuppressionLocked()
	// #18561 (seat U): a connection that just completed TCP and the PSK
	// handshake is itself the liveness answer. Clearing the latch here made
	// the next timeout tick re-probe a peer that had just proved itself and
	// give it one interval; on master that case was deferred. The next
	// admitted heartbeat clears the latch (notePeerHeartbeatRecoveredLocked).
	m.hbLivenessProven = true
}

// clearPeerReconnectBinding removes the OnPeerReconnected binding mgr
// installed on ss, if the current binding is still mgr's (tracked via
// ss.peerReconnectOwner, since func values are not comparable). A binding
// installed by another Manager (the source was republished elsewhere) or
// by a test is left untouched.
func clearPeerReconnectBinding(ss *SessionSync, mgr *Manager) {
	if ss.peerReconnectOwner == mgr {
		ss.OnPeerReconnected = nil
		ss.peerReconnectOwner = nil
	}
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
// It also forgets the outstanding liveness probe (#18561): a reconnect or
// an admitted heartbeat makes the probe's question moot.
// Caller must hold m.mu.
func (m *Manager) resetSyncSuppressionLocked() {
	m.hbSuppressStart = 0
	m.hbLivenessProbeMono = 0
	m.hbLivenessProbeAnswerBy = 0
	m.hbLivenessProven = false
}

// peerLivenessProber is the optional sync-source surface behind the #18561
// liveness probe. *SessionSync implements it; a source that does not (the
// older test fakes) keeps the pre-#18561 recency-only suppression.
type peerLivenessProber interface {
	// PeerHeartbeatAckSupported reports whether the peer has proved it
	// answers a sync-level heartbeat with a heartbeat ack. Lock-free.
	PeerHeartbeatAckSupported() bool
	// LastPeerReceiveMono is the CLOCK_MONOTONIC nanos stamp of the last
	// accepted inbound sync frame; ok is false when none was received.
	// Lock-free.
	LastPeerReceiveMono() (int64, bool)
	// RequestLivenessProbe asks the sync layer to send one sync-level
	// heartbeat to the peer. It must not block: it is called under m.mu.
	RequestLivenessProbe()
}

// minLivenessProbeAnswer is the least time an unanswered probe is given
// before its silence counts as evidence. The probe is normally sent at the
// first missed heartbeat (prearmPeerLivenessProbe), so a live peer has until
// the timeout tick, about (threshold - 1.5) x interval, to answer.
const minLivenessProbeAnswer = 50 * time.Millisecond

// livenessProbeAnswerWindowLocked is the answer window for a probe that could
// not be pre-armed and went out on the timeout tick itself (a receiver
// leaving a restart or boot grace with the peer already late, for instance):
// the same (threshold - 1.5) x interval a pre-armed probe gets, so a live peer
// is never judged on one interval (seat U). Caller must hold m.mu.
func (m *Manager) livenessProbeAnswerWindowLocked() time.Duration {
	w := time.Duration(2*m.hbThreshold-3) * m.hbInterval / 2
	if w < minLivenessProbeAnswer {
		return minLivenessProbeAnswer
	}
	return w
}

// livenessProberLocked returns the published source as a prober, and whether
// the peer has proved it answers sync-level heartbeats. Caller must hold
// m.mu.
func (m *Manager) livenessProberLocked() (peerLivenessProber, bool, bool) {
	ss := m.peerSync
	if ss == nil || !ss.IsConnected() {
		return nil, false, false
	}
	p, ok := ss.(peerLivenessProber)
	if !ok {
		return nil, false, false
	}
	return p, true, p.PeerHeartbeatAckSupported()
}

// prearmPeerLivenessProbe sends ONE liveness probe per suppression window at
// the first missed heartbeat (#18561). heartbeatReceiver.checkTimeout calls
// it while the last heartbeat is late (older than 1.5 intervals) but not yet
// stale. The probe goes out whether or not the peer has proved ack support:
// its answer is what latches that support.
func (m *Manager) prearmPeerLivenessProbe(nowMono int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerAlive || m.hbLivenessProbeMono != 0 || m.hbLivenessProven {
		return
	}
	p, ok, _ := m.livenessProberLocked()
	if !ok {
		return
	}
	m.hbLivenessProbeMono = nowMono
	m.hbLivenessProbeAnswerBy = nowMono + int64(minLivenessProbeAnswer)
	m.livenessProbesSent++
	p.RequestLivenessProbe()
}

// peerAnsweredLivenessProbeLocked is the #18561 liveness proof behind a
// sync-recency suppression, for a peer that answers sync-level heartbeats.
//
// Recent sync traffic alone does not prove the peer alive: a hard-killed peer
// leaves a half-open sync socket that still reads "connected", and its last
// frame is only about one heartbeat interval younger than its last heartbeat,
// so the 2s recency window kept a dead peer alive for up to 2s past the
// threshold (loss: declared 0.7-1.58 s after the kill at 1.0 s). One probe is
// sent at the first missed heartbeat. If any sync frame newer than it has
// arrived by the timeout tick, the peer is alive: the window keeps the
// recency rule and the 5s cap and is not probed again. If none has, the
// timeout fires. So a live peer has (threshold - 1.5) intervals for one round
// trip (700 ms in the lab's 200 ms x 5, 350 ms at the 100 ms x 5 default)
// rather than one per tick.
//
// Returns false (do not suppress) only for an unanswered probe at least
// minLivenessProbeAnswer old. Caller must hold m.mu.
func (m *Manager) peerAnsweredLivenessProbeLocked(p peerLivenessProber, nowMono int64) bool {
	if m.hbLivenessProven {
		return true
	}
	sent := m.hbLivenessProbeMono
	if sent == 0 {
		// No probe was pre-armed (the late-heartbeat tick fell inside a
		// restart or boot grace, or the tick phase skipped it): probe now and
		// give it the full window a pre-armed probe would have had.
		m.hbLivenessProbeMono = nowMono
		m.hbLivenessProbeAnswerBy = nowMono + int64(m.livenessProbeAnswerWindowLocked())
		m.livenessProbesSent++
		p.RequestLivenessProbe()
		return true
	}
	if last, ok := p.LastPeerReceiveMono(); ok && last > sent {
		m.hbLivenessProven = true
		return true
	}
	if nowMono < m.hbLivenessProbeAnswerBy {
		return true
	}
	m.livenessProbeTimeouts++
	slog.Warn("cluster: peer sent nothing over session sync since the liveness probe; heartbeat timeout not deferred",
		"probe_age", time.Duration(nowMono-sent).Truncate(time.Millisecond))
	return false
}

// LivenessProbeStats reports the #18561 heartbeat-timeout liveness probe:
// whether the published peer has proved it answers sync-level heartbeats
// (when false, the recency-only rule is in force), and how many probes were
// sent and found unanswered at a timeout tick.
func (m *Manager) LivenessProbeStats() (ackSupported bool, sent, unanswered uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok, ack := m.livenessProberLocked()
	return ok && ack, m.livenessProbesSent, m.livenessProbeTimeouts
}

// notePeerHeartbeatRecoveredLocked is the heartbeat-admission reset: an
// admitted peer heartbeat ends the current continuous-suppression window in
// the same critical section that marks the peer alive (#12165).
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
		m.resetSyncSuppressionLocked() // reset when sync disconnected
		return false, ""
	}
	age, ok := ss.LastPeerReceiveAge()
	if !ok || age > maxPeerSyncSilence {
		m.resetSyncSuppressionLocked() // reset when sync goes quiet
		return false, ""
	}
	if m.hbSuppressStart == 0 {
		m.hbSuppressStart = nowMono
	}
	if hbSuppressCapExceeded(m.hbSuppressStart, nowMono, maxSyncSuppressDuration) {
		return false, ""
	}
	// #18561: a peer that can answer a sync-level probe must have answered
	// one sent after its heartbeats went late. A peer that never proved ack
	// support keeps the recency-only rule above.
	if p, ok, ack := m.livenessProberLocked(); ok && ack && !m.peerAnsweredLivenessProbeLocked(p, nowMono) {
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
