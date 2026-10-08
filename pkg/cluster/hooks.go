package cluster

import "time"

// SetPreManualFailoverHook registers a callback that runs before ManualFailover
// changes local RG ownership.
func (m *Manager) SetPreManualFailoverHook(fn func(rgID int) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.preManualFailoverFn = fn
}

// SetTransferReadinessFunc sets the callback used to report whether a local
// redundancy group is ready for explicit transfer-based manual failover.
func (m *Manager) SetTransferReadinessFunc(fn func(rgID int) (bool, []string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transferReadinessFn = fn
}

// SetLocalTransferCommitReadyHook registers a callback that runs on the
// requesting node after local ownership is committed and before the final
// peer-demotion commit is sent.
func (m *Manager) SetLocalTransferCommitReadyHook(fn func(rgIDs []int) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localTransferCommitReadyFn = fn
}

// SetPeerFailoverFunc sets the callback used to send remote failover requests
// to the peer via the fabric sync connection.
func (m *Manager) SetPeerFailoverFunc(fn func(rgID int) (uint64, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverFn = fn
}

// SetPeerFailoverCommitFunc sets the callback used to send remote
// transfer-commit messages via the fabric sync connection.
func (m *Manager) SetPeerFailoverCommitFunc(fn func(rgID int, reqID uint64) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverCommitFn = fn
}

// SetPeerFailoverBatchFunc sets the callback used to send remote multi-RG
// failover requests to the peer via the fabric sync connection.
func (m *Manager) SetPeerFailoverBatchFunc(fn func(rgIDs []int) (uint64, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverBatchFn = fn
}

// SetPeerFailoverCommitBatchFunc sets the callback used to send the final
// multi-RG transfer-commit message via the fabric sync connection.
func (m *Manager) SetPeerFailoverCommitBatchFunc(fn func(rgIDs []int, reqID uint64) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFailoverCommitBatchFn = fn
}

// SetPeerFenceFunc sets the callback used to send a fence message to the
// peer via the fabric sync connection, telling it to disable all RGs.
func (m *Manager) SetPeerFenceFunc(fn func() error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFenceFn = fn
}

// SetPeerFenceConfirmFunc sets the callback used to send a SEQUENCED fence and
// wait for the peer's confirmation of what it disabled (#7147). Consulted only
// under `peer-fencing disable-rg-confirmed`.
func (m *Manager) SetPeerFenceConfirmFunc(fn func(timeout time.Duration) (FenceAck, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerFenceConfirmFn = fn
}

// SetPeerTimeoutGuard sets a callback that can suppress heartbeat-driven
// peer-loss if another control-plane signal proves the peer is still alive.
func (m *Manager) SetPeerTimeoutGuard(fn func() (bool, string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerTimeoutGuardFn = fn
}

// SetPeerNeverSeenSyncFreshFunc installs the sync-recency probe used before
// confirming an unheard peer absent. It runs under m.mu and therefore must be
// a fast, lock-free read that does not call back into Manager.
func (m *Manager) SetPeerNeverSeenSyncFreshFunc(fn func() bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerNeverSeenSyncFreshFn = fn
}

// SetPeerHeartbeatRecoveredFunc installs a notification called for every
// admitted peer heartbeat. It runs under m.mu and must therefore be a fast,
// lock-free action that does not call back into Manager.
func (m *Manager) SetPeerHeartbeatRecoveredFunc(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerHeartbeatRecoveredFn = fn
}

// SetHeartbeatRestartNotifyFunc sets the callback invoked around the
// RestartHeartbeat socket teardown/rebind window. The daemon wires it to
// SessionSync.SendLivenessKeepalive so the peer's heartbeat-timeout
// suppression guard keeps observing fresh sync traffic while this node's
// UDP heartbeats are silent during the restart (#1792).
func (m *Manager) SetHeartbeatRestartNotifyFunc(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hbRestartNotifyFn = fn
}

// SetRGForwardingFunc registers the callback that reports a redundancy group's
// DATAPLANE-side state (applied rg_active and VRRP mastership) for
// `show chassis cluster status`.
//
// #7367: without it the status render carries no forwarding term at all, so a
// node that owns an RG but forwards nothing for it is indistinguishable from a
// healthy primary. The daemon owns the rgStateMachine, so the value has to come
// back across this boundary rather than being read here.
//
// Returning ok=false for a group omits the sub-line for that group. That is
// deliberate: a group the daemon has no state machine for has no forwarding
// state to report, and rendering a default would assert something false about
// the dataplane.
func (m *Manager) SetRGForwardingFunc(fn func(rgID int) (RGForwarding, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rgForwardingFn = fn
}
