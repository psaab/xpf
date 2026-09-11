package cluster

import "log/slog"

// SyncStatsProvider abstracts access to session sync statistics.
type SyncStatsProvider interface {
	Stats() SyncStatsSnapshot
	IsConnected() bool
	// PeerSessionSyncWireVersion is #7990's peer sync-wire advertisement, 0
	// when the peer has not advertised one. It is on THIS interface rather
	// than reached through an optional type assertion on purpose: an
	// assertion that silently fails renders no version and makes the LANE-1
	// drain gate unable to fire, which is indistinguishable from a healthy
	// pair. The compiler asks the question instead.
	PeerSessionSyncWireVersion() uint16
	// UnauthenticatedSessionConns lists the remote address of every established
	// session-sync connection that has never authenticated while this node holds
	// a control-link key (#9717), or nil when it holds none. It is on THIS
	// interface for the reason above: an assertion that silently failed would list
	// no connections, which reads exactly like the all-authenticated state.
	UnauthenticatedSessionConns() []string
}

// SetSyncReady marks session sync as ready (bulk sync received, or the
// readiness timeout released the hold).
//
// It does NOT gate RG promotion, in private-rg-election mode or any other
// (#7102). Say that plainly, because the opposite belief is the one #110 was
// filed to prevent and this comment used to assert it: this FLAG is not a term
// in the readiness conjunction (ifReady && takeoverGateReady && fabricReady &&
// userspaceReady, in daemon_ha_userspace_readiness.go).
//
// #7162 UPDATE — read this before concluding that startup promotion is
// ungated. It no longer is, but the gate is NOT this flag. no-RETH /
// private-rg-election mode now takes a BOUNDED startup hold
// (Daemon.armNoRethSyncHold, pkg/daemon/daemon_ha_noreth_hold.go), which
// checkNoRethTakeoverReadiness consults, so a node does not promote before bulk
// session sync during the hold window.
//
// The distinction is the entire point and must not be collapsed: the hold
// releases itself after a fixed duration whatever sync does, whereas THIS flag
// has no bound while the sync channel is down (armSyncReadyTimer early-returns
// unless syncPeerConnected). Making this flag a readiness conjunct would block
// promotion indefinitely with the peer alive on the control link and session
// sync down — including the degraded-peer case preemption exists for. That is
// what #110 measured and rejected. Do not "simplify" the hold into this flag.
//
// The gate DID exist: reconcileRGState set vrrpReady = d.cluster.IsSyncReady()
// in no-RETH mode and reported "session sync not ready" as a takeover blocker,
// until 0781f7a60 (2026-04-05) deleted it. That commit has an empty body, so
// the rationale for the removal is unavailable and would need re-deriving;
// whether the gate SHOULD come back is #110, still open. Do not restore it from
// this comment.
//
// Pinned by TestTakeoverReadinessForRG_NoRethIgnoresClusterSyncReady and
// TestTakeoverReadinessForRG_PrivateRGElectionIgnoresClusterSyncReady_7102
// (pkg/daemon), which drive a reconcile with sync NOT ready and assert the RG
// still reaches Ready with no "session sync not ready" reason.
//
// What the flag IS for: the readiness timeout in pkg/daemon/daemon_ha_sync.go,
// which uses it to decide whether to release its own hold, and two log fields
// on the sync connect/disconnect edges. Those are its only production readers.
// The real preemption suppressor with a similar name is the VRRP sync-hold
// (vrrp.Manager.SetSyncHold / ReleaseSyncHold), which is armed only in RETH
// VRRP mode and is not this flag.
func (m *Manager) SetSyncReady(ready bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.syncReady == ready {
		return
	}
	m.syncReady = ready
	slog.Info("cluster: sync readiness changed", "ready", ready)
}

// IsSyncReady returns true if session sync is ready.
func (m *Manager) IsSyncReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncReady
}

// SetSyncTransport records the active sync transport mode ("fabric" or "control-link").
func (m *Manager) SetSyncTransport(transport string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncTransport = transport
}

// SyncTransport returns the active sync transport mode.
func (m *Manager) SyncTransport() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.syncTransport == "" {
		return "fabric"
	}
	return m.syncTransport
}

// SetSyncStats sets the sync stats provider (called by daemon after sessionSync creation).
func (m *Manager) SetSyncStats(p SyncStatsProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncStats = p
}

// GetSyncStats returns sync stats, or nil if no provider is set.
func (m *Manager) GetSyncStats() *SyncStatsSnapshot {
	m.mu.RLock()
	p := m.syncStats
	m.mu.RUnlock()
	if p == nil {
		return nil
	}
	stats := p.Stats()
	return &stats
}

// IsSyncConnected returns true if the sync peer is connected.
func (m *Manager) IsSyncConnected() bool {
	m.mu.RLock()
	p := m.syncStats
	m.mu.RUnlock()
	if p == nil {
		return false
	}
	return p.IsConnected()
}

// PeerSessionSyncWireVersion reports the peer's advertised session-sync wire
// version through the sync-stats provider, or 0 when no provider is set or the
// peer has not advertised one (#7990).
//
// Both zero cases mean the same thing to a caller — "not known to differ" — and
// SessionSyncWireCompatible maps that to PERMIT. That is deliberate: a Manager
// with no provider is a node with no session sync to be incompatible about.
func (m *Manager) PeerSessionSyncWireVersion() uint16 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	p := m.syncStats
	m.mu.RUnlock()
	if p == nil {
		return 0
	}
	return p.PeerSessionSyncWireVersion()
}

// unauthenticatedSessionConns reports, through the sync-stats provider, the
// established session-sync connections that have never authenticated (#9717),
// or nil when no provider is set. A Manager with no provider has no session-sync
// connection to report.
func (m *Manager) unauthenticatedSessionConns() []string {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	p := m.syncStats
	m.mu.RUnlock()
	if p == nil {
		return nil
	}
	return p.UnauthenticatedSessionConns()
}
