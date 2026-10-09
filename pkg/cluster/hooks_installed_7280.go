package cluster

import "time"

// hooks_installed_7280.go — the #7280 observation seam.
//
// `Daemon.startClusterComms` installs wiring assignments into the
// cluster Manager and the SessionSync. #6428 bound the seventeen sites that
// were already observable and measured that the rest were bound by NOTHING:
// `go tool cover -func` reported 0.0% statement coverage for every builder
// running inside the constructor goroutine, and nilling all thirty wiring
// assignments at once left `pkg/daemon` and `pkg/cluster` fully green.
//
// They could not be bound then because the Manager exposed no way to ask
// whether a hook had been installed. This file is the smallest thing that
// makes installation observable. It deliberately does NOT assert behaviour —
// the question is "was this wired", and a behavioural assertion would need a
// live peer for hooks whose whole job is to talk to one.
//
// WHY THIS RETURNS A map[string]bool AND NOT THE FUNCS THEMSELVES.
//
// #6428's first draft of the equivalent test collected the func fields into a
// table of `any` and compared each against nil. Fourteen of seventeen
// mutations stayed GREEN, because **boxing a typed nil into an interface
// produces a non-nil interface**: `var f func(); any(f) != nil`. The nil-ness
// is destroyed by the boxing, not by the comparison.
//
// So the `!= nil` comparisons happen HERE, against the concrete typed fields,
// and only the resulting bools cross the package boundary. A caller cannot
// reintroduce the boxing bug because it never touches a func value.
//
// These hooks are cluster failover, fencing and sync-transport selection. A
// silently dropped assignment there is not a cosmetic defect.

// Hook names reported by InstalledHooks. Exported as constants so a test binds
// a symbol rather than a string literal: renaming a hook then breaks the test
// at COMPILE time instead of silently dropping a row from the map.
const (
	HookPeerFailover            = "PeerFailoverFunc"
	HookPeerFailoverCommit      = "PeerFailoverCommitFunc"
	HookPeerFailoverBatch       = "PeerFailoverBatchFunc"
	HookPeerFailoverCommitBatch = "PeerFailoverCommitBatchFunc"
	HookPreManualFailover       = "PreManualFailoverHook"
	HookLocalTransferCommitRdy  = "LocalTransferCommitReadyHook"
	HookTransferReadiness       = "TransferReadinessFunc"
	HookPeerTimeoutGuard        = "PeerTimeoutGuard"
	HookPeerNeverSeenSyncFresh  = "PeerNeverSeenSyncFreshFunc"
	HookHeartbeatRestartNotify  = "HeartbeatRestartNotifyFunc"
	HookPeerHeartbeatRecovered  = "PeerHeartbeatRecoveredFunc"
	HookPeerFence               = "PeerFenceFunc"
	HookPeerFenceConfirm        = "PeerFenceConfirmFunc"
)

// InstalledHooks reports, per hook, whether a non-nil callback is installed.
//
// The returned map always carries EVERY key, so a caller can tell "not
// installed" (present, false) from "no longer a hook" (absent). A test that
// looked up a renamed key in a map built only from installed hooks would read
// the rename as an uninstalled hook — or worse, a `_, ok :=` guard would skip
// the row entirely and report success.
//
// Takes m.mu, so it must NOT be called from a path that already holds it. Every
// caller is external observation (tests, diagnostics); no Manager method calls
// this.
func (m *Manager) InstalledHooks() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]bool{
		HookPeerFailover:            m.peerFailoverFn != nil,
		HookPeerFailoverCommit:      m.peerFailoverCommitFn != nil,
		HookPeerFailoverBatch:       m.peerFailoverBatchFn != nil,
		HookPeerFailoverCommitBatch: m.peerFailoverCommitBatchFn != nil,
		HookPreManualFailover:       m.preManualFailoverFn != nil,
		HookLocalTransferCommitRdy:  m.localTransferCommitReadyFn != nil,
		HookTransferReadiness:       m.transferReadinessFn != nil,
		HookPeerTimeoutGuard:        m.peerTimeoutGuardFn != nil,
		HookPeerNeverSeenSyncFresh:  m.peerNeverSeenSyncFreshFn != nil,
		HookHeartbeatRestartNotify:  m.hbRestartNotifyFn != nil,
		HookPeerHeartbeatRecovered:  m.peerHeartbeatRecoveredFn != nil,
		HookPeerFence:               m.peerFenceFn != nil,
		HookPeerFenceConfirm:        m.peerFenceConfirmFn != nil,
	}
}

// RemoteTransferOutLease returns the armed-lease duration.
//
// Unlike the hooks above this is a VALUE, not a callback, so "installed" is not
// a meaningful question — SetRemoteTransferOutLeaseDuration clamps to
// minRemoteTransferOutLease and the field is never nil. A binding test asserts
// the daemon's computed duration arrived, which is why the getter returns the
// duration rather than a bool.
func (m *Manager) RemoteTransferOutLease() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.remoteTransferOutLease
}

// HasAuthProvider reports whether a non-nil shared-PSK provider is installed.
//
// SessionSync stores the provider in an atomic box rather than a mu-guarded
// field, so this cannot join InstalledHooks above. The double check is not
// redundant: the box itself is a pointer AND it wraps an interface, so an
// installed box holding a nil provider is a distinct state from no box at all,
// and only the second one means "wired".
func (s *SessionSync) HasAuthProvider() bool {
	box := s.authProvider.Load()
	return box != nil && box.p != nil
}
