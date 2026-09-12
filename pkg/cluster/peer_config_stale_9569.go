package cluster

import (
	"errors"
	"fmt"
)

// #9569: the #5563 config-stale gate used to guard only the node-targeted
// failover. That form reaches RequestPeerFailover on the node that will become
// primary, whose transfer readiness includes ConfigStale. The untargeted
// `request chassis cluster failover redundancy-group N`, the batch form, and
// ForceSecondary (the ISSU drain and `request system software
// in-service-upgrade`) demote THIS node and never asked about the peer. For RG0
// the stale standby is then promoted, refuses the newer config the old primary
// pushes, and pushes its own older config back over the committed one.
//
// The demoting node cannot read the standby's ConfigStale: heartbeats carry
// only per-RG priority, weight and state. It does hold the one signal that
// covers the reachable windows. A standby whose stored config is still the
// older one either failed to apply the newest push, or dropped it from a full
// apply queue. Both send a config-apply nack for that generation (#7328), so a
// nack matching lastSentConfigGen means the peer is stale. A newer successful
// push supersedes it. A push the standby is still applying sends no nack and is
// safe: SyncApply makes the new tree active before applying it.

// ErrPeerConfigStale reports that a handover would promote a standby that did
// not apply the newest config generation this node sent.
var ErrPeerConfigStale = errors.New("peer config stale")

// SetPeerConfigStaleFunc registers the predicate that reports whether the peer
// failed to apply the newest config generation this node sent (#9569). The
// Manager evaluates it outside its own lock.
func (m *Manager) SetPeerConfigStaleFunc(fn func() (stale bool, reason string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerConfigStaleFn = fn
}

// peerConfigStaleRefusal evaluates fn and returns the refusal for a handover, or
// nil. Callers must NOT hold m.mu: fn reaches into the daemon's session sync.
func peerConfigStaleRefusal(fn func() (bool, string), what string) error {
	if fn == nil {
		return nil
	}
	if stale, reason := fn(); stale {
		return fmt.Errorf("%w: refusing %s: %s", ErrPeerConfigStale, what, reason)
	}
	return nil
}

// PeerConfigStale reports whether the peer sent a config-apply nack for the
// newest config generation this node pushed (#9569). A nack for an older
// generation, or a newer push since, is not stale.
func (s *SessionSync) PeerConfigStale() (bool, string) {
	nacked := s.peerConfigNackedGen.Load()
	if nacked != 0 && nacked == s.lastSentConfigGen.Load() {
		return true, fmt.Sprintf("the standby did not apply config generation %d (it sent a config-apply nack)", nacked)
	}
	return false, ""
}
