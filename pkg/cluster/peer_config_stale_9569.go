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
// only per-RG priority, weight and state. It tracks the newest generation sent
// and the highest positive config-apply ACK from the peer. NACKs (#7328) still
// report failures, but are diagnostic only: a newer write does not prove the
// standby applied it. A config currently being applied remains stale until the
// ordered apply loop succeeds and returns the matching ACK.

// ErrPeerConfigStale reports that a handover would promote a standby that did
// not apply the newest config generation this node sent.
var ErrPeerConfigStale = errors.New("peer config stale")

// SetPeerConfigStaleFunc registers the predicate that reports whether the peer
// has not positively acknowledged applying the newest config generation this
// node sent (#9569). The Manager evaluates it outside its own lock.
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

// PeerConfigStale reports whether the peer has not positively acknowledged
// applying the newest config generation this node sent. NACKs remain useful
// diagnostics, but only an apply ACK clears the gate.
func (s *SessionSync) PeerConfigStale() (bool, string) {
	sent := s.lastSentConfigGen.Load()
	applied := s.peerAppliedConfigGen.Load()
	if sent != 0 && applied < sent {
		return true, fmt.Sprintf("the standby has not acknowledged applying config generation %d (peer applied %d)", sent, applied)
	}
	return false, ""
}
