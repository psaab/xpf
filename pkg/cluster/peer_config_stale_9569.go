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
// and the highest positive config-apply ACK from the peer. A config currently
// being applied remains stale until the ordered apply loop succeeds and returns
// the matching ACK — but only for a peer that advertised it can ACK (#16756:
// capFlag2ConfigApplyAck). A peer predating the type-40 ACK (28556c2b19) can
// never satisfy that, so for it the gate falls back to the pre-ACK semantics:
// stale iff the newest sent generation was NACKed.

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

// configApplyDebt16756 is the paired state for the newest config send.
// generation and the capability advertised for that send must be published
// together; a known legacy capability is distinct from not having learned the
// peer's capability yet.
type configApplyDebt16756 struct {
	generation      uint64
	capabilityKnown bool
	ackCapable      bool
}

func (s *SessionSync) configApplyDebtSnapshot16756() configApplyDebt16756 {
	s.configApplyDebtMu.RLock()
	debt := s.lastSentConfigDebt16756
	s.configApplyDebtMu.RUnlock()
	return debt
}

// peerConfigAckCapabilitySnapshot16756 samples the learned marker and ACK
// capability from one peer incarnation. The pointer retry avoids combining a
// retired capability set with the successor's learned state.
func (s *SessionSync) peerConfigAckCapabilitySnapshot16756() (known, ackCapable bool) {
	for {
		state := s.peerIncarnationState()
		known = s.peerSnaps.peerSnapshotProtocol.Load() != 0
		flags2 := state.peerCapabilityFlags2.Load()
		if s.peerIncarnationStatePtr.Load() == state {
			return known, uint8(flags2)&capFlag2ConfigApplyAck != 0
		}
	}
}

// PeerConfigStale reports whether handing over to the peer would promote
// a standby that has not applied the newest config generation this node
// sent.
//
// ACK-capable peer (advertised capFlag2ConfigApplyAck for the incarnation
// that received the newest send): only a positive apply ACK clears the
// gate — a NACK is diagnostic, and silence is stale (#9569/#11070).
// If that peer disconnects before ACKing, its send debt survives until a
// successor applies it or explicitly advertises the legacy capability set.
//
// Legacy peer (no ACK advertisement for that incarnation — it predates
// the type-40 ACK, 28556c2b19): it can never ACK, so requiring one
// refuses forever with a reason that blames a config-apply failure that
// never happened (#16756). Fall back to the pre-28556c2b19 semantics:
// stale iff the newest sent generation was NACKed. No NACK means there
// is no evidence the peer failed to apply, and handover proceeds.
func (s *SessionSync) PeerConfigStale() (bool, string) {
	if s == nil {
		return false, ""
	}
	debt := s.configApplyDebtSnapshot16756()
	sent := debt.generation
	if sent == 0 {
		return false, ""
	}
	legacyStale := func() (bool, string) {
		if nacked := s.peerIncarnationState().peerConfigNackedGen16756.Load(); nacked >= sent {
			return true, fmt.Sprintf("peer predates config-apply ACK and reported it did not apply config generation %d (peer nacked %d)", sent, nacked)
		}
		return false, ""
	}
	if debt.capabilityKnown && !debt.ackCapable {
		return legacyStale()
	}
	// An unknown/disconnected incarnation is NOT proof of a pre-ACK peer:
	// keep outstanding ACK-capable debt fail-closed until capability
	// discovery identifies either another ACK-capable peer or an explicit
	// downgrade. Sample learned state and its capability under s.mu so the
	// gate cannot observe the capability frame between those publications.
	s.mu.Lock()
	state := s.peerIncarnationState()
	learned := s.peerSnaps.peerSnapshotProtocol.Load() != 0
	currentAckCapable := uint8(state.peerCapabilityFlags2.Load())&capFlag2ConfigApplyAck != 0
	s.mu.Unlock()
	if learned && !currentAckCapable {
		return legacyStale()
	}
	applied := s.peerAppliedConfigGen.Load()
	if applied < sent {
		return true, fmt.Sprintf("the standby has not acknowledged applying config generation %d (peer applied %d)", sent, applied)
	}
	return false, ""
}

// PeerAppliedConfigGen returns the highest config generation the peer has
// positively acknowledged as applied (#15212).
func (s *SessionSync) PeerAppliedConfigGen() uint64 {
	if s == nil {
		return 0
	}
	return s.peerAppliedConfigGen.Load()
}
