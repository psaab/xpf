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

// peerConfigCapStaleKnown16756 reports whether the peer incarnation that
// was current when the newest generation was sent advertised ACK
// support. It pairs lastSentConfigGen with the capability recorded
// alongside it, so it separates "the peer said it cannot ACK" (false)
// from "the peer promised an ACK" (true). A peer that never sent a
// capabilities frame (peerCapabilitiesLearned false) records false at
// send time and keeps the legacy fallback — exactly a pre-ACK peer.
func (s *SessionSync) peerConfigCapStaleKnown16756() bool {
	if s == nil {
		return false
	}
	return s.lastSentConfigAckCapable16756.Load()
}

// PeerConfigStale reports whether handing over to the peer would promote
// a standby that has not applied the newest config generation this node
// sent.
//
// ACK-capable peer (advertised capFlag2ConfigApplyAck for the incarnation
// that received the newest send): only a positive apply ACK clears the
// gate — a NACK is diagnostic, and silence is stale (#9569/#11070).
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
	sent := s.lastSentConfigGen.Load()
	if sent == 0 {
		return false, ""
	}
	legacyStale := func() (bool, string) {
		if nacked := s.peerConfigNackedGen16756.Load(); nacked >= sent {
			return true, fmt.Sprintf("peer predates config-apply ACK and reported it did not apply config generation %d (peer nacked %d)", sent, nacked)
		}
		return false, ""
	}
	if !s.peerConfigCapStaleKnown16756() {
		return legacyStale()
	}
	// The send-time recording says the receiving incarnation promised an
	// ACK. If the CURRENT incarnation does not advertise the bit —
	// downgrade-on-reconnect, or an advance whose new peer has not
	// advertised yet (flags cleared, applied mark reset by the boot
	// switch) — the promised ACK can never arrive from it, and the
	// strict gate would refuse on (sent, 0) forever. Treat the current
	// peer as the legacy peer it now is. A currently ACK-capable peer
	// keeps the strict gate below.
	if !s.ConfigApplyAckCapable() {
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
