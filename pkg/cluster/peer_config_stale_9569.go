package cluster

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
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
	// sentMono is when generation was put on the wire (nowMono), for the
	// #18521 overdue-ACK re-push. Zero for a debt recorded by a test seam
	// without a time.
	sentMono int64
	// supersededByPeer: this node has since applied (or re-acknowledged) a
	// config the PEER pushed, so the debt no longer gates handovers
	// (supersedeSentConfigDebtByPeer).
	supersededByPeer bool
}

// supersedeSentConfigDebtByPeer retires this node's own outstanding send
// debt once it has APPLIED a config the PEER pushed (#18521 review round 2).
// The apply branch is reached only when the daemon's handler accepted the
// push, and it refuses one while this node believes it is the RG0 primary
// (errConfigSyncRejectedPrimary), so this is the moment config authority is
// known to be the peer's: both nodes now hold the peer's config by
// construction, and what this node sent earlier is no longer anyone's config.
// The duplicate re-ACK branch does NOT call this (review round 3): it runs no
// handler, so it never passes that RG0 check, and a duplicate of a generation
// applied earlier says nothing about this node's current config. Without this, a node that held an uncredited ACK
// debt and lost RG0 by a path its own gate does not guard (a monitor-driven
// weight change) kept refusing every later handover of a data RG, and the
// overdue-ACK re-push — which only the RG0 authority runs — could not clear
// it. A later send by this node records a fresh debt as usual.
func (s *SessionSync) supersedeSentConfigDebtByPeer(peerGen uint64) {
	s.configApplyDebtMu.Lock()
	debt := s.lastSentConfigDebt16756
	if debt.generation == 0 || debt.supersededByPeer {
		s.configApplyDebtMu.Unlock()
		return
	}
	s.lastSentConfigDebt16756.supersededByPeer = true
	s.configApplyDebtMu.Unlock()
	slog.Info("cluster sync: applied the peer's config; this node's own unacknowledged config "+
		"send is superseded and no longer gates handovers (#18521)",
		"own_gen", debt.generation, "peer_gen", peerGen)
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
	if sent == 0 || debt.supersededByPeer {
		return false, ""
	}
	legacyStale := func() (bool, string) {
		if nacked := s.peerConfigNackedGen16756.Load(); nacked >= sent {
			return true, fmt.Sprintf("peer predates config-apply ACK and reported it did not apply config generation %d (peer nacked %d)", sent, nacked)
		}
		return false, ""
	}
	// Sample the current incarnation after reading the send-time debt. A
	// legacy send can use NACK-only semantics while the peer remains legacy
	// (or disconnected), but a successor that proves ACK capability must
	// satisfy the still-outstanding generation with a positive ACK.
	s.mu.Lock()
	state := s.peerIncarnationState()
	learned := s.peerSnaps.peerSnapshotProtocol.Load() != 0
	currentAckCapable := uint8(state.peerCapabilityFlags2.Load())&capFlag2ConfigApplyAck != 0
	s.mu.Unlock()
	if learned && !currentAckCapable {
		return legacyStale()
	}
	if debt.capabilityKnown && !debt.ackCapable && !(learned && currentAckCapable) {
		return legacyStale()
	}
	// An unknown/disconnected incarnation is NOT proof of a pre-ACK peer
	// when the send itself was ACK-capable: keep that debt fail-closed until
	// capability discovery identifies a compatible successor.
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

// PeerConfigAckOverdue reports whether a CONNECTED, ACK-capable peer has gone
// longer than after without positively acknowledging the newest config
// generation this node sent (#18521). The stale-config gate is otherwise
// satisfied only by that ACK, and the only events that re-push a config are a
// NACK, a reconnect and a new commit. An ACK that never gets credited — skipped
// on the standby because its delivering connection was replaced, lost with a
// torn-down connection, or discarded by a reboot reset — therefore left the
// gate refusing failover onto an in-sync standby until the next commit. The
// daemon uses this to re-push, which the standby (already holding the config)
// answers with a fresh ACK.
//
// A legacy peer (no ACK advertisement) is never overdue: its gate is
// NACK-driven and a NACK already re-arms the push.
func (s *SessionSync) PeerConfigAckOverdue(after time.Duration) (gen uint64, age time.Duration, overdue bool) {
	if s == nil || !s.stats.Connected.Load() {
		return 0, 0, false
	}
	debt := s.configApplyDebtSnapshot16756()
	if debt.generation == 0 || debt.sentMono == 0 || debt.supersededByPeer {
		return 0, 0, false
	}
	known, ackCapable := s.peerConfigAckCapabilitySnapshot16756()
	if !known || !ackCapable {
		return 0, 0, false
	}
	if s.peerAppliedConfigGen.Load() >= debt.generation {
		return 0, 0, false
	}
	age = time.Duration(s.nowMono() - debt.sentMono)
	return debt.generation, age, age >= after
}
