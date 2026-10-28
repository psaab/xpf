package cluster

import (
	"net"
	"sync/atomic"
)

// peerIncarnationState is the single source for every peer-incarnation-scoped
// latch, debt, and learned capability (#17097).
//
// Before #17097 those fields were scattered on SessionSync and retired by
// three hand-written reset lists (boot-ID switch, installConn's
// supersession/epoch-raise advance, and handleDisconnect's full-disconnect
// arm). The lists diverged: the capability triple was replicated to the
// advance paths (#10512/#14161) while nine fields documented as "same
// incarnation scoping" were reset only on full disconnect, so a new
// incarnation reached by supersession or boot-ID switch inherited silenced
// one-shot warnings, a stale PBR-announced latch, and suppress debts it did
// not owe (#14161 and #15182 were earlier bugs of the same missed-site class).
//
// A fresh value is installed by retirePeerIncarnationLocked at every
// retirement site, so a field added here is reset at all sites by
// construction; the reflection-driven test in
// peer_incarnation_retirement_17097_test.go sets every field non-zero and
// asserts each trigger leaves it zero or seeded, so a new field cannot be
// added without coverage.
//
// Deliberately NOT in this state:
//   - clockSynced (SessionSync): an incarnation that ends by switch keeps
//     the surviving connection's proven clock (applyPeerIncarnationSwitchLocked
//     preserves it under the #9915 F-118 provenance rule), so it has a
//     different owner than the fields below. peerClockOffset IS here: every
//     retirement zeroes it, and the switch then re-seeds it from the kept
//     connection when that connection proves the new boot.
//   - peerSnapshotProtocol and peerSnapshotProtocolGeneration: they live on
//     peerSnapshotState (#16159) behind peerSnapshotProtocolWriteMu, which
//     serializes capability-incarnation changes with gated config writes.
//     Moving them would split that lock domain; retirePeerIncarnationLocked
//     still clears them at every site beside this state.
//   - peerIdentity / peerBootIncarnation / bulk-receive state: retired by
//     each site's own identity/bulk logic, which differs per trigger (the
//     switch adopts the priming connection's identity; full disconnect
//     clears it) and is not a plain reset.
type peerIncarnationState struct {
	// peerCapabilityFlags holds the peer's advertised capability bits
	// (#7147), carried in the trailing byte of syncMsgPeerCapabilities on
	// top of #6650's version field. 0 means "advertises nothing", which
	// for every bit means INCAPABLE — a pre-#7147 peer sends a 2-byte
	// frame with no flags at all. A retained fence-ack bit would make a
	// confirmed-fence gate wait out its whole timeout against a
	// downgraded peer that can never answer.
	peerCapabilityFlags atomic.Uint32
	// peerCapabilityFlags2 holds the peer's SECOND advertised capability
	// byte (#16756), carried after the wire-version field in
	// syncMsgPeerCapabilities because the first flags byte is full. Bit 0
	// (capFlag2ConfigApplyAck) means the peer sends syncMsgConfigApplyAck;
	// bit 1 (capFlag2PersistentNatLeaseProvenance) means it decodes lease
	// provenance frames (types 50/51); bit 2 (capFlag2PrimaryLiveness)
	// means it accepts the primary-liveness marker on session frames.
	peerCapabilityFlags2 atomic.Uint32
	// peerSessionSyncWire holds the peer's advertised
	// SessionSyncWireVersion (#7990), carried as a trailing u16 on
	// syncMsgPeerCapabilities on top of #6650's version field and #7147's
	// flags byte. 0 means UNKNOWN — a peer predating #7990 advertises
	// nothing, and that is genuinely different from "advertises 0": there
	// is no valid sync wire version 0. A retained version would let the
	// LANE-1 drain gate certify compatibility against a version the
	// reconnected (possibly downgraded) peer no longer speaks.
	peerSessionSyncWire atomic.Uint32
	// peerHeartbeatAckEver latches when the CURRENTLY connected peer
	// proves it understands syncMsgHeartbeat by replying
	// syncMsgHeartbeatAck. It gates the two enforcement paths that would
	// otherwise punish a legacy peer that simply never acks: the
	// receiveLoop missed-heartbeat teardown (sync_conn_read.go) and
	// PeerHealthy's silence window (sync.go). #5718 C01a: scoped to the
	// peer incarnation, NOT SessionSync-lifetime — a peer downgrade (new
	// build acks, then rolls back to a build that never acks) must not
	// leave the latch armed against the new process. Do not promote this
	// back to a set-once flag.
	peerHeartbeatAckEver atomic.Bool
	// peerClockOffset is the global fallback clock offset rebasing
	// sessions carried by a connection that has not synced its own
	// (#9653/#9915 F-118). Every retirement zeroes it; the boot-ID switch
	// then re-seeds it from the kept connection's proven offset.
	peerClockOffset atomic.Int64
	// lastSentConfigAckCapable16756 records, atomically with
	// lastSentConfigGen, whether the peer incarnation that was current
	// when the newest generation was sent advertised config-apply-ACK
	// support (#16756). It lets PeerConfigStale charge a missing ACK
	// only to a peer that promised one.
	lastSentConfigAckCapable16756 atomic.Bool
	// peerConfigNackedGen16756 is the generation of the newest
	// current-send NACK (#16756 legacy fallback), or 0. A NACK whose
	// generation is behind lastSentConfigGen is a straggler and is
	// ignored by the fallback exactly as handleConfigApplyNack ignores
	// it for the re-push marker.
	peerConfigNackedGen16756 atomic.Uint64
	// deleteSuppressionWarned latches the #9714 F5 operator warning so a
	// path that can run thousands of times a second logs the episode
	// ONCE. The warning is about a peer INCARNATION, and a latch that
	// outlived it would stay silent through the reconnect that actually
	// matters — a downgrade, or the upgrade that fixes it.
	deleteSuppressionWarned atomic.Bool
	// purgeRetirementSuppressionWarned latches the #9752
	// forward-only-delete suppression warning, same incarnation scoping
	// as deleteSuppressionWarned.
	purgeRetirementSuppressionWarned atomic.Bool
	// scopedPolicySuppressionWarned latches the #10512 scoped-delete
	// suppression warning, same incarnation scoping as
	// deleteSuppressionWarned.
	scopedPolicySuppressionWarned atomic.Bool
	// installTableSuppressionWarned latches the #9752 round 3
	// stamped-install suppression warning, same incarnation scoping.
	installTableSuppressionWarned atomic.Bool
	// ipsecDiscriminatorSuppressionWarned latches the S9.4 IPsec
	// discriminator suppression warning (#17113), same incarnation
	// scoping as installTableSuppressionWarned.
	ipsecDiscriminatorSuppressionWarned atomic.Bool
	// bulkFencedForPeer latches a #9752 round 4 bulk refusal for the peer
	// incarnation: once a window aborts on the install fence, retries
	// skip quietly instead of burning full-table walks that all abort
	// the same way. Plus an early clear when a capable capability frame
	// lands (sync_bulk.go revalidates it on consume).
	bulkFencedForPeer atomic.Bool
	// bulkFencedForIpsecPeer is the independent S9.4 refusal latch. Its
	// eligibility is the IPsec discriminator capability, not
	// install-table identity; either fence must be revalidated on its
	// own bit.
	bulkFencedForIpsecPeer atomic.Bool
	// pbrAnnouncedForFence records that this node ANNOUNCED (sent) or
	// INSTALLED (received) a stamped session this peer incarnation
	// (#9752 round 5 item 1). While set, a mirror-sourced (0,0) with NO
	// memo record is suspect (in-race delta, foreign row, or post-cap)
	// rather than genuinely-non-PBR, and the sweep/bulk fence withholds
	// it from incapable peers.
	//
	// Scope decision (#17097): this stays incarnation-scoped even though
	// "this node announced a stamp" sounds node-local. The latch's
	// consumer withholds (0,0) installs only from an INCAPABLE peer
	// (suppressUnannouncedForPBRActivePeer also requires
	// !InstallTableIdentityCapable), and capability is per-incarnation:
	// carrying the latch into a new incarnation would withhold installs
	// from a peer whose capability has not been learned yet on evidence
	// gathered against its predecessor — the traced #17097 harm. The
	// next incarnation re-earns it on its first announced/received stamp
	// (sync_conn_gen.go), which precedes any mirror-sourced send that
	// needs it.
	pbrAnnouncedForFence atomic.Bool
	// installTableSuppressDebt records that this incarnation withheld ≥1
	// install on the #9752 fence (#9752 round 5 item 5). Suppressed
	// installs are never retried by the sweep (its window advances past
	// them), so a capable discovery transfers this debt into a
	// cold-prime re-arm (the redriven bulk snapshot carries them all).
	// Distinct from the warn latch above it: that one must never clear
	// within an incarnation (warn-once), this one is consumed by the
	// re-arm.
	installTableSuppressDebt atomic.Bool
	// ipsecDiscriminatorSuppressDebt records that the peer's S9.4
	// capability was unknown or absent when an IPsec-tagged session was
	// withheld. A capable discovery transfers this debt into a
	// cold-prime re-arm; the authoritative bulk then heals every
	// withheld session at once.
	ipsecDiscriminatorSuppressDebt atomic.Bool
}

// retirePeerIncarnationLocked installs a fresh peerIncarnationState for the
// new peer incarnation and clears the peerSnapshotProtocol pair that lives
// on peerSnapshotState (#17097). It is the ONLY incarnation-retirement
// reset: the boot-ID switch, installConn's supersession/epoch-raise
// advance, and handleDisconnect's full-disconnect arm all call it, so the
// three sites cannot diverge again.
//
// seed, when non-nil, is the priming connection whose already-proven
// capability set belongs to the NEW incarnation (#14161): only that
// connection's learned set is restored, never the retired global
// observation. An unproven seed (no interpretable frame, or a boot that
// does not match peerBootIncarnation) leaves the new incarnation unlearned
// (snapshot 0), incapable (flags 0) and wire-unknown (0). seed is nil on
// the advance and full-disconnect paths, which start unlearned.
//
// Caller must hold s.mu and s.peerSnaps.peerSnapshotProtocolWriteMu: the
// snapshot store and generation bump must serialize with gated config
// writes exactly as the inline lists they replace did. The state swap
// itself is a single pointer store under s.mu, so each individual
// peerIncarnationState() load observes either the whole old incarnation
// or the whole new one. That atomicity is per load only: production gates
// that re-load the pointer per field (rather than loading once and
// reading several fields from that snapshot) can still mix incarnations
// if a retirement lands mid-sequence, exactly as the pre-change flat
// atomics could — no stronger cross-field guarantee is claimed.
func (s *SessionSync) retirePeerIncarnationLocked(seed net.Conn) {
	fresh := &peerIncarnationState{}
	var snapshotProtocol uint32
	if ac, ok := seed.(*authConn); ok &&
		ac.bootIncarnation.known() && ac.bootIncarnation == s.peerBootIncarnation {
		snapshotProtocol = uint32(ac.peerSnapshotVersion)
		fresh.peerCapabilityFlags.Store(uint32(ac.peerCapabilityFlags))
		fresh.peerCapabilityFlags2.Store(uint32(ac.peerCapabilityFlags2))
		fresh.peerSessionSyncWire.Store(uint32(ac.peerSessionSyncWire))
	}
	s.peerSnaps.peerSnapshotProtocol.Store(snapshotProtocol)
	s.peerSnaps.peerSnapshotProtocolGeneration++
	// Publish last: capability readers load the pointer, so the seeded
	// values must be stored before the pointer becomes visible.
	s.peerIncarnationStatePtr.Store(fresh)
}

// peerIncarnationState returns the current incarnation's state, allocating
// the zero state on first use. SessionSync is built by ~98 in-package
// literals that never run a constructor (see sync_gen_state_16159.go), so
// the pointer starts nil and every access goes through here; the
// CompareAndSwap keeps concurrent first uses on one allocation. Once
// installed the pointer is only replaced (under s.mu) by
// retirePeerIncarnationLocked, never cleared, so the result is never nil.
func (s *SessionSync) peerIncarnationState() *peerIncarnationState {
	if p := s.peerIncarnationStatePtr.Load(); p != nil {
		return p
	}
	fresh := &peerIncarnationState{}
	if s.peerIncarnationStatePtr.CompareAndSwap(nil, fresh) {
		return fresh
	}
	return s.peerIncarnationStatePtr.Load()
}
