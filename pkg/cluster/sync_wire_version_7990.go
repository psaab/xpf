package cluster

// Session-sync WIRE version exchange (#7990).
//
// THE GAP THIS CLOSES. Since #7925, SessionSyncWireVersion is its own counter,
// independent of CurrentHAProtocolVersion. That was the right split — a
// session-wire-only change should not push the HA version out from under its own
// compat floor — but it left the version with exactly ONE gating consumer: the
// image manifest (`xpfd protocol-versions`), read by the LANE-2 executor
// (_gate_mixed_base in xpf-deploy.py) of upgrade.GateProtocolCompat.
//
// The LANE-1 IN-PLACE rolling path had no such check, because it had no channel:
// the heartbeat carries HAProtocolVersion and nothing about the sync wire, and
// sync.go records that the session-sync frame header has no on-wire version
// field. So a rolling upgrade across a SessionSyncWireVersion change would roll
// a pair into a state where neither node can decode the other's session frames —
// while heartbeat, election and failover all keep working, because the HA
// protocol never moved.
//
// That failure is the bad kind. The cluster stays UP and looks healthy; what is
// broken is session synchronisation, which is invisible until a failover needs
// it, and whose absence is indistinguishable from a cluster that simply has not
// synced anything yet. The operator discovers it by losing every established
// flow after a rolling upgrade that reported success.
//
// WHY THIS CHANNEL. The advertisement rides syncMsgPeerCapabilities rather than
// the heartbeat, for the three reasons #6650 already wrote down when it chose
// the same channel for the config-snapshot version — and they apply with more
// force here, because this version describes the sync connection itself:
//
//  1. It is the SAME connection whose compatibility is in question, so "peer
//     reachable" and "peer sync-wire version known" share one lifecycle.
//  2. The heartbeat is a size-capped UDP frame whose optional sections are
//     located by back-indexing from a fixed-size auth trailer; adding another
//     tail section makes both readers' offsets depend on whether the other is
//     present (a misplacement already split a keyed cluster in #6370's review),
//     and the epoch section requires a PSK, so an unkeyed cluster would get no
//     advertisement at all.
//  3. The sync wire has the precedent and the room: TCP, no size pressure, and
//     handleMessage's switch has no default arm with length-prefixed framing, so
//     growth is additive. #2239, #6650 and #7147 all relied on exactly this, and
//     #7147 grew THIS message by a trailing byte.
//
// NO VERSION BUMP, and here that is not merely convenient but forced: bumping
// SessionSyncWireVersion in order to advertise SessionSyncWireVersion would make
// GateProtocolCompat — which compares it for EXACT equality — refuse session sync
// across precisely the upgrade that first carries the field.

// PeerSessionSyncWireVersion reports the peer's advertised SessionSyncWireVersion,
// or 0 if the peer has not advertised one.
//
// 0 means UNKNOWN, and unlike #6650's snapshot version it does NOT mean
// "incapable": there is no valid sync wire version 0, so a caller can always
// tell "peer predates #7990" from any real version. Callers MUST handle unknown
// explicitly rather than comparing it as a number — see
// SessionSyncWireCompatible for why the honest handling is to permit.
func (s *SessionSync) PeerSessionSyncWireVersion() uint16 {
	if s == nil {
		return 0
	}
	return uint16(s.peerIncarnationState().peerSessionSyncWire.Load())
}

// SessionSyncWireCompatible reports whether the peer's session-sync wire version
// is known to be compatible with this node's, plus a human reason.
//
// TOTAL: every input yields exactly one (bool, reason) pair, so a caller can
// never get a verdict it has to guess at.
//
// THE UNKNOWN CASE IS PERMITTED, DELIBERATELY. A peer that advertises nothing
// predates #7990, and refusing on that would break the LANE-1 rolling upgrade
// that first introduces the field — the gate would fire on every roll from the
// last release and on no real skew, which is the worst possible calibration. It
// is the same dual-accept shape #4107 (heartbeat auth) and #4126 (VRRP checksum)
// used: accept both wire forms during the upgrade window, enforce once both
// sides speak the new one.
//
// Being honest about the consequence: this gate CANNOT protect the first roll
// that carries it. It protects every roll after, which is every roll that could
// actually move SessionSyncWireVersion — the constant has never moved, and #7160
// is the change that would move it first.
func SessionSyncWireCompatible(peerVersion uint16) (bool, string) {
	switch {
	case peerVersion == 0:
		return true, "peer advertises no session-sync wire version (predates #7990) — " +
			"permitted: refusing here would block the very rolling upgrade that " +
			"introduces the advertisement, and this node's version has not moved"
	case peerVersion == SessionSyncWireVersion:
		return true, "peer session-sync wire version matches"
	default:
		return false, "peer session-sync wire version differs — synced sessions would " +
			"not decode across the pair, so a drain would hand over to a node that " +
			"cannot receive this node's sessions"
	}
}
