package cluster

// Peer capability exchange for the cross-chassis config-snapshot protocol
// skew (#6650).
//
// THE HAZARD. The #5488 gate protects the daemon<->local-helper skew: a node
// refuses to commit a config its OWN helper cannot represent. It does nothing
// for the CROSS-CHASSIS skew, which on this product is what "rolling upgrade"
// usually means — a chassis cluster upgraded one node at a time. An upgraded
// primary's gate short-circuits (its own helper is current), the commit
// succeeds, and pushCommittedConfigToPeer ships the config TEXT to the peer.
// The peer recompiles that text with ITS OWN older compiler against its own
// older helper, passes its own gate, and installs a NARROWED policy. Traffic
// the operator denied is denied on one node and permitted on the other.
//
// WHY THE SENDER HAS TO DECIDE. The receiver cannot fix this: it is the old
// binary, and an old binary cannot be taught a shape it does not parse. Only
// the sender can decline to push. So the sender needs to know what the peer
// can represent, and nothing in the tree exchanged that — the heartbeat
// carries HAProtocolVersion and a free-form SoftwareVersion, and the
// config-snapshot protocol version is deliberately node-local
// (cmd/xpfd/main.go says so in a comment).
//
// WHY THIS CHANNEL. The advertisement rides the session-sync connection rather
// than the heartbeat for three reasons:
//
//  1. It is the SAME connection the config push goes over, so "peer reachable"
//     and "peer capability known" share one lifecycle. A capability learned
//     over one transport and acted on over another can disagree.
//  2. The heartbeat is a size-capped UDP frame whose optional sections are
//     located by back-indexing from a fixed-size auth trailer (the #6169 boot
//     epoch sits at len-68). Adding a second tail section makes both readers'
//     offsets depend on whether the other is present, and the epoch section
//     additionally requires a PSK — so an unkeyed cluster would get no
//     advertisement at all.
//  3. The sync wire already has the precedent and the room: TCP, no size
//     pressure, and the #2239 DHCP-lease messages established that a NEW
//     message type is additive because the receive switch has no default arm.

// SetLocalSnapshotProtocolVersion records this node's config-snapshot protocol
// version for advertisement to the peer. The daemon calls it at bring-up,
// mirroring Manager.SetSoftwareVersion.
//
// A zero version is advertised as zero. Receivers treat a connected peer
// with no nonzero protocol version as incapable, independently of the trailing
// capability flags carried in the same frame.
func (s *SessionSync) SetLocalSnapshotProtocolVersion(v uint16) {
	if s == nil {
		return
	}
	s.localSnapshotProtocol.Store(uint32(v))
}

// PeerSnapshotProtocolVersion reports the peer's advertised config-snapshot
// protocol version, or 0 if the peer has not advertised one.
//
// 0 means INCAPABLE, not unknown. A connected peer that advertises nothing runs
// a build predating #6650, which necessarily predates every snapshot version a
// caller could be gating on. Callers must therefore treat 0 as "refuse", and
// must separately check that a peer is connected at all before refusing —
// a node with no peer has nothing to narrow its config.
func (s *SessionSync) PeerSnapshotProtocolVersion() uint16 {
	if s == nil {
		return 0
	}
	return uint16(s.peerSnapshotProtocol.Load())
}

// PeerSnapshotState is the capability observation that authorizes an outgoing
// config snapshot. Learned follows the existing #6650 convention: nonzero
// versions are learned, while 0 is incapable whether absent or explicit.
// Generation changes when the advertised protocol changes or is cleared, so a
// sender can bind a later queue operation to this exact observation.
type PeerSnapshotState struct {
	Version    uint16
	Learned    bool
	Generation uint64
	Connected  bool
}

// SnapshotPeerSnapshotProtocol returns the peer capability and connection
// state under the same lock used to replace connections and update the
// advertised protocol.
func (s *SessionSync) SnapshotPeerSnapshotProtocol() PeerSnapshotState {
	if s == nil {
		return PeerSnapshotState{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerSnapshotStateLocked()
}

// peerSnapshotStateLocked binds the session-global advertisement to the
// SELECTED connection's own proof. A replacement installed into the empty
// alternate slot can become the preferred active socket while the other fabric
// survives, without tripping the supersession or epoch-reboot classifiers.
// Production connections are authConn wrappers; direct unwrapped connections
// are test fixtures and retain the injected session-level observation. Caller
// holds s.mu.
func (s *SessionSync) peerSnapshotStateLocked() PeerSnapshotState {
	version := uint16(s.peerSnapshotProtocol.Load())
	selected := s.activeConnLocked()
	if selected != nil && !s.connIsCurrentIncarnationLocked(selected) {
		version = 0
	} else if ac, ok := selected.(*authConn); ok && ac.peerSnapshotVersion < version {
		version = ac.peerSnapshotVersion
	}
	return PeerSnapshotState{
		Version:    version,
		Learned:    version != 0,
		Generation: s.peerSnapshotProtocolGeneration,
		Connected:  s.stats.Connected.Load(),
	}
}
