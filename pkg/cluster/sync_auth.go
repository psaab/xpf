package cluster

// Session-sync stream authentication (#4107 F23).
//
// The cross-chassis session-sync stream (sync.go / sync_conn.go /
// sync_protocol.go) is length-framed: every message is a `syncHeader`
// (magic + type + length) followed by `length` payload bytes. Before this
// change the stream carried session state, config, and election/failover
// control messages in cleartext with no authentication — any host that could
// reach the fabric/control-link IP could open the listener, dump session
// tuples, or drive a failover.
//
// The heartbeat's trailing-HMAC approach (heartbeat.go, #4357/PR-A) does NOT
// work on a length-framed stream: a legacy reader would mis-frame an appended
// HMAC as the next message header. So F23 uses an auth-capability HANDSHAKE at
// connection setup that negotiates — BEFORE any session frame flows — whether
// the connection is authenticated, and, once authenticated, seals every
// subsequent frame with a per-connection monotonic sequence + HMAC so an
// on-path attacker can neither forge nor replay a frame.
//
// Design summary:
//   - Handshake (performSyncHandshake): only a node that holds the shared
//     control-link PSK (the same `set chassis cluster authentication-key`
//     secret that #4357 wired for the heartbeat + fabric gRPC) initiates the
//     handshake. It sends a HELLO advertising a fresh 32-byte challenge nonce;
//     when BOTH peers are keyed each proves possession of the PSK with an
//     HMAC over the OTHER side's nonce (mutual challenge-response). Fresh
//     per-connection nonces make the proof replay-safe at setup.
//   - Dual-accept, UNKEYED SIDE ONLY: a node with no key never handshakes and
//     is byte-for-byte a legacy peer, so an unkeyed node still accepts anything.
//     A KEYED node does NOT dual-accept — #5078 removed that. It requires an
//     authenticated peer and rejects a legacy/unkeyed one outright, with no
//     first-contact grace and no migration window; see syncAuthDecision.
//   - No sync-side downgrade-guard: there is nothing left for one to protect.
//     A guard of that shape only matters where an unkeyed peer would otherwise
//     be admitted, and on a keyed node none ever is. The former
//     syncPeerAuthSeen / syncAuthedEver pair was removed once #5078 made the
//     rejection unconditional — it had become unreachable, and a dead guard
//     whose doc still asserts a live property is exactly the hazard #5078
//     removed the pre-admission frame path for. The #4107 HEARTBEAT downgrade
//     guard is SEPARATE state (heartbeatAuthState.peerAuthenticated, reached
//     via Manager.HeartbeatPeerAuthSeen) and is unaffected, as is the #4357
//     fabric guard that consumes it.
//   - Per-frame seal (authConn.sealFrame / verifyFrame): on an authenticated
//     connection every frame gets an 8-byte per-connection sequence + a
//     32-byte HMAC (keyed by a per-connection key derived from the PSK and
//     BOTH handshake nonces). The receiver rejects a bad HMAC (forgery /
//     tamper) or a non-increasing sequence (replay). Frames on an
//     unauthenticated connection are pass-through — identical to the legacy
//     wire — so dual-accept never changes the bytes.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

const (
	// syncMsgAuthHello and syncMsgAuthProof are the two handshake message
	// types. They are ABOVE the legacy message set (<= 26) so a peer that
	// predates F23 hits the (implicit) default receive case and ignores them —
	// the same additive-type discipline as the #2239 DHCP-lease messages.
	syncMsgAuthHello = 27 // {version:u8, keyed:u8, nonce[32]}
	syncMsgAuthProof = 28 // HMAC-SHA256 proof over the peer's HELLO nonce
)

const (
	syncAuthMACSize = sha256.Size // 32
	// syncAuthFrameTrailerSize is appended to each frame on an authenticated
	// connection: seq(8) + HMAC-SHA256(32).
	syncAuthFrameTrailerSize = 8 + syncAuthMACSize
	// syncHandshakeTimeout bounds the whole setup handshake. A hung/absent
	// peer drops the connection; fabricConnectLoop retries after ~1s, so a
	// transient handshake failure only delays reconnect — it never bricks
	// (dual-accept keeps a rolling upgrade alive without the handshake).
	//
	// The keyed↔keyed challenge-response completes in milliseconds when both
	// nodes are up; this bound only covers a hung or absent peer. It is kept
	// short (#4370) because the accepting node runs the handshake per inbound
	// connection — a longer bound lets a stalled connection tie up a handshake
	// goroutine (and, on Stop, keep it inside the 5s shutdown budget). 3s is
	// ample headroom over the sub-millisecond keyed path.
	syncHandshakeTimeout = 3 * time.Second
)

// Domain-separation tags — bound into every HMAC so a value produced for one
// purpose can never be reused as another.
//
// #7163 removed two of them with the constructions they belonged to:
// syncAuthProofTag (the challenge-response proof) and syncAuthFrameKeyTag (the
// canonically-sorted, and therefore undirected, frame-key derivation). Both
// are now supplied by the Noise pattern — see sync_auth_noise_7163.go — and
// leaving the primitives behind would leave a second way to derive an
// unbound key sitting in the tree for the next author to reach for.
var (
	syncAuthFrameMACTag = []byte("xpf-cluster-sync-frame-mac-v1\x00")

	// syncAuthUpgradeConfirmTag separates the #6628 upgrade confirmation MAC
	// from the per-frame seal, which is keyed by the SAME directional key.
	// Without the tag a confirmation and a frame seal would be two HMACs under
	// one key over attacker-influenced input.
	syncAuthUpgradeConfirmTag = []byte("xpf-cluster-sync-upgrade-confirm-v1\x00")
)

var (
	errSyncFrameAuth   = errors.New("cluster sync: frame HMAC verification failed")
	errSyncFrameReplay = errors.New("cluster sync: frame sequence replay/regression")
)

// syncAuthMode is the negotiated auth posture for one sync connection.
type syncAuthMode int

const (
	syncAuthUnauthenticated syncAuthMode = iota // dual-accept: frames are pass-through
	syncAuthAuthenticated                       // PSK handshake succeeded; frames sealed
)

// SyncAuthProvider supplies the shared control-link PSK to the session-sync
// stream authenticator (#4107 F23). *Manager satisfies it. It is OPTIONAL:
// when no provider is wired, or the key is empty, the sync stream runs in
// legacy unauthenticated mode, byte-identical to before.
//
// #5078: this used to also require HeartbeatPeerAuthSeen(), the cross-channel
// downgrade-guard signal. Its only consumer was syncPeerAuthSeen, which the
// unconditional keyed-node rejection made unreachable, so the requirement went
// with it. Manager still EXPORTS HeartbeatPeerAuthSeen — the gRPC fabric
// listener (pkg/grpcapi) and the control-link auth status string both consume
// it — it is simply no longer part of this interface's contract.
type SyncAuthProvider interface {
	ControlLinkAuthKey() []byte
}

type syncAuthProviderBox struct{ p SyncAuthProvider }

// SetAuthProvider wires the shared-PSK source used to authenticate the
// session-sync stream. Call once before Start.
func (s *SessionSync) SetAuthProvider(p SyncAuthProvider) {
	s.authProvider.Store(&syncAuthProviderBox{p: p})
}

// authKey returns the current control-link PSK, or nil when no provider is
// wired / no key is configured. Read live so a key added/changed at commit is
// picked up on the next handshake.
func (s *SessionSync) authKey() []byte {
	if box := s.authProvider.Load(); box != nil && box.p != nil {
		return box.p.ControlLinkAuthKey()
	}
	return nil
}

// authConn wraps a session-sync connection after the setup handshake. When
// key != nil the connection is AUTHENTICATED: every frame written through
// writeFull gets a per-connection sequence + HMAC trailer (sealFrame) and
// receiveLoop verifies + replay-checks it (verifyFrame). key == nil is an
// UNAUTHENTICATED (dual-accept) pass-through — byte-identical to the legacy
// path — so the same wrapper type covers both negotiated postures.
type authConn struct {
	net.Conn
	// readKey and writeKey are the per-connection frame-MAC key, held
	// SEPARATELY per direction (#6628). Nil ⇒ pass-through in that direction.
	//
	// One field for both directions was correct while authentication could
	// only be decided at connection setup: the handshake set it before any
	// frame flowed, so read and write were always in the same state. The
	// in-place upgrade switches a LIVE stream, and a single field flips both
	// directions at the same instant on ONE end — the moment X starts
	// requiring a trailer, Y is still sending unsealed frames, so X consumes
	// syncAuthFrameTrailerSize bytes of the NEXT frame as a "trailer", fails
	// the MAC, and drops the connection. Splitting them lets each direction
	// switch at the frame boundary the peer actually switched at, which TCP's
	// per-direction ordering makes unambiguous. See upgradeAuthInPlace.
	//
	// writeKey is published under SessionSync.writeMu — already the invariant
	// that serialises every write to a connection — so the receive-loop
	// goroutine that installs it cannot race a concurrent seal. readKey is
	// touched only by the single receiveLoop goroutine that owns this
	// connection, like recvSeq/recvSeen below.
	readKey  []byte
	writeKey []byte

	// bootIncarnation is the peer boot id the BulkStart on THIS connection
	// primed under (#5084). Zero until an incarnated prime arrives, and zero
	// forever against a peer that predates the field. Per connection rather
	// than per slot because a config payload must be stamped with the
	// incarnation of the stream that carried it, not with whatever the other
	// fabric last saw.
	//
	// unincarnatedWarned makes the fail-open notice ONE line per connection
	// instead of one per prime.
	bootIncarnation    bootIncarnation
	unincarnatedWarned bool

	// authPSK is the control-link PSK this connection's authentication was
	// established under — the staleness test the #6628 reconciler uses. Nil on
	// an unauthenticated connection. It is what lets ReconcileConnectionAuth
	// be called on EVERY commit and cost nothing: an unrelated config change
	// finds authPSK equal to the live key and does nothing.
	authPSK []byte

	// upgrade is the #6628 in-place upgrade exchange state, nil until an
	// exchange starts on this connection. Defined and driven entirely by
	// sync_auth_upgrade.go; read and written under SessionSync.writeMu, which
	// the exchange already holds so each key install sits in the same critical
	// section as the frame that is the peer's read boundary.
	upgrade *authUpgradeState

	// strictGraceStart anchors the #7441 eviction grace: the MONOTONIC instant
	// of the first reconcile at which this node was keyed and this connection
	// was not authenticated. Zero until then, which is why an unkeyed node
	// evicts nothing.
	//
	// SET ONCE, and that is a security property rather than an optimisation: a
	// later reconcile must not push it forward, or a peer able to induce
	// commits could hold its own window open indefinitely — #5078's "re-arming"
	// constraint. Monotonic so a wall-clock step cannot extend it.
	//
	// Written and read under SessionSync.writeMu, like authPSK above.
	strictGraceStart int64

	sendSeq atomic.Uint64 // monotonic per-connection send counter
	// recvSeq/recvSeen are the replay watermark, touched only by the single
	// receiveLoop goroutine that owns this connection — no lock needed.
	recvSeq  uint64
	recvSeen bool
}

// readAuthed reports whether inbound frames on this connection carry a trailer
// that must be verified.
func (a *authConn) readAuthed() bool { return a != nil && len(a.readKey) > 0 }

// writeAuthed reports whether outbound frames on this connection must be
// sealed.
func (a *authConn) writeAuthed() bool { return a != nil && len(a.writeKey) > 0 }

// authed reports whether this connection is authenticated in BOTH directions.
// It is the operator-facing / status sense of the word; the two directional
// predicates above are what the frame paths gate on, because during an
// in-place upgrade (#6628) the two are briefly, legitimately, different.
func (a *authConn) authed() bool { return a.readAuthed() && a.writeAuthed() }

// sealFrame appends the per-connection auth trailer to a fully-encoded frame
// (header||payload). Callers hold s.writeMu — the invariant that serializes
// every write to a connection — so the assigned sequence order equals the
// on-wire order.
func (a *authConn) sealFrame(frame []byte) []byte {
	seq := a.sendSeq.Add(1)
	out := make([]byte, len(frame)+syncAuthFrameTrailerSize)
	n := copy(out, frame)
	binary.LittleEndian.PutUint64(out[n:n+8], seq)
	mac := hmac.New(sha256.New, a.writeKey)
	mac.Write(syncAuthFrameMACTag)
	mac.Write(out[:n+8]) // frame || seq
	copy(out[n+8:], mac.Sum(nil))
	return out
}

// verifyFrame authenticates the trailer that follows a frame on an
// authenticated connection and enforces the strictly-increasing per-connection
// sequence (replay/regression guard). header+payload are the frame as read by
// receiveLoop; trailer is the syncAuthFrameTrailerSize bytes read immediately
// after. On success it advances the watermark; any error causes receiveLoop to
// drop the connection.
func (a *authConn) verifyFrame(header, payload, trailer []byte) error {
	if len(trailer) != syncAuthFrameTrailerSize {
		return errSyncFrameAuth
	}
	seq := binary.LittleEndian.Uint64(trailer[:8])
	mac := hmac.New(sha256.New, a.readKey)
	mac.Write(syncAuthFrameMACTag)
	mac.Write(header)
	mac.Write(payload)
	mac.Write(trailer[:8])
	if !hmac.Equal(trailer[8:], mac.Sum(nil)) {
		return errSyncFrameAuth
	}
	if a.recvSeen && seq <= a.recvSeq {
		return errSyncFrameReplay
	}
	a.recvSeq = seq
	a.recvSeen = true
	return nil
}

// #7163 removed syncAuthProof, syncCheckPeerNonce and syncDeriveFrameKey from
// this file. They were the vector-B defect itself, not merely its carriers:
//
//   - syncAuthProof was HMAC(key, tag ‖ challenge) — no role, no node identity,
//     no transcript — so a proof computed on one connection verified on any
//     other, which is the two-connection oracle.
//   - syncDeriveFrameKey sorted its two nonces canonically, so both directions
//     of a connection derived ONE key and a node's own frame verified when
//     echoed back at it.
//   - syncCheckPeerNonce was the #5078 vector-A patch on top of syncAuthProof.
//     With no nonces left to reflect it guards nothing.
//
// They are DELETED rather than left unreferenced. Both admission paths — the
// connect handshake and the #6628 in-place upgrade — now run Noise_NNpsk0, and
// an unused HMAC-over-a-nonce helper sitting in this file is what the next
// author reaches for when they add a third one.

// syncAuthDecision applies the #4107 dual-accept policy for a session-sync
// connection handshake and returns the negotiated mode, whether to accept the
// connection, and (on rejection) a short reason for logging — never the key.
// It mirrors heartbeatAuthDecision.
//
//	keyConfigured  — the local ControlLinkAuthKey is set (we can verify).
//	peerAdvertised — the peer sent an auth HELLO (an upgrade-aware peer).
//	peerKeyed      — the peer's HELLO advertised that it holds a key.
//	proofOK        — the peer's challenge-response proof verified (meaningful
//	                 only when both sides are keyed).
//
// Policy:
//   - No local key: dual-accept — this node cannot verify and may be the
//     not-yet-keyed side of a rolling upgrade.
//   - Local key + peer keyed (proof exchanged): enforce — reject a bad proof.
//   - Local key + peer legacy/unkeyed: REJECT, unconditionally.
//
// #5078: that last line used to grant a first-contact grace — a keyed node
// dual-accepted an unkeyed peer whenever `peerAuthSeen` was still false. That
// grace was an unauthenticated ACTIVE bypass, not a compatibility affordance,
// and it did not need the reflection weakness to exploit: a PSK-less attacker
// reaching the fabric on first contact was admitted, could fence the node
// (disabling every RG), and displaced the legitimate peer connection — after
// which arming the sticky guard did not evict it. `peerAuthSeen` is therefore
// no longer consulted for this branch; it cannot be, because the whole window
// is "before the guard arms".
//
// There is deliberately NO relaxation knob — but the rollout constraint is
// sharper than an earlier revision of this comment claimed. An RG0 secondary
// whose read-only gate is ARMED cannot be keyed locally:
// applyRG0OwnershipTransition sets the store read-only on
// StateSecondary/StateSecondaryHold and EnterConfigureSession then returns
// ErrClusterReadOnly, so config-sync is that node's only writer. Arming is
// driven by an RG0 TRANSITION event and nothing else, so a node that
// cold-starts into secondary and never transitions is still writable, and REST
// has no RG0 check of its own — see #6890 (and #6889 for the dropped-event
// variant). Both are OPEN and unscheduled; do not design a rollout around
// either, and do not assume they are fixed.
// Keying a LIVE cluster therefore means committing on the PRIMARY while sync is
// connected and letting the established connection carry the key across — which
// works only because the auth key is absent from clusterTransportKey, so a key
// commit does not restart cluster comms (pinned by
// TestAuthKeyChangeDoesNotRestartClusterComms_5078). Keying at provisioning,
// before either node seats as secondary, avoids the question entirely.
//
// A bounded dual-accept window was shipped and then removed. It had to bound a
// connection's LIFETIME rather than just its admission (an admitted
// pass-through stream outlived the deadline), it had to stop an admitted peer
// re-arming it through config-sync, and it could not survive a crash loop
// without persisting its deadline. A relaxation that needs three guards of its
// own does not belong in the fix that closes the hole.
//
// The property this leaves is the right one for a security appliance: for a
// connection established AFTER keying, a node must POSSESS the key to join a
// keyed cluster. A fresh or RMA node is keyed locally as part of the same
// bootstrap that gives it its node-id.
//
// That qualifier is load-bearing, and it is exactly what makes the live-keying
// procedure above work. Verification is gated PER CONNECTION and was fixed at
// handshake time, so a connection established BEFORE the key was committed
// used to stay unauthenticated for its whole lifetime and keep having its
// frames accepted with no HMAC.
//
// #6628 closed the part of that about the LEGITIMATE peer: a commit now
// triggers an IN-PLACE upgrade over the established connection
// (sync_auth_upgrade.go), which promotes it to authenticated — and re-derives
// its frame key on a rotation — without a reconnect and without ever dropping
// it. So "the key never applies retroactively to an established stream" is no
// longer true for a peer that answers.
//
// It is still true for a peer that does NOT answer, and that residual is
// OPEN. A hostile stream admitted before the commit declines the upgrade by
// staying silent, and a decliner is indistinguishable from a legitimate peer
// that is not keyed yet — which is the rolling-upgrade case none of this may
// break. Closing it needs a bounded window after which an un-upgraded
// connection is dropped, i.e. the mechanism this file records as shipped and
// then REMOVED, with the three constraints any replacement must answer. Do not
// read the upgrade as closing it.
func syncAuthDecision(keyConfigured, peerAdvertised, peerKeyed, proofOK bool) (mode syncAuthMode, accept bool, reason string) {
	if !keyConfigured {
		return syncAuthUnauthenticated, true, ""
	}
	if peerAdvertised && peerKeyed {
		if proofOK {
			return syncAuthAuthenticated, true, ""
		}
		return syncAuthUnauthenticated, false, "hmac verification failed"
	}
	return syncAuthUnauthenticated, false, "missing auth handshake (enforced: this node is keyed)"
}

// readSyncFrameRaw reads one length-framed sync frame (header+payload) directly
// from a connection during the handshake, before any per-frame sealing is in
// effect. It does not strip an auth trailer.
func readSyncFrameRaw(conn net.Conn) (typ uint8, payload []byte, err error) {
	hdr := make([]byte, syncHeaderSize)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	if [4]byte{hdr[0], hdr[1], hdr[2], hdr[3]} != syncMagic {
		return 0, nil, errors.New("cluster sync: bad magic during handshake")
	}
	typ = hdr[4]
	length := binary.LittleEndian.Uint32(hdr[8:12])
	if length > 16*1024*1024 {
		return 0, nil, fmt.Errorf("cluster sync: handshake frame too large: %d", length)
	}
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return typ, payload, nil
}

// performSyncHandshake runs the connection-setup auth-capability handshake on a
// freshly connected sync connection and returns the negotiated mode, the
// per-connection frame key (non-nil only when authenticated), an optional first
// frame a legacy/unkeyed peer already sent (the caller must process it before
// reading further), and an error when the connection must be dropped (bad PSK
// proof, a downgrade attempt, or an I/O failure).
//
// The handshake runs ONLY when a local key is configured. An unkeyed node
// (legacy build, or a new build with no key yet) sends nothing special and is
// indistinguishable from — and fully compatible with — a legacy peer, so
// existing no-key deployments and tests are unaffected (dual-accept).
//
// HELLO and PROOF are written concurrently with reading the peer's frame so the
// handshake works over a fully-synchronous transport (net.Pipe in tests): a
// strict write-then-read on both symmetric peers would deadlock.
func (s *SessionSync) performSyncHandshake(conn net.Conn, initiator bool, fabricIdx int) (syncAuthMode, syncNoiseKeys, error) {
	key := s.authKey()
	if len(key) == 0 {
		// No local key => no handshake; legacy behavior (dual-accept).
		return syncAuthUnauthenticated, syncNoiseKeys{}, nil
	}

	if err := conn.SetDeadline(time.Now().Add(syncHandshakeTimeout)); err != nil {
		return syncAuthUnauthenticated, syncNoiseKeys{}, err
	}
	defer conn.SetDeadline(time.Time{})

	// #7163: the whole custom challenge-response is replaced by Noise_NNpsk0.
	// What used to live here — a nonce exchange, syncAuthProof over the peer's
	// nonce, syncCheckPeerNonce, and syncDeriveFrameKey's canonical sort — is
	// gone rather than reordered, because every one of those pieces existed to
	// approximate a property the pattern now supplies by construction. See
	// sync_auth_noise_7163.go for which binding comes from where.
	//
	// The legacy arms are gone with it, and that is a DELIBERATE
	// INCOMPATIBILITY, not an oversight: this is a flag day. A pre-#7163 peer
	// sends the old HELLO, which is not a valid Noise msg1, so the handshake
	// fails and the connection drops. SessionSyncWireVersion is bumped so
	// GateMixedBaseSwap refuses the mixed-base swap up front rather than
	// letting an operator discover it as a fabric that will not come up.
	keys, err := s.performNoiseHandshake(conn, key, initiator, fabricIdx)
	if err != nil {
		return syncAuthUnauthenticated, syncNoiseKeys{}, err
	}
	return syncAuthAuthenticated, keys, nil
}

// wrapSyncConn applies the negotiated handshake result to a connection: it
// wraps conn in an authConn (sealing frames when authenticated) and, when the
// connection authenticated, arms the sticky downgrade-guard.
//
// #6881: an earlier revision of this comment described a second return value —
// `pending`, "the legacy peer's first frame (nil when none) ... returned for
// the caller to process before starting the receive loop". There is no such
// value and there is no such frame. #5078 removed the dual-accept path that
// produced one, and this function has returned a bare *authConn since. The
// prose outlived the mechanism; see the `pendingFrame` note in
// syncAuthDecision for why executing a peer frame before admission was the
// bug rather than the feature.
func (s *SessionSync) wrapSyncConn(fabricIdx int, conn net.Conn, mode syncAuthMode, keys syncNoiseKeys) *authConn {
	ac := &authConn{Conn: conn}
	if mode == syncAuthAuthenticated {
		// #7163: the two directions get INDEPENDENT keys, straight from the
		// Noise Split(). Before this they were the same bytes, which is what
		// made a node's own frame — `syncMsgFence` above all — verify when
		// echoed back to it on the same connection.
		//
		// Both are set at once because the handshake completed before any
		// frame flowed: there is no live stream to switch and no ordering to
		// respect. Only the #6628 in-place upgrade sets them separately.
		ac.readKey = keys.readKey
		ac.writeKey = keys.writeKey
		// #6628: record the PSK this connection authenticated under, so the
		// in-place-upgrade reconciler leaves it alone. Without this a
		// connect-authenticated connection looks stale to the reconciler
		// (authPSK nil) and every commit starts a pointless upgrade exchange
		// on a perfectly healthy stream — needless traffic, and a mid-stream
		// key switch exercised for no reason.
		ac.authPSK = append([]byte(nil), s.authKey()...)
		slog.Info("cluster sync: connection authenticated with control-link PSK",
			"fabric", fabricIdx, "remote", connRemoteAddrString(conn))
	}
	return ac
}
