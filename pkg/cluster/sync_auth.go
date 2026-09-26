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
//   - Handshake (`performSyncHandshake`): only a node with a local control-link
//     PSK enters Noise_NNpsk0. The dialer writes msg1 in `syncMsgAuthHello`;
//     the accepter reads it and writes msg2 in `syncMsgAuthProof`. Noise binds
//     the transcript to the PSK, and a peer that cannot complete the exchange
//     is rejected before any session frame flows. A successful split supplies
//     independent directional frame keys.
//   - Dual-accept, UNKEYED SIDE ONLY: a node with no key never handshakes and
//     is byte-for-byte a legacy peer, so an unkeyed node still accepts anything.
//     A KEYED node does NOT dual-accept — #5078 removed that. It requires a
//     peer that completes the Noise exchange and rejects one that cannot, with
//     no first-contact grace and no migration window; see performSyncHandshake.
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
//     32-byte HMAC keyed by the directional frame key from Noise Split(). The
//     receiver rejects a bad HMAC (forgery / tamper) or a non-increasing
//     sequence (replay). Frames on an unauthenticated connection are
//     pass-through — identical to the legacy wire, so dual-accept never
//     changes the bytes.

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
	// syncMsgAuthHello and syncMsgAuthProof are the two PRE-INSTALL handshake
	// message types, read by readSyncFrameRaw before the connection is wired
	// up. They sit above the pre-F23 message set (which ran to 26 when F23
	// landed) so a peer that predates F23 hits the (implicit) default receive
	// case and ignores them — the same additive-type discipline as the #2239
	// DHCP-lease messages. Post-install, 27 is REUSED as syncMsgConfigApplyNack
	// (phase-separated, not a live collision — see the NOTE in sync.go); the
	// post-install set runs to 39 (the scoped #10018 persistent-NAT lease
	// message); 38 is retained as the retired unscoped lease message, 28 has
	// no post-install receive arm, and 34 is reserved-unused. See
	// liveSyncMessageTypesExcept and TestLiveSyncMessageCensusIsComplete7163
	// for the current census.
	syncMsgAuthHello = 27 // Noise_NNpsk0 handshake msg1 (raw; see performNoiseHandshake)
	syncMsgAuthProof = 28 // Noise_NNpsk0 handshake msg2 (raw; see performNoiseHandshake)
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
	// The keyed↔keyed Noise exchange completes in milliseconds when both
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
// listener consumes it — it is simply no longer part of this interface's
// contract, and the control-link auth status string renders from local key
// state instead (#10315).
type SyncAuthProvider interface {
	ControlLinkAuthKey() []byte
}

// syncPeerAuthRecorder is an optional capability for auth providers that retain
// the process-lifetime proof that the peer holds the shared key. The Manager
// uses the same sticky signal for the fabric gRPC downgrade guard when a keyed
// fabric-transport cluster has no heartbeat.
type syncPeerAuthRecorder interface {
	noteSyncPeerAuthenticated()
}

func (s *SessionSync) recordAuthenticatedPeer() {
	if box := s.authProvider.Load(); box != nil && box.p != nil {
		if recorder, ok := box.p.(syncPeerAuthRecorder); ok {
			recorder.noteSyncPeerAuthenticated()
		}
	}
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

// peerProcessIdentity is the sender identity advertised on a capabilities
// frame (#9818). The boot id distinguishes OS boots; the ordered boot epoch
// distinguishes daemon processes that restart without an OS reboot; and the
// Manager-scoped token remains unique when persistence cannot advance the
// epoch. Either field may be absent while a peer is rolling back or cannot
// read its local identity, so the zero value means "unattributed".
type peerProcessIdentity struct {
	boot  bootIncarnation
	epoch uint64
	token uint64
}

func (id peerProcessIdentity) known() bool {
	return id.boot.known() || id.epoch != 0 || id.token != 0
}

func (id peerProcessIdentity) sameProcess(other peerProcessIdentity) bool {
	if id.token != 0 && other.token != 0 {
		return id.token == other.token
	}
	return id.boot == other.boot && id.epoch == other.epoch
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
	// clockOffset is the peer clock offset the ClockSync on THIS connection
	// established, and clockSynced says one was accepted (#9653). Sessions the
	// connection carries rebase with it (clockOffsetFor), so a ClockSync on one
	// connection cannot rebase the sessions another connection carries.
	clockOffset atomic.Int64
	clockSynced atomic.Bool

	// bootIncarnation is the peer boot id the BulkStart on THIS connection
	// primed under (#5084). Zero until an incarnated prime arrives, and zero
	// forever against a peer that predates the field. Per connection rather
	// than per slot because a config payload must be stamped with the
	// incarnation of the stream that carried it, not with whatever the other
	// fabric last saw.
	//
	// peerIdentity is the process identity the peer advertised on this
	// connection's capabilities frame (#9818). It is deliberately per
	// connection: a new peer process can install one fabric before any reboot
	// classifier has evidence, while the other fabric still carries the
	// retired process. A zero value means the peer announced nothing, so
	// retirement falls back to the pre-#9818 stamp rule.
	peerIdentity peerProcessIdentity
	// peerCapabilitiesSeen records that this connection delivered the
	// capabilities frame, including a legacy/short frame. Retirement defers
	// eviction while this is false because the other fabric's frame may arrive
	// first; the two receive loops have no cross-connection ordering.
	peerCapabilitiesSeen bool
	// peerCapabilitiesExpected marks a production connection after wrapping
	// and before its local capabilities advertisement is sent. Test fixtures
	// that install sockets directly leave it false, retaining legacy behavior.
	peerCapabilitiesExpected bool
	// pendingRetirement marks a stale-stamped connection preserved until its
	// in-flight capabilities frame identifies it as the retired process or a
	// replacement. Guarded by SessionSync.mu.
	pendingRetirement      bool
	pendingRetirementGen   uint64
	retiredIdentity        peerProcessIdentity
	pendingRetirementTimer *time.Timer
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

	// strictGraceStart anchors the #10717 default eviction grace: the
	// MONOTONIC instant of the first reconcile at which this node was keyed
	// and this connection was not authenticated. Zero until then, which is
	// why an unkeyed node evicts nothing.
	//
	// SET ONCE, so later commits cannot extend the connection's lifetime.
	// Monotonic time prevents wall-clock steps from extending the grace.
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

// Session-sync admission is enforced by performSyncHandshake. The connection
// setup runs Noise_NNpsk0, so a keyed node accepts only a peer that proves
// possession of the control-link PSK; there is no separate policy helper whose
// result can drift from the live handshake.
// Keying at provisioning, before either node seats as secondary, avoids the
// question entirely.

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

// performSyncHandshake runs the connection-setup Noise_NNpsk0 handshake on a
// freshly connected sync connection and returns the negotiated mode, directional
// frame keys (non-nil only when authenticated), and an error when the connection
// must be dropped (a peer that cannot complete the PSK handshake or an I/O
// failure).
// The handshake runs ONLY when a local key is configured. An unkeyed node
// (legacy build, or a new build with no key yet) sends nothing special and is
// indistinguishable from — and fully compatible with — a legacy peer, so
// existing no-key deployments and tests are unaffected (dual-accept).
// The initiator writes its Noise msg1 before reading the responder's msg2; the
// responder reads msg1 before writing msg2. This role order avoids deadlock on
// a fully-synchronous transport (net.Pipe in tests).
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
	// The Noise handshake proves that the peer holds the same control-link
	// PSK. This also arms the fabric gRPC downgrade guard when the selected
	// transport is fabric and no control-link heartbeat is running.
	s.recordAuthenticatedPeer()
	return syncAuthAuthenticated, keys, nil
}

// wrapSyncConn applies the negotiated handshake result to a connection: it
// wraps conn in an authConn, installing directional frame keys when the
// connection authenticated and leaving an unauthenticated connection as a
// pass-through. Admission has already succeeded in performSyncHandshake.
// There is no pending frame to process before installation. A peer frame is
// handled only after the handshake has completed and the connection is wrapped.
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
