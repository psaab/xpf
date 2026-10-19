package cluster

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/flynn/noise"
)

// Noise-based session-sync handshake (#7163, vector B of #5078).
//
// THE DEFECT THIS REPLACES. `syncAuthProof(key, challenge)` was
// `HMAC(key, tag ‖ challenge)`: no initiator/responder role, no node or
// endpoint identity, and no transcript. `syncDeriveFrameKey` then canonically
// SORTED the two nonces, so both directions derived ONE key and shared one
// counter space, and `wrapSyncConn` wrote those same bytes into readKey and
// writeKey alike.
//
// Two consequences, and the second is why this is not a narrow fix:
//
//   - THE TWO-CONNECTION ORACLE. An attacker with no PSK opens a second keyed
//     connection and relays a proof computed over connection α's nonce onto
//     connection β. The nonces differ on each connection, so #7152's
//     equal-nonce rejection never fires. Both nodes share one PSK, so the
//     oracle can be the PEER NODE ITSELF — no per-node nonce bookkeeping can
//     observe it.
//   - SELF-FENCING. Because readKey == writeKey, a frame the victim SENT
//     verifies when echoed straight back on the same connection, and the
//     anti-replay counter cannot see it (`verifyFrame` compares against that
//     connection's RECEIVE counter, which is independent of its send counter).
//     The worst reflectable frame is `syncMsgFence`: empty payload, and on
//     receipt the victim disables all of its own redundancy groups.
//
// WHY A LIBRARY RATHER THAN ANOTHER HAND-ROLLED CONSTRUCTION. Composing this
// in-house produced three separate findings — #5078 (reflection), #7152
// (equal-nonce), and this issue's vector B. Role binding, identity binding and
// transcript binding are what a standard construction provides BY DEFINITION,
// and they are exactly the three things the old proof omitted. This is the
// appliance's first third-party crypto dependency, accepted deliberately.
//
// WHY Noise_NNpsk0 SPECIFICALLY. The existing trust model is a config-derived
// shared PSK (`Manager.ControlLinkAuthKey`) with no static-keypair
// infrastructure, no CA, no certificate lifecycle and no trust-anchor
// distribution. A psk0-family pattern authenticates from that PSK directly.
// Introducing static keys would import exactly the lifecycle question that
// ruled out TLS, and it does not become free by being called Noise.
//
// WHAT EACH BINDING COMES FROM, so a reader can check the claim rather than
// take it:
//
//   - ROLE: initiator and responder are structural in the pattern. The TCP
//     dialer is the initiator; the accepter is the responder. Not a field we
//     add and could forget.
//   - TRANSCRIPT: the handshake hash covers every message AND the prologue.
//   - IDENTITY: protocol version, cluster id, ROLE-ORDERED node ids and the
//     fabric index go in the prologue, so they are inside that hash. Two nodes
//     that disagree on any of them derive different keys and the handshake
//     fails — it is not a field either side can assert unilaterally.
//   - DIRECTION: `Split()` returns two CipherStates, one per direction. This
//     is the specific replacement for the canonical nonce sort.
const (
	// syncNoiseVersion is the version byte inside the prologue. It is NOT the
	// session-sync wire version (that is SessionSyncWireVersion, bumped
	// separately); this one binds the handshake construction itself into the
	// transcript so two builds that disagree about the handshake cannot derive
	// a common key even if every other input matches.
	syncNoiseVersion = 1

	// syncNoiseKeyLen is the directional frame-key length. Noise CipherStates
	// hold 32-byte keys.
	syncNoiseKeyLen = 32

	// syncNoisePhaseConnect and syncNoisePhaseUpgrade separate the two places
	// a Noise_NNpsk0 exchange runs: the connection-setup handshake
	// (performSyncHandshake) and the #6628 in-place upgrade of an ALREADY
	// ESTABLISHED connection (sync_auth_upgrade.go).
	//
	// They must not share a transcript, and the reason is concrete rather than
	// hygienic. Both run under the same PSK, and a connect msg1 travels in
	// cleartext on a fresh TCP connection where anyone on the fabric can read
	// it. Without this byte the two prologues are identical, so that captured
	// msg1 is ALSO a well-formed upgrade Hello: replay it into an established
	// unauthenticated stream and the responder answers with a msg2 and switches
	// its write direction to a key derived from an ephemeral nobody holds — not
	// the attacker (no PSK) and not the legitimate initiator (it never sent that
	// msg1). The peer can then no longer read a single frame and the connection
	// DROPS, which is the one property the in-place upgrade promises it will
	// never do. One byte in the prologue makes the replayed message fail its
	// AEAD tag instead.
	syncNoisePhaseConnect = 1
	syncNoisePhaseUpgrade = 2
)

// syncNoiseCipherSuite is the negotiated suite. Fixed, not negotiated: this is
// a closed two-node system upgrading as a flag day, so there is no peer to
// negotiate down to and no reason to carry agility that only widens the attack
// surface. 25519 + ChaChaPoly + SHA256 needs no AES-NI, which matters because
// the appliance runs on whatever the operator racked.
var syncNoiseCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// SyncIdentityProvider supplies the cluster/node identity bound into the
// handshake prologue (#7163).
//
// It is a SEPARATE interface from SyncAuthProvider rather than an extension of
// it because the failure modes differ and must not be conflated: a missing key
// is a supported state (an unkeyed cluster), whereas a provider that cannot
// answer for identity is a wiring bug. See syncNoiseIdentity for what each does.
type SyncIdentityProvider interface {
	NodeID() int
	ClusterID() int
}

// syncNoiseIdentity resolves the local identity for the prologue.
//
// IT FAILS CLOSED, and that is the whole point of it being a separate
// function. The tempting shape is to default a missing provider to zeros and
// carry on; that would produce a prologue that is perfectly well-formed and
// binds NOTHING, on both nodes, so the handshake would succeed and the
// identity binding would be silently absent. A gate that silently does not run
// is indistinguishable from a healthy one — which is the exact class of defect
// this issue exists to close, so it must not be re-introduced by the fix.
func (s *SessionSync) syncNoiseIdentity() (clusterID, nodeID int, err error) {
	box := s.authProvider.Load()
	if box == nil || box.p == nil {
		return 0, 0, errors.New("cluster sync: no auth provider wired for the handshake identity")
	}
	ident, ok := box.p.(SyncIdentityProvider)
	if !ok {
		return 0, 0, fmt.Errorf(
			"cluster sync: auth provider %T does not supply cluster/node identity; "+
				"the #7163 handshake cannot bind identity and refuses to run unbound", box.p)
	}
	cluster, node := ident.ClusterID(), ident.NodeID()
	// #9915 F-043: the prologue derives the peer as 1-local, so any node id
	// outside {0,1} makes the two ends derive DIFFERENT prologues and the
	// msg1 AEAD fails permanently on both fabrics while the cluster looks
	// alive. Fail LOUD naming the identity instead of handshaking unbound.
	if node != 0 && node != 1 {
		return 0, 0, fmt.Errorf(
			"cluster sync: local node id %d outside {0,1} (cluster %d); "+
				"the keyed handshake cannot bind identity and refuses to run — "+
				"check /etc/xpf/node-id", node, cluster)
	}
	// #9915 F-043 review: the prologue binds the cluster id verbatim, so a
	// corrupt cluster id diverges the two ends' prologues exactly like a bad
	// node id — silent msg1 AEAD failure on both fabrics. The schema bounds it
	// to 0..255 (one RETH MAC byte); anything else is corruption, failed loud.
	if cluster < 0 || cluster > 255 {
		return 0, 0, fmt.Errorf(
			"cluster sync: local cluster id %d outside 0..255 (node %d); "+
				"the keyed handshake cannot bind identity and refuses to run — "+
				"check chassis cluster cluster-id", cluster, node)
	}
	return cluster, node, nil
}

// syncNoisePrologue builds the transcript-bound identity blob.
//
// ROLE-ORDERED, not sorted. The old frame-key derivation sorted its two inputs
// canonically, which is exactly what made the key undirected and the oracle
// work. Here the initiator's node id always precedes the responder's, so the
// two sides agree on the bytes only when they also agree on WHO DIALED — a
// disagreement about role changes the prologue, changes the handshake hash and
// fails the handshake, rather than quietly producing a shared key.
//
// The PHASE byte separates the connect handshake from the #6628 in-place
// upgrade; see syncNoisePhaseConnect for the replay it stops.
//
// Fixed width and fixed order: every field is a fixed-size big-endian integer,
// so the encoding is unambiguous and no length-prefix parsing is involved. The
// prologue is never parsed by anyone — both sides construct it independently
// and the hash compares them — so an ambiguous encoding would surface as an
// unexplained handshake failure rather than as a confusion attack.
func syncNoisePrologue(phase byte, clusterID, initiatorNode, responderNode, fabricIdx int) []byte {
	buf := make([]byte, 0, 2+4*4)
	buf = append(buf, syncNoiseVersion, phase)
	var scratch [4]byte
	for _, v := range []int{clusterID, initiatorNode, responderNode, fabricIdx} {
		binary.BigEndian.PutUint32(scratch[:], uint32(v))
		buf = append(buf, scratch[:]...)
	}
	return buf
}

// syncNoisePSK maps the config-derived control-link key onto the fixed-width
// PSK Noise requires.
//
// NOT COSMETIC, and not a detail the caller can skip: flynn/noise rejects
// anything but 32 bytes outright ("specification mandates 256-bit preshared
// keys"), while `ControlLinkAuthKey` is an operator-authored string of
// arbitrary length. Passing it through unchanged makes EVERY real cluster fail
// the handshake — which is how this was found, by the suite rather than by
// reading.
//
// SHA-256 rather than a bare truncate-or-pad: truncation would silently
// collapse two distinct keys that share a 32-byte prefix, and zero-padding a
// short key would leave most of the PSK constant. Both are the shape of
// weakness this issue exists to stop shipping.
//
// The label is mixed in so this derivation cannot collide with any other use of
// the same config key elsewhere in the tree — the heartbeat authenticates off
// the same secret, and two protocols sharing one derived key is its own defect.
func syncNoisePSK(key []byte) []byte {
	h := sha256.New()
	h.Write([]byte("xpf-sync-noise-psk-v1"))
	h.Write(key)
	return h.Sum(nil)
}

// syncNoiseKeys is the result of a completed handshake: two INDEPENDENT
// directional frame keys.
type syncNoiseKeys struct {
	readKey  []byte
	writeKey []byte
}

// performNoiseHandshake runs Noise_NNpsk0 over conn and returns the two
// directional frame keys.
//
// initiator selects the role, and the caller derives it from the transport:
// the side that dialed is the initiator, the side that accepted is the
// responder. That is the only role source that cannot be asserted by the peer.
//
// The peer's node id is NOT carried on the wire. Both sides construct the
// prologue from what they already know — a two-node cluster, so the peer's id
// is `1 - localNode` — and the handshake hash is what checks that they agree.
// Sending it would make it an attacker-chosen input to our own identity
// binding, which is precisely the mistake the old proof made with its nonce.
func (s *SessionSync) performNoiseHandshake(conn net.Conn, key []byte, initiator bool, fabricIdx int) (syncNoiseKeysWithPSK, error) {
	if !initiator {
		// The connect responder is ring-aware since #14703; reaching this
		// branch with initiator=false would silently narrow verification to
		// one key, so refuse rather than guess.
		return syncNoiseKeysWithPSK{}, fmt.Errorf("cluster sync: performNoiseHandshake responder path is ring-aware; use performNoiseResponderHandshake")
	}
	hs, err := s.newSyncNoiseState(key, true, syncNoisePhaseConnect, fabricIdx)
	if err != nil {
		return syncNoiseKeysWithPSK{}, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return syncNoiseKeysWithPSK{}, fmt.Errorf("cluster sync: noise msg1: %w", err)
	}
	if err := writeMsg(conn, syncMsgAuthHello, msg1); err != nil {
		return syncNoiseKeysWithPSK{}, err
	}
	typ, payload, err := readSyncFrameRaw(conn)
	if err != nil {
		return syncNoiseKeysWithPSK{}, err
	}
	if typ != syncMsgAuthProof {
		return syncNoiseKeysWithPSK{}, fmt.Errorf("cluster sync: expected noise msg2, got frame type %d", typ)
	}
	_, cs1, cs2, err := hs.ReadMessage(nil, payload)
	if err != nil {
		// The single most important error in this file. A peer that does
		// not hold the PSK cannot produce a msg2 that authenticates
		// against our handshake hash, so this is where a PSK-less
		// attacker is refused -- by the construction, not by a comparison
		// we remembered to write.
		return syncNoiseKeysWithPSK{}, fmt.Errorf("cluster sync: noise msg2 rejected: %w", err)
	}
	if cs1 == nil || cs2 == nil {
		return syncNoiseKeysWithPSK{}, errors.New("cluster sync: noise handshake produced no cipher states")
	}
	keys := syncNoiseSplitKeys(true, cs1, cs2)
	// #15140: msg2 verification proves the RESPONDER holds the PSK, but
	// the responder cannot yet distinguish this live initiator from a
	// replay of a captured msg1. Send the key confirmation sealed under
	// the i2r key (our writeKey) over this handshake's channel binding:
	// only the holder of the msg1 ephemeral private key can derive it.
	confirm := syncConnectConfirmMAC(keys.writeKey, hs.ChannelBinding())
	if err := writeMsg(conn, syncMsgAuthConfirm, confirm); err != nil {
		return syncNoiseKeysWithPSK{}, err
	}
	return syncNoiseKeysWithPSK{
		syncNoiseKeys: keys,
		matchedPSK:    append([]byte(nil), key...),
	}, nil
}

// performNoiseResponderHandshake is the connect responder (#14703). It reads
// msg1 ONCE off the wire, then tries each accepted key in ring order against
// a FRESH handshake state: Noise consumes msg1, so a failed ReadMessage
// cannot be retried on the same state, and re-reading the wire would let a
// peer (or an attacker) substitute a different msg1 between attempts. The
// first key whose ReadMessage succeeds is the matched key; msg2 is built and
// written only for that key, so the wire carries exactly one msg2 and a peer
// holding no ring member is rejected after the ring is exhausted — still
// fail-closed, just widened from one key to the accepted set the heartbeat
// and fabric gRPC listener already verify against.
// syncNoisePending is the #15140 PENDING responder result: msg1 verified
// under a ring key and msg2 written, but the initiator has NOT yet proven
// it holds the ephemeral private key behind msg1. Keys are derived but
// must not be installed, recorded, or transmitted under until
// awaitInitiatorConfirm verifies the key confirmation. A replayed msg1
// reaches exactly this state and no further.
type syncNoisePending struct {
	keys    syncNoiseKeys
	matched []byte
	binding []byte
}

// syncConnectConfirmMAC is the #15140 key confirmation: HMAC-SHA256
// under the initiator->responder frame key over the connect-confirm tag
// and the Noise channel binding. Only a peer that completed Split()
// with the initiator ephemeral private key can produce it.
func syncConnectConfirmMAC(i2rKey, binding []byte) []byte {
	mac := hmac.New(sha256.New, i2rKey)
	mac.Write(syncAuthConfirmTag)
	mac.Write(binding)
	return mac.Sum(nil)
}

func (s *SessionSync) performNoiseResponderHandshake(conn net.Conn, accepted [][]byte, fabricIdx int) (syncNoisePending, error) {
	typ, payload, err := readSyncFrameRaw(conn)
	if err != nil {
		return syncNoisePending{}, err
	}
	if typ != syncMsgAuthHello {
		return syncNoisePending{}, fmt.Errorf("cluster sync: expected noise msg1, got frame type %d", typ)
	}
	var lastErr error
	for _, candidate := range accepted {
		if len(candidate) == 0 {
			continue
		}
		hs, err := s.newSyncNoiseState(candidate, false, syncNoisePhaseConnect, fabricIdx)
		if err != nil {
			return syncNoisePending{}, err
		}
		if _, _, _, err := hs.ReadMessage(nil, payload); err != nil {
			lastErr = err
			continue
		}
		msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return syncNoisePending{}, fmt.Errorf("cluster sync: noise msg2: %w", err)
		}
		if cs1 == nil || cs2 == nil {
			return syncNoisePending{}, errors.New("cluster sync: noise handshake produced no cipher states")
		}
		keys := syncNoiseSplitKeys(false, cs1, cs2)
		binding := append([]byte(nil), hs.ChannelBinding()...)
		if err := writeMsg(conn, syncMsgAuthProof, msg2); err != nil {
			return syncNoisePending{}, err
		}
		// PENDING (#15140): do NOT authenticate here. A captured msg1
		// re-verifies and reaches this line with no PSK; only the
		// initiator's key confirmation promotes the connection.
		return syncNoisePending{
			keys:    keys,
			matched: append([]byte(nil), candidate...),
			binding: binding,
		}, nil
	}
	if lastErr != nil {
		return syncNoisePending{}, fmt.Errorf("cluster sync: noise msg1 rejected: %w", lastErr)
	}
	return syncNoisePending{}, errors.New("cluster sync: noise msg1 rejected: no accepted key")
}

// awaitInitiatorConfirm is the #15140 responder gate: read exactly one
// syncMsgAuthConfirm frame and verify it against the pending keys.
// Silence, a wrong frame type, or a bad MAC all fail closed.
func (s *SessionSync) awaitInitiatorConfirm(conn net.Conn, pending syncNoisePending) (syncNoiseKeysWithPSK, error) {
	typ, payload, err := readSyncFrameRaw(conn)
	if err != nil {
		return syncNoiseKeysWithPSK{}, fmt.Errorf("cluster sync: noise key confirmation not received: %w", err)
	}
	if typ != syncMsgAuthConfirm {
		return syncNoiseKeysWithPSK{}, fmt.Errorf("cluster sync: expected noise key confirmation, got frame type %d", typ)
	}
	want := syncConnectConfirmMAC(pending.keys.readKey, pending.binding)
	if len(payload) != len(want) || !hmac.Equal(payload, want) {
		return syncNoiseKeysWithPSK{}, errors.New("cluster sync: noise key confirmation rejected")
	}
	return syncNoiseKeysWithPSK{
		syncNoiseKeys: pending.keys,
		matchedPSK:    pending.matched,
	}, nil
}

// newSyncNoiseState builds the Noise_NNpsk0 handshake state both exchanges run
// on: the connection-setup handshake and the #6628 in-place upgrade.
//
// It is ONE function on purpose. The prologue is where every identity binding
// lives, so two copies of this construction would be two places for a binding
// to be dropped from — and a dropped binding is invisible, because both ends
// drop it together and the handshake still succeeds. The phase byte is what
// keeps the two exchanges' transcripts apart while the code stays single.
func (s *SessionSync) newSyncNoiseState(key []byte, initiator bool, phase byte, fabricIdx int) (*noise.HandshakeState, error) {
	clusterID, localNode, err := s.syncNoiseIdentity()
	if err != nil {
		return nil, err
	}
	peerNode := 1 - localNode

	initiatorNode, responderNode := localNode, peerNode
	if !initiator {
		initiatorNode, responderNode = peerNode, localNode
	}
	prologue := syncNoisePrologue(phase, clusterID, initiatorNode, responderNode, fabricIdx)

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           syncNoiseCipherSuite,
		Pattern:               noise.HandshakeNN,
		Initiator:             initiator,
		Prologue:              prologue,
		PresharedKey:          syncNoisePSK(key),
		PresharedKeyPlacement: 0, // psk0: the PSK is mixed in before anything else.
		Random:                rand.Reader,
	})
	if err != nil {
		return nil, fmt.Errorf("cluster sync: noise handshake init: %w", err)
	}
	return hs, nil
}

// syncNoiseSplitKeys maps the two CipherStates Split() returns onto THIS side's
// read and write directions.
//
// flynn/noise returns them in a fixed order — (initiator→responder,
// responder→initiator) — for both peers, so the two sides read the same pair
// and disagree only about which one they write with. That asymmetry is the
// whole point: it is the specific replacement for the pre-#7163 canonical nonce
// sort, which handed both directions the same bytes and let a node's own frame
// verify when echoed back at it.
func syncNoiseSplitKeys(initiator bool, csInitiatorToResponder, csResponderToInitiator *noise.CipherState) syncNoiseKeys {
	// UnsafeKey() is the library's own name for "give me the raw key", and the
	// warning it encodes is real, so here is why it is the right call here.
	//
	// The frame layer this feeds is NOT being replaced in this change: frames
	// keep their HMAC trailer, their per-direction anti-replay counters, and
	// the #6628 mid-stream switch-point discipline. Replacing the frame FORMAT
	// as well would put two independent wire changes in one flag day, and the
	// defect being closed is the KEY (undirected, unbound), not the seal. So
	// the two Noise directional keys are lifted out and handed to the existing
	// sealer, which is what makes this a key fix rather than a rewrite.
	i2r := csInitiatorToResponder.UnsafeKey()
	r2i := csResponderToInitiator.UnsafeKey()

	keys := syncNoiseKeys{}
	if initiator {
		keys.writeKey = append([]byte(nil), i2r[:]...)
		keys.readKey = append([]byte(nil), r2i[:]...)
	} else {
		keys.writeKey = append([]byte(nil), r2i[:]...)
		keys.readKey = append([]byte(nil), i2r[:]...)
	}
	return keys
}
