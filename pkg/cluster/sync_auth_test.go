package cluster

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSyncAuthProvider is a test SyncAuthProvider that returns a fixed PSK.
//
// #5078: it also carried a settable HeartbeatPeerAuthSeen, the cross-channel
// downgrade-guard signal. That left the interface once syncPeerAuthSeen went,
// and with it the only caller that ever passed authSeen=true — the deleted
// TestSyncAuthHandshakeDowngradeGuardRejects.
type fakeSyncAuthProvider struct {
	key     []byte
	node    int
	cluster int
}

func (f *fakeSyncAuthProvider) ControlLinkAuthKey() []byte { return f.key }

// #7163: the Noise prologue binds cluster/node identity, so the fake supplies
// it. fakeSyncAuthProviderNoIdentity below deliberately does NOT — it exists to
// prove the handshake refuses to run unbound rather than defaulting to zeros.
func (f *fakeSyncAuthProvider) NodeID() int    { return f.node }
func (f *fakeSyncAuthProvider) ClusterID() int { return f.cluster }

// fakeSyncAuthProviderNoIdentity is a provider that satisfies SyncAuthProvider
// but NOT SyncIdentityProvider.
type fakeSyncAuthProviderNoIdentity struct{ key []byte }

func (f *fakeSyncAuthProviderNoIdentity) ControlLinkAuthKey() []byte { return f.key }

type handshakeResult struct {
	mode syncAuthMode
	key  syncNoiseKeys
	err  error
}

func runHandshake(s *SessionSync, conn net.Conn, initiator bool) <-chan handshakeResult {
	ch := make(chan handshakeResult, 1)
	go func() {
		mode, key, err := s.performSyncHandshake(conn, initiator, 0)
		ch <- handshakeResult{mode: mode, key: key, err: err}
	}()
	return ch
}

func newAuthSync(t *testing.T, key []byte) *SessionSync {
	t.Helper()
	return newAuthSyncNode(t, key, 0)
}

// newAuthSyncNode builds a SessionSync whose provider reports the given node
// id. #7163: the two ends of a handshake must disagree about node id the way
// real nodes do (0 and 1), because the prologue binds ROLE-ORDERED ids and a
// pair that agreed on both would not exercise the ordering at all.
func newAuthSyncNode(t *testing.T, key []byte, node int) *SessionSync {
	t.Helper()
	s := NewSessionSync(":0", ":0", nil)
	if key != nil {
		s.SetAuthProvider(&fakeSyncAuthProvider{key: key, node: node, cluster: 22})
	}
	return s
}

// TestSyncAuthHandshakeBothKeyedAuthenticates verifies the happy path: two
// keyed peers with the SAME PSK complete Noise_NNpsk0, both negotiate
// authenticated, and derive complementary directional read/write keys before
// a sealed session frame round-trips. RED on revert: without the handshake
// there is no authentication and no directional frame key.
func TestSyncAuthHandshakeBothKeyedAuthenticates(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	// #7163: the two ends must be DIFFERENT nodes. The prologue binds
	// role-ordered node ids, so a fixture that gave both ends the same id would
	// build mismatched prologues and fail — which is the binding working, not a
	// bug. Real nodes are 0 and 1.
	a := newAuthSyncNode(t, key, 0)
	b := newAuthSyncNode(t, key, 1)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)  // dialer => Noise initiator
	bch := runHandshake(b, cb, false) // accepter => Noise responder

	ar := <-ach
	br := <-bch

	if ar.err != nil || br.err != nil {
		t.Fatalf("handshake errored: a=%v b=%v", ar.err, br.err)
	}
	if ar.mode != syncAuthAuthenticated || br.mode != syncAuthAuthenticated {
		t.Fatalf("expected both authenticated, got a=%d b=%d", ar.mode, br.mode)
	}
	// #7163: the two directions must derive INDEPENDENT keys, and A's write
	// direction must match B's read direction (and vice versa). Before this
	// change one key covered both, which is what let a node's own frame verify
	// when echoed back at it.
	if len(ar.key.writeKey) == 0 || len(ar.key.readKey) == 0 {
		t.Fatalf("frame keys must be non-empty: %+v", ar.key)
	}
	if bytes.Equal(ar.key.readKey, ar.key.writeKey) {
		t.Fatalf("THE VECTOR B FIX: the two directions derived the SAME key (%x). "+
			"A single key covering both directions is exactly what makes a node's own "+
			"syncMsgFence verify when reflected back to it on the same connection.",
			ar.key.readKey)
	}
	if bytes.Equal(br.key.readKey, br.key.writeKey) {
		t.Fatalf("responder derived one key for both directions: %x", br.key.readKey)
	}
	if !bytes.Equal(ar.key.writeKey, br.key.readKey) {
		t.Fatalf("A's write key must equal B's read key: %x vs %x", ar.key.writeKey, br.key.readKey)
	}
	if !bytes.Equal(ar.key.readKey, br.key.writeKey) {
		t.Fatalf("A's read key must equal B's write key: %x vs %x", ar.key.readKey, br.key.writeKey)
	}

	// A sealed session frame must round-trip across the directional pair.
	sender := &authConn{Conn: ca, readKey: ar.key.readKey, writeKey: ar.key.writeKey}
	receiver := &authConn{Conn: cb, readKey: br.key.readKey, writeKey: br.key.writeKey}
	frame := encodeRawMessage(syncMsgSessionV4, []byte("session-payload"))
	sealed := sender.sealFrame(frame)

	header := sealed[:syncHeaderSize]
	length := binary.LittleEndian.Uint32(header[8:12])
	payload := sealed[syncHeaderSize : syncHeaderSize+int(length)]
	trailer := sealed[syncHeaderSize+int(length):]
	if len(trailer) != syncAuthFrameTrailerSize {
		t.Fatalf("sealed frame trailer size = %d, want %d", len(trailer), syncAuthFrameTrailerSize)
	}
	if err := receiver.verifyFrame(header, payload, trailer); err != nil {
		t.Fatalf("authenticated frame failed to verify: %v", err)
	}
}

// TestSyncAuthHandshakeMismatchedKeyRejected verifies that a peer presenting a
// bad setup proof (a different PSK) is REJECTED — the connection is dropped and
// no session data is accepted. RED on revert: without the handshake the
// connection is accepted regardless of key.
func TestSyncAuthHandshakeMismatchedKeyRejected(t *testing.T) {
	a := newAuthSync(t, []byte("key-alpha"))
	b := newAuthSync(t, []byte("key-bravo-different"))

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)  // dialer => Noise initiator
	bch := runHandshake(b, cb, false) // accepter => Noise responder

	ar := <-ach
	br := <-bch

	if ar.err == nil {
		t.Fatalf("expected rejection on side A, got mode=%d key=%x", ar.mode, ar.key)
	}
	if br.err == nil {
		t.Fatalf("expected rejection on side B, got mode=%d key=%x", br.mode, br.key)
	}
	if ar.mode == syncAuthAuthenticated || br.mode == syncAuthAuthenticated {
		t.Fatalf("mismatched keys must not authenticate: a=%d b=%d", ar.mode, br.mode)
	}
}

// TestSyncAuthHandshakeKeyedNodeRejectsLegacyPeer is the #5078 fail-closed
// guard, and it REPLACES a test that asserted the opposite.
//
// The old TestSyncAuthHandshakeDualAcceptLegacyPeer required a keyed node to
// dual-accept a legacy/unkeyed peer "so the stream stays legacy-compatible (no
// brick)". That compatibility was an unauthenticated active bypass: the peer is
// admitted with no proof of the PSK, its first frame reaches cluster state, and
// it displaces the legitimate peer connection. A keyed node now rejects it.
//
// There is no migration window serving the legacy-compat need — an earlier
// draft of #5078 shipped one and it was removed; a rolling key rollout is
// handled by the procedure in pkg/cluster/README.md instead.
//
// RED on revert: make performSyncHandshake accept the peer frame instead of
// failing the Noise exchange and this test fails. The rejection must happen
// before any peer frame can reach cluster state; this is the production
// enforcement assertion.
//
// This is deliberately a live-handshake assertion, not a policy-matrix-only
// claim: changing an unused compatibility decision would not reach this path.
// The keyed-peer matrix was removed with that dead helper; the handshake tests
// here cover the behavior that actually runs.
func TestSyncAuthHandshakeKeyedNodeRejectsLegacyPeer(t *testing.T) {
	a := newAuthSync(t, []byte("psk"))

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)

	if _, _, err := readSyncFrameRaw(cb); err != nil {
		t.Fatalf("legacy peer failed to read HELLO: %v", err)
	}
	var clockBuf [8]byte
	binary.LittleEndian.PutUint64(clockBuf[:], 12345)
	if err := writeMsg(cb, syncMsgClockSync, clockBuf[:]); err != nil {
		t.Fatalf("legacy peer failed to send clock sync: %v", err)
	}

	ar := <-ach
	if ar.err == nil {
		t.Fatalf("a keyed node must REJECT an unauthenticated peer, got mode=%d", ar.mode)
	}

// Assert the REASON, not just that some error occurred. A nil frame key is
// the failure default of every error path in performSyncHandshake — a read
// timeout or a write failure also produces it — so `err != nil` plus
// `key == nil` would still pass if the connection died for an unrelated
// reason. Under Noise this peer sent a session frame where msg2 was required,
// so the diagnostic must identify the rejected Noise message rather than an
// unrelated I/O failure.
	if !strings.Contains(ar.err.Error(), "noise") {
		t.Fatalf("rejection must come from the Noise handshake and name the cause; "+
			"got %q, want it to mention the noise exchange", ar.err.Error())
	}
	if len(ar.key.readKey) != 0 || len(ar.key.writeKey) != 0 {
		t.Fatalf("a rejected handshake must yield no frame key")
	}
}

// legacySyncAuthVersion / legacySyncAuthNonceSize describe the RETIRED
// pre-#7163 HELLO used by TestNoiseHandshakeRejectsLegacyPeer7163. They are
// literals rather than references to live constants on purpose: this frozen
// legacy shape must not move with the current Noise handshake.
const (
	legacySyncAuthVersion   = 1
	legacySyncAuthNonceSize = 32
)

func TestSyncAuthDisabledNoHandshake(t *testing.T) {
	s := NewSessionSync(":0", ":0", nil) // no provider

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	// If performSyncHandshake performed any I/O it would block on the pipe; a
	// watchdog guarantees the test fails loudly instead of hanging.
	done := make(chan handshakeResult, 1)
	go func() {
		mode, key, err := s.performSyncHandshake(ca, true, 0)
		done <- handshakeResult{mode: mode, key: key, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("disabled handshake errored: %v", r.err)
		}
		if r.mode != syncAuthUnauthenticated || len(r.key.readKey) != 0 {
			t.Fatalf("disabled handshake must be an unauthenticated no-op, got %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("performSyncHandshake blocked with no key configured (must be a no-op)")
	}
	_ = cb
}

// TestSyncFrameSealVerifyRoundTripAndReplay unit-tests the per-frame seal /
// verify path: sequential frames verify and advance the watermark; a replayed
// (regressed sequence) frame, a tampered payload, and a wrong-key MAC are all
// rejected. RED on revert: sealFrame/verifyFrame do not exist.
func TestSyncFrameSealVerifyRoundTripAndReplay(t *testing.T) {
	key := []byte("per-connection-frame-key-abc")
	send := &authConn{readKey: key, writeKey: key}
	recv := &authConn{readKey: key, writeKey: key}

	split := func(sealed []byte) (header, payload, trailer []byte) {
		header = sealed[:syncHeaderSize]
		length := binary.LittleEndian.Uint32(header[8:12])
		payload = sealed[syncHeaderSize : syncHeaderSize+int(length)]
		trailer = sealed[syncHeaderSize+int(length):]
		return
	}

	frame1 := encodeRawMessage(syncMsgSessionV4, []byte("one"))
	frame2 := encodeRawMessage(syncMsgSessionV6, []byte("two"))
	sealed1 := send.sealFrame(frame1)
	sealed2 := send.sealFrame(frame2)

	// Sequence must be strictly increasing (1, then 2).
	if got := binary.LittleEndian.Uint64(sealed1[len(sealed1)-syncAuthFrameTrailerSize : len(sealed1)-syncAuthMACSize]); got != 1 {
		t.Fatalf("first sealed frame seq = %d, want 1", got)
	}

	h1, p1, tr1 := split(sealed1)
	if err := recv.verifyFrame(h1, p1, tr1); err != nil {
		t.Fatalf("frame1 must verify: %v", err)
	}
	h2, p2, tr2 := split(sealed2)
	if err := recv.verifyFrame(h2, p2, tr2); err != nil {
		t.Fatalf("frame2 must verify: %v", err)
	}
	// Replay frame1 (seq 1 <= watermark 2) must be rejected.
	if err := recv.verifyFrame(h1, p1, tr1); err != errSyncFrameReplay {
		t.Fatalf("replayed frame must be rejected as replay, got %v", err)
	}

	// Tampered payload must fail the HMAC on a fresh receiver.
	recv2 := &authConn{readKey: key, writeKey: key}
	tampered := append([]byte(nil), p2...)
	tampered[0] ^= 0xFF
	if err := recv2.verifyFrame(h2, tampered, tr2); err != errSyncFrameAuth {
		t.Fatalf("tampered payload must fail HMAC, got %v", err)
	}

	// Wrong key must fail the HMAC.
	recv3 := &authConn{readKey: []byte("wrong-key"), writeKey: []byte("wrong-key")}
	if err := recv3.verifyFrame(h1, p1, tr1); err != errSyncFrameAuth {
		t.Fatalf("wrong-key frame must fail HMAC, got %v", err)
	}
}


// #7163 SUPERSESSION NOTE. Four tests were removed from this file by the Noise
// conversion, and they are recorded here rather than deleted quietly, because
// three of them were the #5078/#7152 attack guards and a reader must be able to
// see where that coverage went:
//
//   - TestSyncAuthHandshakeKeyedHelloPeerStillAuthenticates asserted that a
//     peer speaking the legacy HELLO/PROOF exchange is ACCEPTED. That is the
//     opposite of the flag-day contract; it is replaced by
//     TestNoiseHandshakeRejectsLegacyPeer7163 below.
//   - TestSyncAuthProofBindsToNonce characterised syncAuthProof, which no
//     longer exists. Binding is now structural (prologue + transcript), and
//     TestNoiseHandshakeBindsIdentity7163 asserts the property that mattered:
//     two ends that disagree about identity cannot derive a common key.
//
//     That test ALSO pinned `syncDeriveFrameKey(key, n1, n2)` ==
//     `syncDeriveFrameKey(key, n2, n1)` — "frame-key derivation must be
//     order-independent (both peers derive equal)". That assertion is not
//     relocated, it is INVERTED, and saying so matters: order-independence is
//     not a property this fix preserves elsewhere, it IS the vector-B defect.
//     A key that does not depend on which end derived it is a key both
//     directions share, which is what let a node's own syncMsgFence verify
//     when echoed back at it. The replacement assertions are its negation —
//     TestSyncAuthHandshakeBothKeyedAuthenticates and
//     TestInPlaceUpgradeInstallsDirectionalKeys7163 both require the two
//     directions to hold DIFFERENT keys. A reader who greps for the old
//     assertion and finds nothing should not conclude the coverage was
//     dropped.
//   - TestSyncAuthHandshakeRejectsReflectedNonce_5078 and
//     TestSyncAuthHandshakeRejectsZeroNonce_5078 guarded vector A by rejecting
//     a reflected/degenerate NONCE. There are no nonces to reflect any more —
//     the initiator and responder derive from a Diffie-Hellman exchange mixed
//     with the PSK — so the guard is replaced by
//     TestNoiseHandshakeRejectsReflectedMessage7163, which reflects the actual
//     handshake message and asserts it is refused.
//
// Deleting the three attack guards without replacements would have decommissioned
// the vector A coverage while the suite stayed green.

// TestNoiseHandshakeRejectsLegacyPeer7163 pins the FLAG DAY. A pre-#7163 peer
// sends the legacy HELLO, which is not a valid Noise message, and must be
// refused rather than silently downgraded to an unauthenticated stream.
func TestNoiseHandshakeRejectsLegacyPeer7163(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	a := newAuthSyncNode(t, key, 0)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)

	// Consume our msg1 and answer with a legacy-shaped HELLO.
	go func() {
		_, _, _ = readSyncFrameRaw(cb)
		legacy := make([]byte, 2+legacySyncAuthNonceSize)
		legacy[0], legacy[1] = 1, 1
		_ = writeMsg(cb, syncMsgAuthHello, legacy)
	}()

	ar := <-ach
	if ar.err == nil {
		t.Fatal("a legacy peer was ACCEPTED. This is a flag day: the old handshake " +
			"must not interoperate, or an operator gets a silently unauthenticated " +
			"fabric instead of a refused one.")
	}
	if ar.mode == syncAuthAuthenticated {
		t.Fatalf("legacy peer negotiated authenticated mode: %d", ar.mode)
	}
}

// TestNoiseHandshakeRejectsReflectedMessage7163 replaces the vector A nonce
// guards. The attacker reflects the initiator's own handshake message back at
// it — the modern form of the same attack — and it must not authenticate.
func TestNoiseHandshakeRejectsReflectedMessage7163(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	a := newAuthSyncNode(t, key, 0)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ach := runHandshake(a, ca, true)

	go func() {
		_, msg1, err := readSyncFrameRaw(cb)
		if err != nil {
			return
		}
		// Echo msg1 straight back as if it were msg2.
		_ = writeMsg(cb, syncMsgAuthProof, msg1)
	}()

	ar := <-ach
	if ar.err == nil {
		t.Fatal("a REFLECTED handshake message authenticated. The initiator accepted " +
			"its own message as the responder's, which is vector A in its modern form.")
	}
}

// TestNoiseHandshakeBindsIdentity7163 binds the CONNECT path's prologue field
// by field.
//
// The prologue is never PARSED — both ends construct it independently and the
// handshake hash compares them — so a field that stopped being mixed in would
// not surface as a decode error. It would surface as nothing at all: both ends
// would drop it together and the handshake would still succeed, with the
// binding silently absent.
//
// The FIRST row is the matching pair and must SUCCEED. Without it every
// remaining row is satisfied by a handshake that never completes, which is the
// failure this test would otherwise be blind to — an earlier revision varied
// only the cluster id and had no positive control of its own.
func TestNoiseHandshakeBindsIdentity7163(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	const cluster = 22
	for _, tc := range []struct {
		name        string
		bNode       int
		bCluster    int
		bFabric     int
		wantSuccess bool
	}{
		{"matching identity", 1, cluster, 0, true},
		{"different cluster id", 1, cluster + 77, 0, false},
		{"different node id", 0, cluster, 0, false},
		{"different fabric index", 1, cluster, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuthSyncNode(t, key, 0)
			b := NewSessionSync(":0", ":0", nil)
			b.SetAuthProvider(&fakeSyncAuthProvider{key: key, node: tc.bNode, cluster: tc.bCluster})

			ca, cb := net.Pipe()
			defer ca.Close()
			defer cb.Close()

			ach := runHandshake(a, ca, true)
			bch := runHandshakeFabric(b, cb, false, tc.bFabric)
			ar, br := <-ach, <-bch

			ok := ar.err == nil && br.err == nil
			if ok != tc.wantSuccess {
				if tc.wantSuccess {
					t.Fatalf("the MATCHING pair failed the handshake (a=%v b=%v). Every "+
						"refusal below is then satisfied by a handshake that never "+
						"completes, and none of the bindings is actually pinned.",
						ar.err, br.err)
				}
				t.Fatal("two ends that DISAGREE about this field completed the handshake, " +
					"so the field is not mixed into the prologue. It would not surface as " +
					"a decode error either: both ends would drop it together and the " +
					"handshake would still succeed with the binding silently absent.")
			}
		})
	}
}

// runHandshakeFabric is runHandshake with an explicit fabric index, so the
// table above can make the two ends disagree about which fabric they are on —
// the one prologue field runHandshake hard-codes to 0.
func runHandshakeFabric(s *SessionSync, conn net.Conn, initiator bool, fabricIdx int) <-chan handshakeResult {
	ch := make(chan handshakeResult, 1)
	go func() {
		mode, key, err := s.performSyncHandshake(conn, initiator, fabricIdx)
		ch <- handshakeResult{mode: mode, key: key, err: err}
	}()
	return ch
}

// TestNoiseHandshakeRefusesWithoutIdentity7163 pins the FAIL-CLOSED path. A
// provider that cannot answer for identity must stop the handshake, not default
// to zeros — a zero prologue is well-formed, binds nothing, and would be
// identical on both nodes, so the handshake would SUCCEED with the identity
// binding silently absent. That is the "silently does not run" shape this whole
// issue exists to remove, and it must not be re-introduced by the fix.
func TestNoiseHandshakeRefusesWithoutIdentity7163(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	s := NewSessionSync(":0", ":0", nil)
	s.SetAuthProvider(&fakeSyncAuthProviderNoIdentity{key: key})

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	_, _, err := s.performSyncHandshake(ca, true, 0)
	if err == nil {
		t.Fatal("a provider with no identity produced a handshake. It must refuse: a " +
			"defaulted zero prologue binds nothing while looking perfectly healthy.")
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("error should name the missing identity, got: %v", err)
	}
}
