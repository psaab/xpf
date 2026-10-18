package cluster

import (
	"bytes"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ringFakeProvider models one node in a #6630 rotation for #14703 tests:
// it SIGNS with key and ACCEPTS [key, alt...]. It satisfies both
// SyncAuthProvider and the optional syncAcceptedKeysProvider probe, the
// same shape *Manager presents in production.
type ringFakeProvider struct {
	key     []byte
	alt     [][]byte
	node    int
	cluster int
}

func (f *ringFakeProvider) ControlLinkAuthKey() []byte { return f.key }

func (f *ringFakeProvider) ControlLinkAcceptedKeys() [][]byte {
	out := make([][]byte, 0, 1+len(f.alt))
	if len(f.key) > 0 {
		out = append(out, f.key)
	}
	for _, k := range f.alt {
		if len(k) > 0 {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (f *ringFakeProvider) NodeID() int    { return f.node }
func (f *ringFakeProvider) ClusterID() int { return f.cluster }

func newRingSyncNode(key []byte, alt [][]byte, node int) *SessionSync {
	s := NewSessionSync(":0", ":0", nil)
	s.SetAuthProvider(&ringFakeProvider{key: key, alt: alt, node: node, cluster: 22})
	return s
}

var (
	rot14703KeyA = []byte("rotation-key-A-14703")
	rot14703KeyB = []byte("rotation-key-B-14703")
	rot14703KeyC = []byte("rotation-key-C-unrelated")
)

// TestSessionSyncHitlessKeyRotationAcceptRing is the decisive #14703
// regression named by the issue. It drives the asymmetric #6630 step-3
// state — node0 signs B / accepts [B,A], node1 signs A / accepts [A,B] —
// through (1) a FRESH performSyncHandshake in both dial directions and
// (2) the B-sealed in-place upgrade Hello, asserting the responder stamps
// authPSK with the MATCHED key.
//
// FAIL-ON-REVERT: revert SyncAuthProvider to exposing only
// ControlLinkAuthKey (drop authAcceptedKeys and the ring responder paths)
// and every sub-check below reds: the B-initiator handshake is rejected
// with "noise msg1 rejected", the upgrade Hello is left unanswered, and
// wrapSyncConn stamps the responder's signing key instead of B.
func TestSessionSyncHitlessKeyRotationAcceptRing(t *testing.T) {
	// (1a) Fresh connection: node0 (signs B, accepts [B,A]) INITIATES to
	// node1 (signs A, accepts [A,B]). The responder must open msg1 under B.
	t.Run("fresh handshake B-initiator to A-responder", func(t *testing.T) {
		init := newRingSyncNode(rot14703KeyB, [][]byte{rot14703KeyA}, 0)
		resp := newRingSyncNode(rot14703KeyA, [][]byte{rot14703KeyB}, 1)

		ca, cb := net.Pipe()
		defer ca.Close()
		defer cb.Close()
		ach := runHandshake(init, ca, true)
		bch := runHandshake(resp, cb, false)
		ar, br := <-ach, <-bch
		if ar.err != nil || br.err != nil {
			t.Fatalf("step-3 fresh handshake must complete in the B->A direction: initiator=%v responder=%v", ar.err, br.err)
		}
		if ar.mode != syncAuthAuthenticated || br.mode != syncAuthAuthenticated {
			t.Fatalf("both ends must authenticate, got initiator=%d responder=%d", ar.mode, br.mode)
		}
		if !bytes.Equal(ar.key.writeKey, br.key.readKey) || !bytes.Equal(ar.key.readKey, br.key.writeKey) {
			t.Fatal("directional keys must agree across a ring-matched handshake")
		}
		// The responder matched under B, not under its own signing key A.
		if !bytes.Equal(br.key.matchedPSK, rot14703KeyB) {
			t.Fatalf("responder matchedPSK = %q, want the matched ring key B", br.key.matchedPSK)
		}
		if !bytes.Equal(ar.key.matchedPSK, rot14703KeyB) {
			t.Fatalf("initiator matchedPSK = %q, want its signing key B", ar.key.matchedPSK)
		}
		// wrapSyncConn must stamp the matched key on the responder.
		wrapped := resp.wrapSyncConn(0, cb, br.mode, br.key)
		if !bytes.Equal(wrapped.authPSK, rot14703KeyB) {
			t.Fatalf("wrapSyncConn authPSK = %q, want matched B (stamping the signing key A hides the rotation the connection owes)", wrapped.authPSK)
		}
	})

	// (1b) Fresh connection, reverse dial direction: node1 (signs A)
	// INITIATES to node0 (signs B, accepts [B,A]). Node0 must open the
	// A-sealed msg1 under its additional key.
	t.Run("fresh handshake A-initiator to B-responder", func(t *testing.T) {
		init := newRingSyncNode(rot14703KeyA, [][]byte{rot14703KeyB}, 1)
		resp := newRingSyncNode(rot14703KeyB, [][]byte{rot14703KeyA}, 0)

		ca, cb := net.Pipe()
		defer ca.Close()
		defer cb.Close()
		ach := runHandshake(init, ca, true)
		bch := runHandshake(resp, cb, false)
		ar, br := <-ach, <-bch
		if ar.err != nil || br.err != nil {
			t.Fatalf("step-3 fresh handshake must complete in the A->B direction: initiator=%v responder=%v", ar.err, br.err)
		}
		if ar.mode != syncAuthAuthenticated || br.mode != syncAuthAuthenticated {
			t.Fatalf("both ends must authenticate, got initiator=%d responder=%d", ar.mode, br.mode)
		}
		if !bytes.Equal(br.key.matchedPSK, rot14703KeyA) {
			t.Fatalf("responder matchedPSK = %q, want the matched ring key A", br.key.matchedPSK)
		}
		wrapped := resp.wrapSyncConn(0, cb, br.mode, br.key)
		if !bytes.Equal(wrapped.authPSK, rot14703KeyA) {
			t.Fatalf("wrapSyncConn authPSK = %q, want matched A", wrapped.authPSK)
		}
	})

	// (2) In-place upgrade: an established unauthenticated connection, then
	// node0 rotates to signing B (accept [B,A]) while node1 still signs A
	// (accept [A,B]). Node0 is the upgrade initiator by node id; its
	// B-sealed Hello must be accepted by node1 through the ring, and both
	// ends must record B as the round's key.
	t.Run("B-sealed upgrade hello accepted via the ring", func(t *testing.T) {
		const pskA = "rotation-key-A-14703"
		const pskB = "rotation-key-B-14703"
		a := newUpgEnd(t, pskA, 0)
		b := newUpgEnd(t, pskA, 1)

		// Rotate asymmetrically BEFORE the upgrade starts.
		a.s.SetAuthProvider(&ringFakeProvider{key: []byte(pskB), alt: [][]byte{[]byte(pskA)}, node: 0, cluster: upgClusterID})
		b.s.SetAuthProvider(&ringFakeProvider{key: []byte(pskA), alt: [][]byte{[]byte(pskB)}, node: 1, cluster: upgClusterID})

		if a.ac.readAuthed() || a.ac.writeAuthed() || b.ac.readAuthed() || b.ac.writeAuthed() {
			t.Fatal("fixture must start unauthenticated")
		}
		assertFrameSequence(t, runUpgrade(t, a, b), upgradeFrameSequence)
		if !a.ac.authed() || !b.ac.authed() {
			t.Fatalf("upgrade under the ring must authenticate both ends (a read=%v write=%v, b read=%v write=%v)",
				a.ac.readAuthed(), a.ac.writeAuthed(), b.ac.readAuthed(), b.ac.writeAuthed())
		}
		if !bytes.Equal(a.ac.authPSK, []byte(pskB)) {
			t.Fatalf("initiator authPSK = %q, want B (the key this round authenticated under)", a.ac.authPSK)
		}
		if !bytes.Equal(b.ac.authPSK, []byte(pskB)) {
			t.Fatalf("responder authPSK = %q, want matched B — stamping its signing key A would make the reconciler believe the connection is current on the wrong key", b.ac.authPSK)
		}
		if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
			t.Fatal("both ends must agree on both directional keys after a ring-matched upgrade")
		}
	})

	// Control: a peer holding NO ring member is still rejected, in both the
	// connect handshake and (implicitly, by the same responder code) the
	// upgrade. The ring widens acceptance to the rotation set, not to all.
	t.Run("peer with no ring member still rejected", func(t *testing.T) {
		init := newRingSyncNode(rot14703KeyC, nil, 0)
		resp := newRingSyncNode(rot14703KeyA, [][]byte{rot14703KeyB}, 1)

		ca, cb := net.Pipe()
		defer ca.Close()
		defer cb.Close()
		ach := runHandshake(init, ca, true)
		bch := runHandshake(resp, cb, false)
		ar, br := <-ach, <-bch
		if ar.err == nil || br.err == nil {
			t.Fatalf("a peer holding no accepted key must be rejected: initiator err=%v responder err=%v", ar.err, br.err)
		}
		if ar.mode == syncAuthAuthenticated || br.mode == syncAuthAuthenticated {
			t.Fatal("an unrelated key must not authenticate against the ring")
		}
	})
}

// TestSessionSyncRotationRingFromManager verifies the production wiring:
// a real Manager driven through UpdateConfig (the config leaves, as
// newRotNode does) presents [signing, alt] to SessionSync via the probe,
// so the daemon path — not just the test fake — widens.
func TestSessionSyncRotationRingFromManager(t *testing.T) {
	m := NewManager(0, 22)
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.Secret(rot14703KeyB),
		ControlLinkAuthKeyAlt: config.Secret(rot14703KeyA),
	})
	s := NewSessionSync(":0", ":0", nil)
	s.SetAuthProvider(m)

	keys := s.authAcceptedKeys()
	if len(keys) != 2 || !bytes.Equal(keys[0], rot14703KeyB) || !bytes.Equal(keys[1], rot14703KeyA) {
		t.Fatalf("authAcceptedKeys from Manager = %d keys, want [B A] in ring order", len(keys))
	}
	if !bytes.Equal(s.authKey(), rot14703KeyB) {
		t.Fatal("authKey must remain the SIGNING key B; the ring must not change what this node signs with")
	}

	// Finalize: the retired key leaves the ring.
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey: config.Secret(rot14703KeyB),
	})
	keys = s.authAcceptedKeys()
	if len(keys) != 1 || !bytes.Equal(keys[0], rot14703KeyB) {
		t.Fatalf("after finalize authAcceptedKeys = %d keys, want [B] only — an overlap that cannot close is a second permanent key", len(keys))
	}
}

// TestSessionSyncSingleKeyProviderRingFallback pins the probe fallback: a
// provider implementing only ControlLinkAuthKey (every pre-#14703 fake)
// still presents exactly that one key, so existing fixtures keep meaning
// what they meant.
func TestSessionSyncSingleKeyProviderRingFallback(t *testing.T) {
	s := newAuthSyncNode(t, []byte("only-key"), 0)
	keys := s.authAcceptedKeys()
	if len(keys) != 1 || !bytes.Equal(keys[0], []byte("only-key")) {
		t.Fatalf("single-key provider ring = %v, want [only-key]", keys)
	}

	unkeyed := NewSessionSync(":0", ":0", nil)
	if got := unkeyed.authAcceptedKeys(); len(got) != 0 {
		t.Fatalf("unwired sync ring = %v, want empty", got)
	}
}
