package cluster

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// upgEnd is one side of an in-place upgrade: a SessionSync with a single
// installed authConn, driven frame by frame so the test can assert on the
// exact switch boundaries rather than on a settled end state.
type upgEnd struct {
	s    *SessionSync
	ac   *authConn
	wire net.Conn // the peer's end of the pipe, read by the harness

	// sealedOut records whether this end was SEALING at the instant it was
	// asked to write. A frame's sealed-ness is the writer's posture BEFORE the
	// write, never after — every switch in this exchange happens after the
	// frame that is the peer's boundary — so the harness must sample it at the
	// same instant production does.
	sealedOut bool
}

// tcpPair returns a connected loopback TCP pair.
//
// NOT net.Pipe: net.Pipe is synchronous and unbuffered, so a handler that
// answers a frame blocks until someone reads it — and the exchange under test
// is precisely a sequence of answer-a-frame steps. Driving that over net.Pipe
// needs a goroutine per delivery, which puts the test goroutine's state reads
// in a race with the handler it is asserting about. A kernel socket buffer
// makes every write in this exchange return immediately, so each step can run
// synchronously and the assertions see a settled state.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	t.Cleanup(func() { dialed.Close(); got.c.Close() })
	return dialed, got.c
}

// upgClusterID is the cluster id both ends of every fixture below share. The
// #7163 prologue binds it, so the two ends must agree or nothing authenticates.
const upgClusterID = 22

// newUpgEnd builds one end of an established, initially unauthenticated
// connection.
//
// node is load-bearing since #7163: the in-place upgrade takes its role from
// NODE ID (the lower id initiates), so a fixture that gave both ends the same
// id would have both ends believing they are the initiator and neither would
// ever answer a Hello. Callers pass 0 for the initiator side and 1 for the
// responder side.
func newUpgEnd(t *testing.T, key string, node int) *upgEnd {
	t.Helper()
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	if key != "" {
		s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(key), node: node, cluster: upgClusterID})
	}
	local, remote := tcpPair(t)
	ac := &authConn{Conn: local}
	s.mu.Lock()
	s.conn0 = ac
	s.mu.Unlock()
	return &upgEnd{s: s, ac: ac, wire: remote}
}

// pump reads one frame off e's wire and delivers it to the OTHER end's
// handleMessage, which is exactly what that end's receiveLoop would do.
// Returns the message type delivered.
//
// Frames are moved one at a time on purpose: the whole correctness argument is
// about which frame is the boundary for each direction's key switch, and a
// harness that let both sides run free could not distinguish "switched at the
// right frame" from "settled correctly eventually".
// readUpgradeFrame reads one frame off e's wire WITHOUT delivering it, draining the
// auth trailer when sealed says the writer was sealing as it wrote.
//
// Separate from pump because a single handler can emit two frames at DIFFERENT
// postures — handleAuthUpgradeProof writes the Confirm unsealed and then, if a
// rotation is pending, a Hello that IS sealed — and one sticky flag cannot
// model both.
func readUpgradeFrame(t *testing.T, e *upgEnd, sealed bool) (uint8, []byte) {
	t.Helper()
	_ = e.wire.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, syncHeaderSize)
	if _, err := io.ReadFull(e.wire, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := binary.LittleEndian.Uint32(hdr[8:12])
	body := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(e.wire, body); err != nil {
			t.Fatalf("read frame body: %v", err)
		}
	}
	if sealed {
		if _, err := io.ReadFull(e.wire, make([]byte, syncAuthFrameTrailerSize)); err != nil {
			t.Fatalf("read frame trailer: %v", err)
		}
	}
	return hdr[4], body
}

func pump(t *testing.T, from *upgEnd, to *upgEnd) uint8 {
	t.Helper()
	// The trailer is drained only when the writer was ALREADY sealing before
	// it wrote this frame, which is what makes this an assertion rather than a
	// convenience: every switch in the exchange happens AFTER the frame that
	// is the peer's boundary, so on a first upgrade none of the frames carries
	// a trailer, and on a re-upgrade (a rotation over an already authenticated
	// connection) all of them do. Move any switch ahead of its write and this
	// drain goes wrong by exactly one trailer — the step below then fails on a
	// bogus message type, which is the same desync the ordering contract
	// exists to prevent, surfaced here instead of on a live cluster.
	typ, body := readUpgradeFrame(t, from, from.sealedOut)
	to.sealedOut = to.ac.writeAuthed()
	to.s.handleMessage(to.ac, typ, body)
	return typ
}

// expectSilence asserts that e has written nothing.
func expectSilence(t *testing.T, e *upgEnd, why string) {
	t.Helper()
	_ = e.wire.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := e.wire.Read(buf); err == nil {
		t.Fatal(why)
	}
}

// runUpgrade drives the full exchange initiated by a, and returns the ordered
// list of message types that crossed. a must be the node-0 (initiator) end.
func runUpgrade(t *testing.T, a, b *upgEnd) []uint8 {
	t.Helper()
	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	var seen []uint8
	seen = append(seen, pump(t, a, b)) // Hello   a -> b   (noise msg1)
	seen = append(seen, pump(t, b, a)) // Proof   b -> a   (noise msg2)
	seen = append(seen, pump(t, a, b)) // Confirm a -> b
	return seen
}

// upgradeFrameSequence is the #7163 three-frame choreography.
var upgradeFrameSequence = []uint8{
	syncMsgAuthUpgradeHello, syncMsgAuthUpgradeProof, syncMsgAuthUpgradeConfirm,
}

func assertFrameSequence(t *testing.T, seen, want []uint8) {
	t.Helper()
	if len(seen) != len(want) {
		t.Fatalf("frame sequence %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("frame %d is type %d, want %d (sequence %v)", i, seen[i], want[i], seen)
		}
	}
}

// TestInPlaceUpgradeAuthenticatesAnEstablishedConnection6628 is the primary
// gate: a connection established while BOTH ends were unkeyed — which is by
// construction the connection that carries the PSK across, since
// performSyncHandshake runs no handshake without a local key — becomes
// authenticated in both directions after both ends commit the key, with no
// reconnect and no restart.
//
// FAIL-ON-REVERT: drop the ReconcileConnectionAuth call, or the receive arms,
// and the exchange never happens; the connection stays unauthenticated and
// this reds.
func TestInPlaceUpgradeAuthenticatesAnEstablishedConnection6628(t *testing.T) {
	const psk = "in-place-upgrade-psk-6628"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

	// Precondition: the connection is unauthenticated in both directions, as a
	// connection handshaked while both ends were unkeyed is.
	if a.ac.readAuthed() || a.ac.writeAuthed() || b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("the fixture must start unauthenticated, or the assertions below are vacuous")
	}

	assertFrameSequence(t, runUpgrade(t, a, b), upgradeFrameSequence)

	if !a.ac.authed() {
		t.Fatalf("the initiator must be authenticated in BOTH directions after the exchange "+
			"(read=%v write=%v); an established unkeyed stream that stays unkeyed after the "+
			"key is committed is the whole of #6628", a.ac.readAuthed(), a.ac.writeAuthed())
	}
	if !b.ac.authed() {
		t.Fatalf("the responder must be authenticated in BOTH directions (read=%v write=%v)",
			b.ac.readAuthed(), b.ac.writeAuthed())
	}
	// Both ends must reach the SAME frame key in each direction, or every
	// sealed frame from here on fails verification.
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) {
		t.Fatal("a's write key must equal b's read key")
	}
	if !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("b's write key must equal a's read key")
	}

	// And the upgrade is real: a frame sealed by one end verifies at the other.
	frame := encodeRawMessage(syncMsgSessionV4, []byte("post-upgrade"))
	sealed := a.ac.sealFrame(frame)
	header := sealed[:syncHeaderSize]
	length := binary.LittleEndian.Uint32(header[8:12])
	payload := sealed[syncHeaderSize : syncHeaderSize+int(length)]
	trailer := sealed[syncHeaderSize+int(length):]
	if err := b.ac.verifyFrame(header, payload, trailer); err != nil {
		t.Fatalf("a frame sealed after the upgrade must verify at the peer: %v", err)
	}
}

// TestInPlaceUpgradeInstallsDirectionalKeys7163 is the #7163 property carried
// into the upgrade path, and it is a DIFFERENT assertion from "both ends agree"
// above: the pre-#7163 syncDeriveFrameKey sorted its two nonces canonically, so
// both ends agreed AND both directions got the same bytes. Agreement alone is
// satisfied by the defect.
//
// The consequence that made it a vulnerability is SELF-FENCING: with one key
// per connection, a frame this node SENT verifies when echoed straight back at
// it, and verifyFrame's replay watermark cannot see it because it tracks the
// RECEIVE counter, which is independent of the send counter. The worst
// reflectable frame is syncMsgFence — empty payload, and on receipt the victim
// disables every one of its own redundancy groups.
//
// So this asserts the echo is REFUSED, not merely that two byte slices differ.
func TestInPlaceUpgradeInstallsDirectionalKeys7163(t *testing.T) {
	const psk = "directional-upgrade-psk-7163"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)
	runUpgrade(t, a, b)

	if bytes.Equal(a.ac.readKey, a.ac.writeKey) {
		t.Fatal("the initiator's two directions share one key — the pre-#7163 shape, which " +
			"is what let a node's own frame verify when echoed back at it")
	}
	if bytes.Equal(b.ac.readKey, b.ac.writeKey) {
		t.Fatal("the responder's two directions share one key")
	}

	// The echo, end to end: a's own sealed fence, replayed to a.
	fence := encodeRawMessage(syncMsgFence, nil)
	sealed := a.ac.sealFrame(fence)
	header := sealed[:syncHeaderSize]
	length := binary.LittleEndian.Uint32(header[8:12])
	payload := sealed[syncHeaderSize : syncHeaderSize+int(length)]
	trailer := sealed[syncHeaderSize+int(length):]
	if err := a.ac.verifyFrame(header, payload, trailer); err == nil {
		t.Fatal("a node's OWN sealed frame verified when echoed back at it. That is the " +
			"vector-B self-fencing primitive: the echoed frame is syncMsgFence, and on " +
			"receipt this node disables every redundancy group it owns.")
	}
	// Positive control: the same frame verifies at the PEER, so the refusal
	// above means "wrong direction", not "sealing is broken".
	if err := b.ac.verifyFrame(header, payload, trailer); err != nil {
		t.Fatalf("the same frame must verify at the peer, or the refusal above proves "+
			"nothing about directionality: %v", err)
	}
}

// TestInPlaceUpgradeNeverSwitchesOneDirectionEarly6628 is the assertion the
// multi-frame shape exists for, and it is the one a settled-end-state test
// cannot make.
//
// A single `key` field on authConn — the pre-#6628 shape — would flip read and
// write together on one end. That end then requires a trailer while the peer
// is still sending unsealed frames, consumes syncAuthFrameTrailerSize bytes of
// the NEXT frame as a trailer, fails the MAC and DROPS the connection. So the
// invariant is not "both ends end up authenticated"; it is "no end ever
// requires a trailer before the peer has started writing one".
//
// #7163 makes this harder rather than easier: Split() yields TWO keys where the
// old derivation yielded one, so there are two install points per direction.
// Checked at every frame boundary of the exchange.
func TestInPlaceUpgradeNeverSwitchesOneDirectionEarly6628(t *testing.T) {
	const psk = "in-place-upgrade-psk-6628"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

	check := func(stage string) {
		t.Helper()
		// a reads sealed frames only once b is sealing them, and vice versa.
		if a.ac.readAuthed() && !b.ac.writeAuthed() {
			t.Fatalf("%s: the initiator requires a trailer the responder is not writing — the "+
				"next unsealed frame desyncs the stream and drops the connection", stage)
		}
		if b.ac.readAuthed() && !a.ac.writeAuthed() {
			t.Fatalf("%s: the responder requires a trailer the initiator is not writing", stage)
		}
	}

	check("before the exchange")
	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b)
	check("after the initiator's Hello")
	pump(t, b, a)
	check("after the responder's Proof")
	pump(t, a, b)
	check("after the initiator's Confirm")

	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("the exchange must still complete — a test that never switches anything " +
			"satisfies the invariant above vacuously")
	}
}

// TestUpgradeInstallPointsAreAnchoredToTheirFrames7163 answers the question
// #7163 raises and #6628 did not have to: Split() gives two INDEPENDENT keys,
// so there are two install points per direction rather than one shared derived
// value. What happens if they land out of order?
//
// They cannot land in an arbitrary order, and the reason is worth stating
// exactly, because "both ends end up authenticated" does not imply it. Each
// direction has exactly one boundary frame; the WRITER installs immediately
// after writing that frame, inside the same writeMu section, and the READER
// installs while processing it. TCP orders frames within a direction, so every
// frame written before the install is unsealed and every frame after it is
// sealed, and the reader crosses the same line at the same frame.
//
//	responder WRITE + initiator READ  -> boundary is the Proof
//	initiator WRITE + responder READ  -> boundary is the Confirm
//
// Two sub-tests, because the risk has two halves: the boundary frame must be
// UNSEALED when it crosses a boundary that has not moved yet, and the writer's
// install must not happen at all if that frame did not go out.
func TestUpgradeInstallPointsAreAnchoredToTheirFrames7163(t *testing.T) {
	const psk = "install-points-psk-7163"

	t.Run("the Confirm crosses before the responder's read boundary moves", func(t *testing.T) {
		a := newUpgEnd(t, psk, 0)
		b := newUpgEnd(t, psk, 1)
		a.sealedOut = a.ac.writeAuthed()
		a.s.ReconcileConnectionAuth("test")
		pump(t, a, b) // Hello   a -> b
		pump(t, b, a) // Proof   b -> a

		// The Proof's own boundary has moved on BOTH ends, in one frame.
		if !b.ac.writeAuthed() || !a.ac.readAuthed() {
			t.Fatalf("the Proof must move the responder's write and the initiator's read "+
				"together (b.write=%v a.read=%v)", b.ac.writeAuthed(), a.ac.readAuthed())
		}
		// The initiator has already installed its write key, because the
		// Confirm went out inside the same handler. The responder has not moved
		// its read boundary, because the Confirm has not reached it yet.
		if !a.ac.writeAuthed() {
			t.Fatal("the initiator installs its write key immediately after writing the " +
				"Confirm; a gap between the two would let an unsealed frame follow a " +
				"boundary the peer has already crossed")
		}
		if b.ac.readAuthed() {
			t.Fatal("the responder must not move its read boundary before the Confirm " +
				"reaches it")
		}
		// So the Confirm — still in flight — MUST be unsealed, or the responder
		// cannot parse the very frame that moves its boundary. a.sealedOut was
		// sampled by pump before the handler ran, which is the same instant
		// production sampled it.
		if a.sealedOut {
			t.Fatal("the Confirm was sealed under a key the responder has not installed; " +
				"it would be read as a short frame plus garbage and the connection would " +
				"drop")
		}
		if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
			t.Fatalf("expected the Confirm, got frame type %d", typ)
		}
		if !a.ac.authed() || !b.ac.authed() {
			t.Fatal("both ends must be authenticated in both directions once the Confirm lands")
		}
		if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
			t.Fatal("both ends must agree on both directions")
		}
	})

	t.Run("a Confirm that never goes out installs no write key", func(t *testing.T) {
		// The only way the initiator's write install and the responder's read
		// install can end up on opposite sides of a frame is if the Confirm is
		// never written. Force exactly that: kill the socket, then hand the
		// initiator the Proof directly.
		a := newUpgEnd(t, psk, 0)
		b := newUpgEnd(t, psk, 1)
		a.sealedOut = a.ac.writeAuthed()
		a.s.ReconcileConnectionAuth("test")
		pump(t, a, b) // Hello a -> b, so b answers with a real msg2

		_ = a.wire.SetReadDeadline(time.Now().Add(3 * time.Second))
		hdr := make([]byte, syncHeaderSize)
		if _, err := io.ReadFull(b.wire, hdr); err != nil {
			t.Fatalf("read the responder's Proof header: %v", err)
		}
		body := make([]byte, binary.LittleEndian.Uint32(hdr[8:12]))
		if _, err := io.ReadFull(b.wire, body); err != nil {
			t.Fatalf("read the responder's Proof body: %v", err)
		}

		a.ac.Conn.Close()
		a.wire.Close()
		a.s.handleMessage(a.ac, hdr[4], body)

		if !a.ac.readAuthed() {
			t.Fatal("the read direction must still install: the responder switched its " +
				"write immediately after emitting that frame, so reverting it would " +
				"desync the direction that IS working")
		}
		if a.ac.writeAuthed() {
			t.Fatal("the write key was installed although the Confirm never went out. The " +
				"responder's read boundary therefore never moves, and the initiator's " +
				"next sealed frame desyncs a stream this mechanism promises never to drop.")
		}
	})
}

// TestUpgradeRotationWaitsForAnOutstandingRoundAndHealsOnTheRequest7163 pins
// the rule that keeps a replayed or superseding Hello from dropping the
// connection, and pins the two escapes that keep the rule affordable.
//
// THE RULE. An INCOMPLETE round is never superseded, not even by a rotation.
// The responder may already have answered our Hello and switched its write
// direction, and only that round's handshake state can read the msg2 it sent;
// discarding it strands the peer sealing under a key this node can no longer
// derive. #6628 was immune to this because its round state was set-once nonce
// state a second Hello could not clobber. Noise state is not, so the refusal is
// explicit.
//
// THE ESCAPES, without which the rule would strand a rotation forever against a
// peer that never answers:
//
//   - a peer that was simply not keyed yet says so with a REQUEST. A Request
//     for a round outstanding under the SAME key RE-SENDS that round's Hello
//     rather than replacing it, so nothing is lost even when the Request was
//     forged; only a Request that arrives while the outstanding round belongs
//     to a RETIRED key mints a fresh one, which is the case this test drives;
//   - a round that COMPLETES under a retired key re-triggers itself, which
//     TestUpgradeCompletingFramesAreNotGatedOnTheLiveKey7163 covers.
//
// FAIL-ON-REVERT: let beginAuthUpgrade supersede an incomplete round and the
// silence assertion reds; drop the Request supersession and the heal reds.
func TestUpgradeRotationWaitsForAnOutstandingRoundAndHealsOnTheRequest7163(t *testing.T) {
	const first = "outstanding-round-first-psk-7163"
	const second = "outstanding-round-second-psk-7163"
	a := newUpgEnd(t, first, 0)
	b := newUpgEnd(t, "", 1) // not keyed yet: it will not answer

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("first-commit")
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("expected a Hello, got frame type %d", typ)
	}
	// Idempotent: a second commit under the SAME key adds nothing.
	a.s.ReconcileConnectionAuth("unrelated-commit")
	expectSilence(t, a, "a commit under the same key must not re-emit a Hello while a round "+
		"is already in flight; a second ephemeral leaves the peer answering a handshake "+
		"this node no longer holds")

	// The operator rotates. The round is OUTSTANDING — this node cannot know
	// whether the peer has already answered it — so it must NOT be superseded.
	a.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 0, cluster: upgClusterID})
	a.s.ReconcileConnectionAuth("rotation")
	expectSilence(t, a, "a rotation superseded an OUTSTANDING round. If the responder had "+
		"already answered the first Hello it switched its write direction there, and this "+
		"node has just discarded the only state that can read that msg2 — the peer seals "+
		"under a key this node cannot derive and the connection drops")

	// The peer becomes keyed and prompts. A Request is what disturbs the
	// outstanding round — and here it must MINT a fresh one rather than
	// re-send, because the round on the wire belongs to the RETIRED key and the
	// peer would refuse its msg1. (A Request for a round outstanding under the
	// SAME key re-sends instead; see
	// TestUpgradeRequestReSendsTheOutstandingHello7163.)
	b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 1, cluster: upgClusterID})
	b.sealedOut = b.ac.writeAuthed()
	b.s.ReconcileConnectionAuth("peer-keyed")
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeRequest {
		t.Fatalf("expected a Request, got frame type %d", typ)
	}
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("a Request must supersede the outstanding round and emit a fresh Hello "+
			"under the rotated key; got frame type %d. Without this the rotation waits "+
			"for an unrelated commit that may never come.", typ)
	}
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeProof {
		t.Fatalf("expected a Proof, got frame type %d", typ)
	}
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
		t.Fatalf("expected a Confirm, got frame type %d", typ)
	}
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("the healed exchange must complete both directions")
	}
	if !bytes.Equal(a.ac.authPSK, []byte(second)) {
		t.Fatal("the connection must record the key it is now authenticated under")
	}
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("both ends must agree on both directions")
	}
}

// TestUpgradeReplayedHelloCannotStrandTheResponder7163 is the attack the
// answeredAwaitingConfirm guard exists for, driven end to end.
//
// A msg1 is 48 bytes of CLEARTEXT on a not-yet-sealed stream — which is the only
// stream an in-place upgrade ever starts on — and its AEAD tag covers the
// prologue and the initiator's ephemeral, neither of which changes on a replay.
// So a captured Hello RE-VERIFIES. Without the guard the responder mints a
// second round on top of a commitment it has already made:
//
//  1. R answers Hello_1 and installs writeKey = r2i_1.
//  2. The attacker replays Hello_1. R answers again and installs r2i_1'.
//  3. I completes round 1, installs writeKey = i2r_1, sends Confirm_1.
//  4. R checks Confirm_1 against round 1' -> MAC fails -> R never installs a
//     read key, while I is already sealing.
//  5. Both directions desync. The connection DROPS, which is the one outcome
//     this mechanism promises never happens.
//
// PAIRED: the replay must change nothing AND the legitimate exchange must still
// complete afterwards, so a responder that ignored every Hello cannot pass.
func TestUpgradeReplayedHelloCannotStrandTheResponder7163(t *testing.T) {
	const psk = "replayed-hello-psk-7163"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	typ, hello := readUpgradeFrame(t, a, false)
	if typ != syncMsgAuthUpgradeHello {
		t.Fatalf("expected a Hello, got frame type %d", typ)
	}
	b.s.handleMessage(b.ac, syncMsgAuthUpgradeHello, hello)
	if !b.ac.writeAuthed() {
		t.Fatal("precondition: the responder must have answered and installed its write key")
	}
	committed := append([]byte(nil), b.ac.writeKey...)
	ptyp, msg2 := readUpgradeFrame(t, b, false)
	if ptyp != syncMsgAuthUpgradeProof {
		t.Fatalf("expected a Proof, got frame type %d", ptyp)
	}

	// THE REPLAY: the exact same bytes, again.
	b.s.handleMessage(b.ac, syncMsgAuthUpgradeHello, hello)
	if !bytes.Equal(b.ac.writeKey, committed) {
		t.Fatal("a replayed Hello re-keyed the responder's write direction. The initiator " +
			"derived the FIRST round's key and cannot read a byte from here on.")
	}
	expectSilence(t, b, "a replayed Hello must not be answered; the second msg2 would be "+
		"sealed under the committed key and carry an ephemeral the initiator never sees")

	// The legitimate exchange must still complete — otherwise the refusal above
	// is indistinguishable from a responder that ignores every Hello.
	a.s.handleMessage(a.ac, syncMsgAuthUpgradeProof, msg2)
	ctyp, confirm := readUpgradeFrame(t, a, false)
	if ctyp != syncMsgAuthUpgradeConfirm {
		t.Fatalf("expected a Confirm, got frame type %d", ctyp)
	}
	b.s.handleMessage(b.ac, syncMsgAuthUpgradeConfirm, confirm)
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatalf("the legitimate exchange must complete through the replay "+
			"(a.read=%v a.write=%v b.read=%v b.write=%v)",
			a.ac.readAuthed(), a.ac.writeAuthed(), b.ac.readAuthed(), b.ac.writeAuthed())
	}
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("both ends must agree on both directions")
	}
}

// TestUpgradeRequestReSendsTheOutstandingHello7163 pins the property that makes
// a FORGED Request harmless.
//
// A Request carries no MAC — on a not-yet-sealed stream there is nothing to key
// one with that a replay would not also carry — so an on-path attacker can
// inject one. If that made the initiator mint a FRESH round, it would discard
// the handshake state a msg2 already in flight needs, and the responder would be
// left sealing under a key the initiator can no longer derive: the same drop as
// the replayed Hello, reached from the other side.
//
// So a Request for a round that is still outstanding under the SAME key
// re-emits that round's Hello BYTE FOR BYTE instead. The byte comparison is the
// assertion: a fresh round would carry a different ephemeral, and asserting only
// on the frame TYPE would pass either way.
//
// PAIRED: the re-send must be identical AND the exchange must still complete, so
// a node that answered a Request with nothing at all cannot pass.
func TestUpgradeRequestReSendsTheOutstandingHello7163(t *testing.T) {
	const psk = "request-resend-psk-7163"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, "", 1) // not keyed yet, so the first Hello goes unanswered

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("first-commit")
	typ, hello1 := readUpgradeFrame(t, a, false)
	if typ != syncMsgAuthUpgradeHello {
		t.Fatalf("expected a Hello, got frame type %d", typ)
	}

	// The peer becomes keyed and prompts, under the SAME key.
	b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(psk), node: 1, cluster: upgClusterID})
	b.sealedOut = b.ac.writeAuthed()
	b.s.ReconcileConnectionAuth("peer-keyed")
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeRequest {
		t.Fatalf("expected a Request, got frame type %d", typ)
	}

	typ, hello2 := readUpgradeFrame(t, a, false)
	if typ != syncMsgAuthUpgradeHello {
		t.Fatalf("a Request must produce a Hello, got frame type %d", typ)
	}
	if !bytes.Equal(hello1, hello2) {
		t.Fatal("the Request minted a FRESH round instead of re-sending the outstanding " +
			"one. A Request carries no MAC, so an on-path attacker can forge one; if it " +
			"discards the round, a msg2 already in flight can no longer be read and the " +
			"responder is left sealing under a key this node cannot derive.")
	}

	// The re-sent Hello must still work, or the byte equality above is
	// satisfied by re-sending something inert.
	b.s.handleMessage(b.ac, syncMsgAuthUpgradeHello, hello2)
	if !b.ac.writeAuthed() {
		t.Fatal("the re-sent Hello must be answered by the now-keyed peer")
	}
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeProof {
		t.Fatalf("expected a Proof, got frame type %d", typ)
	}
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
		t.Fatalf("expected a Confirm, got frame type %d", typ)
	}
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatalf("the exchange must complete through the re-send "+
			"(a.read=%v a.write=%v b.read=%v b.write=%v)",
			a.ac.readAuthed(), a.ac.writeAuthed(), b.ac.readAuthed(), b.ac.writeAuthed())
	}
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("both ends must agree on both directions")
	}
}

// TestUpgradeResponderPromptIsDeferredUntilItsRoundCompletes7163 pins the
// silence that makes a Request meaningful.
//
// A Request tells the initiator to SUPERSEDE. If the responder could send one
// while awaiting a Confirm, it would be asking the initiator to discard a round
// the responder itself has already committed to — the same drop as the replay
// above, self-inflicted. So the prompt is deferred, and because it is deferred
// it must then actually FIRE once the round completes, or a rotation that
// landed mid-round is stranded.
//
// PAIRED, and the pairing is the point: silence at the first step alone is
// satisfied by a node that never prompts at all.
func TestUpgradeResponderPromptIsDeferredUntilItsRoundCompletes7163(t *testing.T) {
	const first = "deferred-prompt-first-psk-7163"
	const second = "deferred-prompt-second-psk-7163"
	a := newUpgEnd(t, first, 0)
	b := newUpgEnd(t, first, 1)

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello  a -> b; b answers and is now awaiting the Confirm
	pump(t, b, a) // Proof  b -> a; a completes its side and writes the Confirm
	if b.ac.readAuthed() {
		t.Fatal("precondition: the responder must still be awaiting the Confirm")
	}

	// The operator rotates on the RESPONDER, mid-round.
	b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 1, cluster: upgClusterID})
	b.s.ReconcileConnectionAuth("rotation")
	expectSilence(t, b, "the responder prompted while awaiting a Confirm. A Request makes "+
		"the initiator supersede, and superseding here discards the round this node has "+
		"already committed its write direction to")

	// The Confirm lands; the round completes; the deferred prompt must fire.
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
		t.Fatalf("expected the Confirm, got frame type %d", typ)
	}
	if !b.ac.readAuthed() {
		t.Fatal("the Confirm must complete the responder's read direction")
	}
	b.sealedOut = b.ac.writeAuthed()
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeRequest {
		t.Fatalf("the deferred prompt must fire once the round completes; got frame type "+
			"%d. Without it the rotation waits for an unrelated commit that may never "+
			"come, and the connection keeps sealing under the retired PSK.", typ)
	}
}

// TestInPlaceUpgradeWithMismatchedKeysSwitchesNothing6628 is why neither end
// switches anything until key equality is proven.
//
// A botched rotation leaves the two nodes on different keys. #6628 needed four
// frames to survive it, because its responder had proven nothing when it
// answered. Under Noise_NNpsk0 the responder authenticates the initiator's msg1
// BEFORE answering, so a mismatch is refused one frame earlier and the
// responder simply says nothing — which is what this asserts.
//
// FAIL-ON-REVERT: install the responder's writeKey before the msg1 tag is
// checked, and the silence assertion reds.
func TestInPlaceUpgradeWithMismatchedKeysSwitchesNothing6628(t *testing.T) {
	a := newUpgEnd(t, "key-alpha-6628", 0)
	b := newUpgEnd(t, "key-beta-6628", 1)

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello a -> b  (b will fail to authenticate it)

	if a.ac.readAuthed() || a.ac.writeAuthed() {
		t.Fatal("the initiator must not switch anything on its own Hello")
	}
	if b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("the responder must not switch anything on a Hello that did not " +
			"authenticate; switching there desyncs the stream whenever the two nodes hold " +
			"different keys, which is exactly a botched rotation")
	}
	expectSilence(t, b, "a responder that could not authenticate the Hello must answer with "+
		"silence; a msg2 would hand the initiator a key it cannot derive and move a "+
		"boundary the initiator will never reach")
	// The connection is untouched, not dropped: that is the property.
	if a.ac.authPSK != nil || b.ac.authPSK != nil {
		t.Fatal("a failed upgrade must leave the connection recorded as unauthenticated")
	}

	// POSITIVE CONTROL (#7163). Everything above asserts that NOTHING switched,
	// which a completely broken exchange satisfies just as well as a correctly
	// refusing one. Without this, changing the handshake underneath — as #7163
	// does — could leave the whole test passing for the wrong reason while the
	// mechanism it guards had stopped working entirely.
	//
	// So: the SAME pump sequence, with MATCHING keys, must produce a msg2 and
	// go on to switch both ends. That is what makes the negative result above
	// mean "refused" rather than "never ran".
	c := newUpgEnd(t, "key-alpha-6628", 0)
	d := newUpgEnd(t, "key-alpha-6628", 1)
	c.sealedOut = c.ac.writeAuthed()
	c.s.ReconcileConnectionAuth("test")
	pump(t, c, d)
	if !d.ac.writeAuthed() {
		t.Fatal("positive control FAILED at the Proof: a matching-key Hello must be " +
			"authenticated and answered. The silence asserted above therefore proves " +
			"nothing — it would hold for an exchange that never runs.")
	}
	pump(t, d, c)
	pump(t, c, d)
	if !c.ac.authed() || !d.ac.authed() {
		t.Fatalf("positive control FAILED: matching keys did not complete the upgrade "+
			"(c.read=%v c.write=%v d.read=%v d.write=%v)",
			c.ac.readAuthed(), c.ac.writeAuthed(), d.ac.readAuthed(), d.ac.writeAuthed())
	}
}

// TestUpgradeMsg1IsAuthenticated7163 is the measurement the three-frame shape
// rests on, isolated so a change to it cannot hide inside an end-to-end result.
//
// #6628 needed a fourth frame because its responder had proven nothing when it
// switched its write direction. #7163 drops that frame on the claim that
// Noise_NNpsk0's FIRST message is already AEAD-tagged over the prologue and the
// transcript, so reading it proves key equality. If that claim ever stops
// holding — a pattern change, a placement change, a library change — the
// responder would be switching on an unauthenticated message and a key mismatch
// would desync the stream again.
//
// PAIRED: the wrong-key msg1 must be refused AND the right-key msg1 must be
// accepted, so "refuses everything" cannot pass.
func TestUpgradeMsg1IsAuthenticated7163(t *testing.T) {
	const good = "msg1-auth-good-7163"
	const bad = "msg1-auth-bad-7163"

	// The responder under test: node 1, keyed with `good`.
	deliver := func(t *testing.T, initiatorKey string) *upgEnd {
		t.Helper()
		b := newUpgEnd(t, good, 1)
		hs, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:  syncNoiseCipherSuite,
			Pattern:      noise.HandshakeNN,
			Initiator:    true,
			Prologue:     syncNoisePrologue(syncNoisePhaseUpgrade, upgClusterID, 0, 1, 0),
			PresharedKey: syncNoisePSK([]byte(initiatorKey)),
			Random:       rand.Reader,
		})
		if err != nil {
			t.Fatalf("build msg1: %v", err)
		}
		msg1, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			t.Fatalf("write msg1: %v", err)
		}
		if len(msg1) != 48 {
			t.Fatalf("msg1 is %d bytes, want 48 (32-byte ephemeral + 16-byte Poly1305 tag). "+
				"A msg1 with no tag would carry no proof of PSK possession, and the "+
				"three-frame exchange would be switching the responder's write direction "+
				"on an unauthenticated message.", len(msg1))
		}
		b.s.handleMessage(b.ac, syncMsgAuthUpgradeHello,
			append([]byte{syncAuthUpgradeVersion}, msg1...))
		return b
	}

	t.Run("wrong PSK is refused", func(t *testing.T) {
		b := deliver(t, bad)
		if b.ac.writeAuthed() || b.ac.readAuthed() {
			t.Fatal("a msg1 built under a different PSK must not move any boundary")
		}
		expectSilence(t, b, "a msg1 built under a different PSK must not be answered")
	})
	t.Run("right PSK is accepted", func(t *testing.T) {
		b := deliver(t, good)
		if !b.ac.writeAuthed() {
			t.Fatal("a msg1 built under the SAME PSK must be authenticated and answered, or " +
				"the refusal above proves nothing about the tag")
		}
	})
}

// TestUpgradePrologueBindsEveryField7163 binds the prologue field by field.
//
// The prologue is where every identity binding lives, and it is never PARSED —
// both ends construct it independently and the handshake hash compares them —
// so a field that stopped being mixed in would not surface as a decode error.
// It would surface as nothing at all: both ends would drop it together and the
// handshake would still succeed, with the binding silently absent. Only a
// fixture that feeds a DIFFERENT value for one field at a time can see that.
//
// The PHASE row is the one with a concrete attack behind it. Both exchanges run
// under the same PSK, and a CONNECT msg1 travels in cleartext on a fresh TCP
// connection where anyone on the fabric can read it. Without the phase byte that
// captured message is also a well-formed upgrade Hello: replayed into an
// established unauthenticated stream, the responder would answer and switch its
// write direction to a key derived from an ephemeral nobody holds — not the
// attacker (no PSK) and not the legitimate initiator (it never sent that msg1) —
// and the peer could no longer read a frame. The connection would DROP, which is
// the one thing this mechanism promises it never does.
//
// The table's FIRST row is the correct prologue and must be ACCEPTED. Without
// it the whole table is satisfied by a responder that refuses everything.
func TestUpgradePrologueBindsEveryField7163(t *testing.T) {
	const psk = "prologue-binding-psk-7163"
	// The responder under test is node 1, cluster upgClusterID, on fabric 0, so
	// its own prologue is (upgrade, upgClusterID, initiator 0, responder 1, 0).
	for _, tc := range []struct {
		name          string
		phase         byte
		cluster       int
		initiatorNode int
		responderNode int
		fabric        int
		wantAccepted  bool
	}{
		{"the responder's own prologue", syncNoisePhaseUpgrade, upgClusterID, 0, 1, 0, true},
		{"connect phase", syncNoisePhaseConnect, upgClusterID, 0, 1, 0, false},
		{"another cluster id", syncNoisePhaseUpgrade, upgClusterID + 1, 0, 1, 0, false},
		{"another initiator node", syncNoisePhaseUpgrade, upgClusterID, 5, 1, 0, false},
		{"another responder node", syncNoisePhaseUpgrade, upgClusterID, 0, 0, 0, false},
		{"another fabric index", syncNoisePhaseUpgrade, upgClusterID, 0, 1, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newUpgEnd(t, psk, 1)
			hs, err := noise.NewHandshakeState(noise.Config{
				CipherSuite: syncNoiseCipherSuite,
				Pattern:     noise.HandshakeNN,
				Initiator:   true,
				Prologue: syncNoisePrologue(tc.phase, tc.cluster,
					tc.initiatorNode, tc.responderNode, tc.fabric),
				PresharedKey: syncNoisePSK([]byte(psk)),
				Random:       rand.Reader,
			})
			if err != nil {
				t.Fatalf("build msg1: %v", err)
			}
			msg1, _, _, err := hs.WriteMessage(nil, nil)
			if err != nil {
				t.Fatalf("write msg1: %v", err)
			}
			b.s.handleMessage(b.ac, syncMsgAuthUpgradeHello,
				append([]byte{syncAuthUpgradeVersion}, msg1...))

			if got := b.ac.writeAuthed(); got != tc.wantAccepted {
				if tc.wantAccepted {
					t.Fatal("the responder's OWN prologue was refused. Every refusal in " +
						"this table is then satisfied by a responder that refuses " +
						"everything, and none of the bindings is actually pinned.")
				}
				t.Fatal("a msg1 built with a DIFFERENT value for this field was accepted, " +
					"so the field is not mixed into the prologue. It would not surface " +
					"as a decode error either: both ends would drop it together and the " +
					"handshake would still succeed with the binding silently absent.")
			}
		})
	}
}

// TestUpgradeRoleComesFromNodeIDNotTheWire7163: #6628 decided the role by
// comparing the two challenge nonces, which made role a function of a
// PEER-SUPPLIED value feeding this node's own key derivation — the same class
// of mistake vector B exploited. Role is now local knowledge on both sides.
//
// So a Hello arriving at the node that is the INITIATOR by id must be ignored:
// a peer cannot promote itself to initiator by sending a msg1.
func TestUpgradeRoleComesFromNodeIDNotTheWire7163(t *testing.T) {
	const psk = "role-from-node-id-7163"
	// a is node 0 (initiator) and b is node 1 (responder). Drive the exchange
	// BACKWARDS: b tries to open it.
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

	b.sealedOut = b.ac.writeAuthed()
	b.s.ReconcileConnectionAuth("test")
	typ := pump(t, b, a)
	if typ != syncMsgAuthUpgradeRequest {
		t.Fatalf("the responder-role node must PROMPT rather than open the exchange; it "+
			"emitted frame type %d, want %d", typ, syncMsgAuthUpgradeRequest)
	}

	// And a hand-built Hello aimed at the initiator-role node is ignored.
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:  syncNoiseCipherSuite,
		Pattern:      noise.HandshakeNN,
		Initiator:    true,
		Prologue:     syncNoisePrologue(syncNoisePhaseUpgrade, upgClusterID, 1, 0, 0),
		PresharedKey: syncNoisePSK([]byte(psk)),
		Random:       rand.Reader,
	})
	if err != nil {
		t.Fatalf("build msg1: %v", err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	// Drain whatever the Request prompted a into writing, so the silence check
	// below is about the Hello and not about that.
	pump(t, a, b)
	a.s.handleMessage(a.ac, syncMsgAuthUpgradeHello,
		append([]byte{syncAuthUpgradeVersion}, msg1...))
	if a.ac.writeAuthed() || a.ac.readAuthed() {
		t.Fatal("the initiator-role node accepted a Hello and moved a boundary. Role must " +
			"come from node id; a peer that can choose the role can choose which side of " +
			"the derivation it controls.")
	}
	expectSilence(t, a, "the initiator-role node must not answer a Hello")
}

// TestUpgradeResponderPromptStartsTheExchange7163 is the heal path for the
// order that actually happens on a live cluster.
//
// The operator commits the key on the PRIMARY; config-sync carries it to the
// secondary, which applies it and reconciles. Either node may therefore be
// keyed first. If the higher-id node is keyed second it cannot open the
// exchange — role is fixed by node id — so it prompts, and the prompt is what
// makes the exchange converge without a timer.
//
// FAIL-ON-REVERT: drop the Request arm from the receive switch, or the
// responder-role branch in beginAuthUpgrade, and this reds on a read deadline.
func TestUpgradeResponderPromptStartsTheExchange7163(t *testing.T) {
	const psk = "responder-prompt-psk-7163"
	a := newUpgEnd(t, psk, 0) // initiator by id
	b := newUpgEnd(t, psk, 1) // responder by id, keyed second

	b.sealedOut = b.ac.writeAuthed()
	b.s.ReconcileConnectionAuth("test")
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeRequest {
		t.Fatalf("expected a Request, got frame type %d", typ)
	}
	// The prompt must have made a open the exchange.
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeHello {
		t.Fatalf("a Request must make the initiator-role node emit a Hello; got frame "+
			"type %d. Without this the exchange never starts when the higher-id node is "+
			"the one that becomes keyed.", typ)
	}
	if typ := pump(t, b, a); typ != syncMsgAuthUpgradeProof {
		t.Fatalf("expected a Proof, got frame type %d", typ)
	}
	if typ := pump(t, a, b); typ != syncMsgAuthUpgradeConfirm {
		t.Fatalf("expected a Confirm, got frame type %d", typ)
	}
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatalf("the prompted exchange must complete both directions "+
			"(a.read=%v a.write=%v b.read=%v b.write=%v)",
			a.ac.readAuthed(), a.ac.writeAuthed(), b.ac.readAuthed(), b.ac.writeAuthed())
	}
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("both ends must agree on both directions")
	}
}

// TestUpgradeConfirmForgeryDoesNotMoveTheReadBoundary7163 is why the Confirm
// carries a MAC even though the responder already authenticated the initiator
// at msg1.
//
// The Confirm is the responder's read boundary. On a not-yet-sealed stream
// anyone able to inject a frame could send one; if the responder acted on it,
// it would start requiring a trailer while the real initiator is still writing
// unsealed frames, and the connection would DROP.
//
// PAIRED: the forgery must be refused AND the genuine Confirm that follows it
// must still land, so "ignore all Confirms" cannot pass.
func TestUpgradeConfirmForgeryDoesNotMoveTheReadBoundary7163(t *testing.T) {
	const psk = "confirm-forgery-psk-7163"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello
	pump(t, b, a) // Proof

	forged := make([]byte, 1+syncAuthUpgradeConfirmLen)
	forged[0] = syncAuthUpgradeVersion
	for i := 1; i < len(forged); i++ {
		forged[i] = 0x5A
	}
	b.s.handleMessage(b.ac, syncMsgAuthUpgradeConfirm, forged)
	if b.ac.readAuthed() {
		t.Fatal("a forged Confirm moved the responder's read boundary. The real initiator " +
			"is still writing unsealed frames, so the next one fails the MAC and the " +
			"connection drops — the outcome this mechanism promises never happens.")
	}

	// The genuine Confirm still completes the exchange.
	pump(t, a, b)
	if !b.ac.readAuthed() {
		t.Fatal("the genuine Confirm must still land after a forgery was refused, or the " +
			"refusal above is indistinguishable from ignoring every Confirm")
	}
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("the exchange must complete")
	}
}

// TestUpgradeCompletingFramesAreNotGatedOnTheLiveKey7163 binds the one place a
// mid-round config change could break the NEVER DROPS property.
//
// The Proof and the Confirm are COMPLETING frames: by the time each arrives,
// the peer that sent it has ALREADY switched the matching direction — the
// responder installs its write key immediately after emitting the Proof, and the
// initiator installs its write key immediately after emitting the Confirm.
// Refusing one of them therefore does not "stay safe"; it leaves the peer
// sealing into a reader that never moved, which is precisely the desync the
// switch-point discipline exists to prevent.
//
// So neither handler may consult the LIVE control-link key. A rotation that
// lands between the Hello and the completing frame is a normal operator action;
// it must not be able to cause that desync.
//
// FAIL-ON-REVERT: re-add `if len(key)==0 { return }` or a
// `bytes.Equal(st.forPSK, key)` test to either handler and the matching
// sub-test reds.
func TestUpgradeCompletingFramesAreNotGatedOnTheLiveKey7163(t *testing.T) {
	const first = "completing-frame-first-psk-7163"
	const second = "completing-frame-second-psk-7163"

	t.Run("the initiator installs on a Proof after a local rotation", func(t *testing.T) {
		a := newUpgEnd(t, first, 0)
		b := newUpgEnd(t, first, 1)
		a.sealedOut = a.ac.writeAuthed()
		a.s.ReconcileConnectionAuth("test")
		pump(t, a, b) // Hello a -> b; b installs its write key on answering

		// The operator rotates on THIS node while the Proof is in flight. The
		// round is OUTSTANDING, so the rotation must not supersede it — this
		// node cannot know whether the responder has already answered.
		a.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 0, cluster: upgClusterID})
		a.s.ReconcileConnectionAuth("rotation")
		expectSilence(t, a, "a rotation must not supersede an outstanding round; the "+
			"responder may already have committed to it")
		pump(t, b, a) // Proof b -> a

		if !a.ac.readAuthed() {
			t.Fatal("the initiator refused a Proof because the live key had changed. The " +
				"responder switched its write direction when it emitted that frame, so " +
				"every frame it sends from here on is sealed into a reader that never " +
				"moved — the connection drops.")
		}
		if !bytes.Equal(a.ac.readKey, b.ac.writeKey) {
			t.Fatal("the initiator must install the key THIS ROUND derived")
		}
		// And the stamp records the round's key, not the live one, so the
		// reconciler can still see that a rotation is owed.
		if !bytes.Equal(a.ac.authPSK, []byte(first)) {
			t.Fatalf("authPSK must record the key the round authenticated under (%q), not "+
				"the live one; stamping the live key makes a connection running on a "+
				"RETIRED key look current and the rotation is never re-driven",
				first)
		}
		// The deferred rotation is driven by the round's own completion, with
		// no further commit: the Confirm goes out unsealed, then the fresh
		// Hello goes out SEALED under the key this round just installed. Two
		// frames from one handler at two postures, which is why they are read
		// with readUpgradeFrame rather than pump.
		if typ, _ := readUpgradeFrame(t, a, false); typ != syncMsgAuthUpgradeConfirm {
			t.Fatalf("expected the Confirm, got frame type %d", typ)
		}
		if typ, _ := readUpgradeFrame(t, a, true); typ != syncMsgAuthUpgradeHello {
			t.Fatalf("a round that completes under a RETIRED key must re-trigger itself; "+
				"got frame type %d. Without that, a rotation that landed while the round "+
				"was in flight could not supersede it and would then wait for an "+
				"unrelated commit that may never come — leaving the connection sealing "+
				"under the retired PSK, which is the second property #6628 names.", typ)
		}
	})

	t.Run("the responder installs on a Confirm after a local rotation", func(t *testing.T) {
		a := newUpgEnd(t, first, 0)
		b := newUpgEnd(t, first, 1)
		a.sealedOut = a.ac.writeAuthed()
		a.s.ReconcileConnectionAuth("test")
		pump(t, a, b) // Hello
		pump(t, b, a) // Proof; a installs BOTH and the Confirm goes on the wire

		// The operator rotates on the RESPONDER while the Confirm is in flight.
		b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 1, cluster: upgClusterID})
		pump(t, a, b) // Confirm

		if !b.ac.readAuthed() {
			t.Fatal("the responder refused a Confirm because the live key had changed. The " +
				"initiator switched its write direction when it emitted that frame, so " +
				"the connection desyncs on its next frame.")
		}
		if !bytes.Equal(b.ac.readKey, a.ac.writeKey) {
			t.Fatal("the responder must install the key THIS ROUND derived")
		}
		if !bytes.Equal(b.ac.authPSK, []byte(first)) {
			t.Fatalf("authPSK must record the round's key (%q), not the live one", first)
		}
	})
}

// TestInPlaceUpgradeIsSilentAgainstAnUnkeyedPeer6628: the rolling-upgrade case.
// A peer with no key must not be answered and must not be dropped — it keeps
// its connection, unauthenticated, exactly as today.
//
// This is also the honest limit of #6628: a HOSTILE stream declines the
// upgrade in precisely this way, and a decliner is indistinguishable from a
// legitimate not-yet-keyed peer. That residual is tracked separately.
func TestInPlaceUpgradeIsSilentAgainstAnUnkeyedPeer6628(t *testing.T) {
	a := newUpgEnd(t, "in-place-upgrade-psk-6628", 0)
	b := newUpgEnd(t, "", 1) // no key: a pre-keying peer, or one declining

	a.sealedOut = a.ac.writeAuthed()
	a.s.ReconcileConnectionAuth("test")
	pump(t, a, b) // Hello a -> b

	if b.ac.readAuthed() || b.ac.writeAuthed() {
		t.Fatal("an unkeyed peer cannot authenticate anything")
	}
	expectSilence(t, b, "an unkeyed peer must answer a Hello with silence — anything else "+
		"would either leak that it is unkeyed or start an exchange it cannot finish")
	if a.ac.readAuthed() || a.ac.writeAuthed() {
		t.Fatal("the initiator must not switch on its own Hello")
	}
}

// TestReconcileConnectionAuthIsANoOpWhenAlreadyKeyed6628 binds the staleness
// test. The reconciler runs on EVERY commit, so an already-authenticated
// connection must cost nothing and, more importantly, must not restart the
// exchange — a second Hello mints a second ephemeral and leaves the peer
// answering a handshake this node no longer holds.
//
// FAIL-ON-REVERT: drop the authPSK comparison in beginAuthUpgrade and this
// reds with a spurious Hello on the wire.
func TestReconcileConnectionAuthIsANoOpWhenAlreadyKeyed6628(t *testing.T) {
	const psk = "in-place-upgrade-psk-6628"
	a := newUpgEnd(t, psk, 0)
	b := newUpgEnd(t, psk, 1)
	runUpgrade(t, a, b)
	if !a.ac.authed() || !b.ac.authed() {
		t.Fatal("precondition: the connection must be authenticated at both ends")
	}

	// An unrelated commit, on BOTH roles: the initiator must not re-Hello and
	// the responder must not re-prompt. Checking only one of them would leave
	// the other's branch unbound, and the responder's is the newer of the two.
	a.s.ReconcileConnectionAuth("unrelated-commit")
	expectSilence(t, a, "a commit that does not change the key must put NOTHING on the "+
		"wire; restarting the exchange on a healthy connection leaves the peer answering "+
		"a handshake this node no longer holds")
	b.s.ReconcileConnectionAuth("unrelated-commit")
	expectSilence(t, b, "the responder-role node must not re-prompt on an unrelated commit")
}

// TestConnectAuthenticatedConnectionIsNotDisturbedByACommit6628 covers the
// case the reconciler sees most often and the rest of this file does not
// reach: a connection that authenticated at CONNECT time, through
// performSyncHandshake, and has never been near an upgrade.
//
// Its exchange state is empty, so the "an exchange is already in flight"
// guard does not apply to it; only the recorded PSK distinguishes it from a
// connection that genuinely needs upgrading. Without that record every commit
// would start a pointless exchange on a healthy authenticated stream — needless
// traffic, and a mid-stream key switch exercised for no reason.
//
// FAIL-ON-REVERT: drop the authPSK stamp in wrapSyncConn, or the authPSK
// comparison in beginAuthUpgrade, and a Hello appears on the wire here.
func TestConnectAuthenticatedConnectionIsNotDisturbedByACommit6628(t *testing.T) {
	const psk = "connect-authenticated-psk-6628"
	e := newUpgEnd(t, psk, 0)
	// Built by wrapSyncConn, NOT by hand. Hand-setting readKey/writeKey/authPSK
	// would bind the reconciler's comparison while leaving the STAMP unbound —
	// delete `ac.authPSK = ...` from wrapSyncConn and a hand-built fixture stays
	// green while every real connect-authenticated connection is churned on
	// every commit. Driving the production wrapper is the difference.
	// #7163: directional keys. Deliberately DIFFERENT bytes per direction —
	// the pre-#7163 shape used one key for both, which is the defect.
	frameKeys := syncNoiseKeysWithPSK{
		syncNoiseKeys: syncNoiseKeys{
			readKey:  []byte("connect-time-read-key-32-bytes!!"),
			writeKey: []byte("connect-time-write-key-32-byte!!"),
		},
		matchedPSK: []byte(psk),
	}
	wrapped := e.s.wrapSyncConn(0, e.ac.Conn, syncAuthAuthenticated, frameKeys)
	e.ac = wrapped
	e.s.mu.Lock()
	e.s.conn0 = wrapped
	e.s.mu.Unlock()
	if !wrapped.authed() {
		t.Fatal("precondition: wrapSyncConn must produce an authenticated connection")
	}

	e.s.ReconcileConnectionAuth("unrelated-commit")

	expectSilence(t, e, "a commit must put NOTHING on the wire for a connection that "+
		"already authenticated at connect time under the same key; starting an exchange "+
		"there churns a healthy stream and performs a mid-stream key switch for no reason")
	if !e.ac.authed() {
		t.Fatal("the connection must still be authenticated — a reconciler that tore it " +
			"down would satisfy the check above for the wrong reason")
	}
}

// TestInPlaceUpgradeRekeysOnRotation6628: the second property #6628 names —
// "rotation never revokes an existing connection's old derived frame key". An
// authenticated connection whose PSK is rotated must re-derive under the new
// key rather than keep sealing with the retired one.
//
// The rotation is also the one path where every frame of the exchange itself is
// SEALED, under the OLD key, while the boundaries move — so it exercises the
// switch-point discipline on a stream that is already authenticated rather than
// on a bare one.
func TestInPlaceUpgradeRekeysOnRotation6628(t *testing.T) {
	const first = "rotation-first-psk-6628"
	const second = "rotation-second-psk-6628"
	a := newUpgEnd(t, first, 0)
	b := newUpgEnd(t, first, 1)
	runUpgrade(t, a, b)
	oldKey := append([]byte(nil), a.ac.writeKey...)
	if len(oldKey) == 0 {
		t.Fatal("precondition: the first upgrade must have produced a frame key")
	}

	// Rotate both ends. The exchange is one-shot per key, so a rotation must be
	// able to start a new one.
	a.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 0, cluster: upgClusterID})
	b.s.SetAuthProvider(&fakeSyncAuthProvider{key: []byte(second), node: 1, cluster: upgClusterID})
	assertFrameSequence(t, runUpgrade(t, a, b), upgradeFrameSequence)
	if bytes.Equal(a.ac.writeKey, oldKey) {
		t.Fatal("a rotation must re-derive the connection's frame key; keeping the key " +
			"derived from the RETIRED PSK means the rotation revoked nothing on this " +
			"connection (#6628)")
	}
	if !bytes.Equal(a.ac.writeKey, b.ac.readKey) || !bytes.Equal(b.ac.writeKey, a.ac.readKey) {
		t.Fatal("both ends must agree on the re-derived keys")
	}
	if !bytes.Equal(a.ac.authPSK, []byte(second)) {
		t.Fatal("the connection must record the PSK it is now authenticated under, or the " +
			"reconciler cannot tell a later rotation is needed")
	}
	// And the rotated connection still carries traffic under the NEW keys.
	frame := encodeRawMessage(syncMsgSessionV4, []byte("post-rotation"))
	sealed := a.ac.sealFrame(frame)
	hdr := sealed[:syncHeaderSize]
	n := binary.LittleEndian.Uint32(hdr[8:12])
	if err := b.ac.verifyFrame(hdr, sealed[syncHeaderSize:syncHeaderSize+int(n)],
		sealed[syncHeaderSize+int(n):]); err != nil {
		t.Fatalf("a frame sealed after the rotation must verify at the peer: %v", err)
	}
}

// TestAuthUpgradeMessageTypesAreUnique6628 mirrors the #6650/#6629 guards. A
// receiver MISPARSES a known type used for two purposes, so every upgrade frame
// number has to be unique across the whole live set.
func TestAuthUpgradeMessageTypesAreUnique6628(t *testing.T) {
	t.Parallel()
	for _, under := range []struct {
		v    int
		name string
	}{
		{syncMsgAuthUpgradeHello, "syncMsgAuthUpgradeHello"},
		{syncMsgAuthUpgradeProof, "syncMsgAuthUpgradeProof"},
		{syncMsgAuthUpgradeConfirm, "syncMsgAuthUpgradeConfirm"},
		{syncMsgAuthUpgradeRequest, "syncMsgAuthUpgradeRequest"},
	} {
		live := liveSyncMessageTypesExcept(under.v)
		if len(live) < 36 {
			t.Fatalf("the live-type census holds only %d entries — it has fallen behind "+
				"sync.go and can no longer certify uniqueness", len(live))
		}
		for _, m := range live {
			if m.v == under.v {
				t.Fatalf("%s (%d) collides with %s", under.name, under.v, m.name)
			}
		}
	}
}
