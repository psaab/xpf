package cluster

import (
	"context"
	"crypto/rand"
	"net"
	"testing"

	"github.com/flynn/noise"
	"time"
)

// TestSyncHandshakeTimeoutIsShort pins the #4370 bound: the setup handshake
// timeout must stay short (the keyed Noise exchange completes in milliseconds;
// a longer bound only extends how long a hung/absent peer ties up a
// per-connection handshake goroutine and eats into the 5s Stop budget). RED on
// revert to the original 10s.
func TestSyncHandshakeTimeoutIsShort(t *testing.T) {
	if syncHandshakeTimeout < 1*time.Second || syncHandshakeTimeout > 3*time.Second {
		t.Fatalf("syncHandshakeTimeout = %v, want a short accept-loop bound in [1s, 3s] (#4370)", syncHandshakeTimeout)
	}
}

// TestAcceptLoopHandshakeDoesNotBlockOthers verifies the #4370 fix: a
// slow/hung auth handshake on one accepted connection does NOT stall the accept
// loop from accepting and handshaking OTHER connections.
//
// Client A connects and stalls before sending Noise msg1, leaving the server
// blocked in A's handshake read. Client B then connects. With the
// per-connection goroutine, the accept loop keeps accepting, so B receives the
// server's Noise msg2 within milliseconds. RED on revert: the synchronous
// accept loop is parked inside A's handshake for the full syncHandshakeTimeout,
// so B is never accepted and B's read times out.
func TestAcceptLoopHandshakeDoesNotBlockOthers(t *testing.T) {
	key := []byte("shared-control-link-secret-key")
	s := newAuthSync(t, key)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.acceptLoop(ctx, ln, 0)

	// #7163 INVERTED THE OPENING TURN, and the test follows it rather than
	// working around it. Under Noise the accepter is the RESPONDER: it speaks
	// only after reading the initiator's msg1. So the way a client parks the
	// server's handshake is to connect and say NOTHING — which is the truer
	// form of this hazard anyway, since a silent client is what a stalled or
	// hostile peer actually looks like.
	//
	// Client A: connect and stall by silence. The server is now parked reading
	// A's msg1 for the full syncHandshakeTimeout.
	connA, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.Close()

	// Client B: connect after the server is committed to A. The accept loop must
	// still accept B and start its handshake promptly.
	connB, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer connB.Close()
	if err := connB.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("B set deadline: %v", err)
	}
	start := time.Now()
	// B plays the initiator with the REAL PSK and the server's role-ordered
	// prologue (server is node 0 and the responder, so the initiator is node 1).
	//
	// Both are required, and a first draft of this test got it wrong in an
	// instructive way: under psk0 the FIRST message already carries a tag, so a
	// wrong PSK is refused at msg1 and the server closes — which reads as
	// "the accept loop stalled" when it actually means "B was rejected". The
	// property under test is that the server ANSWERS PROMPTLY while A's
	// handshake is parked, so B has to get far enough to be answered.
	bhs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           syncNoiseCipherSuite,
		Pattern:               noise.HandshakeNN,
		Initiator:             true,
		Prologue:              syncNoisePrologue(syncNoisePhaseConnect, 22, 1, 0, 0),
		PresharedKey:          syncNoisePSK(key),
		PresharedKeyPlacement: 0,
		Random:                rand.Reader,
	})
	if err != nil {
		t.Fatalf("B handshake init: %v", err)
	}
	msg1, _, _, err := bhs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("B msg1: %v", err)
	}
	if err := writeMsg(connB, syncMsgAuthHello, msg1); err != nil {
		t.Fatalf("B failed to send msg1: %v", err)
	}
	typ, _, err := readSyncFrameRaw(connB)
	if err != nil {
		t.Fatalf("B did not receive the server's reply while A's handshake was in flight "+
			"(accept loop stalled on A?): %v", err)
	}
	if typ != syncMsgAuthProof {
		t.Fatalf("B: expected the server's noise msg2 (type %d), got %d", syncMsgAuthProof, typ)
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("B's handshake started too late (%v) — accept loop appears serialized on A", elapsed)
	}
}

// TestConnectDialerIsTheNoiseInitiator7163 binds a CALL SITE that no other test
// in this package reaches.
//
// Role is structural in the Noise pattern, so it has to be supplied, and the
// only source the peer cannot assert is the TRANSPORT: fabricConnectLoop passes
// initiator=true because it DIALED, and the accept path passes false because it
// ACCEPTED. Every other test here hands performSyncHandshake that boolean by
// hand, so flipping the argument at the dial site leaves all of them green while
// no real connection authenticates at all — both ends would take the same half
// of the pattern and each would sit waiting for the other to speak.
//
// The accept site is already bound, by TestAcceptLoopHandshakeDoesNotBlockOthers
// above: it requires the server's FIRST frame to be a Proof written in answer to
// a client msg1, which an accepter that thought it was the initiator could not
// produce. This is the other half.
//
// The assertion is on the first bytes the dialer puts on the wire, against a
// bare listener rather than a peer SessionSync, so it is deterministic: no
// runtime, no bulk sync, no second state machine to settle.
//
// FAIL-ON-REVERT: pass false at the fabricConnectLoop call site and the dialer
// waits to READ instead of writing; this reds on the read deadline.
func TestConnectDialerIsTheNoiseInitiator7163(t *testing.T) {
	key := []byte("connect-role-wiring-psk-7163")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	s := newAuthSyncNode(t, key, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.fabricConnectLoop(ctx, 0, ln.Addr().String())

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	typ, payload, err := readSyncFrameRaw(conn)
	if err != nil {
		t.Fatalf("the DIALER must open the exchange — it is the Noise initiator because "+
			"it dialled — but it wrote nothing: %v. A dial site that passes "+
			"initiator=false makes both ends responders, and every session-sync "+
			"connection in the cluster then waits for a peer that is also waiting.", err)
	}
	if typ != syncMsgAuthHello {
		t.Fatalf("the dialer's first frame is type %d, want syncMsgAuthHello (%d)",
			typ, syncMsgAuthHello)
	}
	// 32-byte X25519 ephemeral + a 16-byte Poly1305 tag: psk0 encrypts the
	// first message's (empty) payload, which is what lets the responder
	// authenticate the initiator before it answers.
	if len(payload) != 48 {
		t.Fatalf("the dialer's msg1 is %d bytes, want 48 (32-byte ephemeral + 16-byte "+
			"tag). A msg1 with no tag would carry no proof of PSK possession.",
			len(payload))
	}
}
