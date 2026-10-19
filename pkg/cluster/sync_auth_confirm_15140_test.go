package cluster

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// #15140 (B04-01): a passively captured Noise_NNpsk0 msg1 replays forever.
//
// Under NNpsk0, msg1 is AEAD-tagged only over the prologue and the
// initiator's ephemeral — neither changes on a replay — so a captured
// 60-byte syncMsgAuthHello re-verifies at a FRESH responder connection
// with NO PSK. Before the fix the responder wrote msg2, split keys,
// recordAuthenticatedPeer() fired, and handleNewConnection installed the
// connection (closing the legitimate conn in the slot), sent clock-sync /
// capabilities / config-key-exchange, and drove a cold-prime bulk the
// attacker could read. The fix adds a mandatory initiator key-confirmation
// (syncMsgAuthConfirm, #15140) sealed under the i2r key over the channel
// binding: the responder returns a PENDING result after msg2 and only
// promotes to authenticated after a valid confirm; a replayed msg1's
// attacker never holds the ephemeral private key, so Split yields keys
// nobody can confirm under and the connection is never installed.

type confirmRecorder15140 struct {
	fakeSyncAuthProvider
	authenticated atomic.Int32
}

func (r *confirmRecorder15140) noteSyncPeerAuthenticated() { r.authenticated.Add(1) }

func newConfirmSync15140(t *testing.T, key []byte, node int) (*SessionSync, *confirmRecorder15140) {
	t.Helper()
	s := NewSessionSync(":0", ":0", nil)
	rec := &confirmRecorder15140{fakeSyncAuthProvider: fakeSyncAuthProvider{key: key, node: node, cluster: 22}}
	s.SetAuthProvider(rec)
	return s, rec
}

// captureMsg1_15140 runs a legitimate initiator far enough to emit its
// msg1 frame and returns the exact framed bytes a passive observer would
// capture, then abandons that initiator (its ephemeral private key is
// discarded with the handshake state, exactly as after a real exchange).
func captureMsg1_15140(t *testing.T, key []byte) (frame []byte, typ uint8, payload []byte) {
	t.Helper()
	init := newAuthSyncNode(t, key, 0)
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = init.performNoiseHandshake(ca, key, true, 0)
	}()
	typ, payload, err := readSyncFrameRaw(cb)
	if err != nil {
		t.Fatalf("capture msg1: %v", err)
	}
	if typ != syncMsgAuthHello {
		t.Fatalf("captured frame type = %d, want syncMsgAuthHello (%d)", typ, syncMsgAuthHello)
	}
	frame = encodeRawMessage(typ, payload)
	ca.Close()
	cb.Close()
	<-done
	return frame, typ, payload
}

// TestReplayedMsg1NeverInstalled15140 is the headline #15140 regression.
//
// A PSK-less attacker replays a byte-identical captured msg1 on a fresh
// connection to a keyed responder that already holds a legitimate
// installed connection. The replay must never reach installConn, never
// close/displace the existing connection, never record an authenticated
// peer, and the attacker must read nothing beyond msg2.
//
// RED on current origin/master: performSyncHandshake returns
// authenticated after msg2 alone, so handleNewConnection installs the
// replayed connection and closes the legitimate one.
func TestReplayedMsg1NeverInstalled15140(t *testing.T) {
	key := []byte("shared-control-link-secret-15140")
	_, msg1Typ, msg1Payload := captureMsg1_15140(t, key)
	_ = msg1Typ

	resp, rec := newConfirmSync15140(t, key, 1)

	// Pre-existing legitimate connection in fabric 0.
	legitLocal, legitPeer := net.Pipe()
	defer legitPeer.Close()
	resp.installConn(0, legitLocal)

	// Attacker: fresh pipe, replays the captured msg1 byte-identically,
	// receives msg2 (that much is unavoidable and harmless), then stays
	// SILENT — it cannot produce the key confirmation.
	atkSrv, atkCli := net.Pipe()
	defer atkCli.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp.handleNewConnection(ctx, 0, atkSrv, false)
	}()

	if err := writeMsg(atkCli, syncMsgAuthHello, msg1Payload); err != nil {
		t.Fatalf("attacker replay write: %v", err)
	}
	// Attacker reads msg2 — the only bytes it may ever obtain.
	atkCli.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ2, _, err := readSyncFrameRaw(atkCli)
	if err != nil {
		t.Fatalf("attacker must receive msg2 before the confirm gate: %v", err)
	}
	if typ2 != syncMsgAuthProof {
		t.Fatalf("attacker second frame type = %d, want syncMsgAuthProof (%d)", typ2, syncMsgAuthProof)
	}
	// Now silent. The responder must time out the confirmation and drop
	// the connection WITHOUT installing it.
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("handleNewConnection did not return after silent post-msg2 peer (confirm must time out and drop)")
	}

	resp.mu.Lock()
	installed := resp.conn0
	resp.mu.Unlock()
	if installed != net.Conn(legitLocal) {
		t.Fatalf("replayed msg1 displaced the legitimate connection: installed=%v want the pre-existing conn; "+
			"a byte-identical replay must never reach installConn (#15140)", installed)
	}
	// The legitimate connection must not have been closed by supersession.
	legitPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := legitPeer.Read(buf); err == nil {
		t.Fatal("unexpected byte on legitimate peer pipe")
	}
	if got := rec.authenticated.Load(); got != 0 {
		t.Fatalf("recordAuthenticatedPeer fired %d times for a silent replay; want 0 before key confirmation (#15140)", got)
	}
	// Attacker reads nothing beyond msg2: the server end must be closed.
	atkCli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := readSyncFrameRaw(atkCli); err == nil {
		t.Fatal("attacker received a frame beyond msg2 on a silent replay; want connection dropped")
	}
}

// TestSilentPostMsg2PeerNeverAuthenticated15140 pins the pending-state
// unit property: after msg2 alone (no confirm) the responder handshake
// must NOT report authenticated and must NOT have recorded the peer.
func TestSilentPostMsg2PeerNeverAuthenticated15140(t *testing.T) {
	key := []byte("shared-control-link-secret-15140")
	resp, rec := newConfirmSync15140(t, key, 1)

	_, _, msg1Payload := captureMsg1_15140(t, key)

	srv, cli := net.Pipe()
	defer cli.Close()
	resCh := make(chan handshakeResult, 1)
	go func() {
		mode, keys, err := resp.performSyncHandshake(srv, false, 0)
		resCh <- handshakeResult{mode: mode, key: keys, err: err}
	}()
	if err := writeMsg(cli, syncMsgAuthHello, msg1Payload); err != nil {
		t.Fatalf("replay write: %v", err)
	}
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ2, _, err := readSyncFrameRaw(cli)
	if err != nil || typ2 != syncMsgAuthProof {
		t.Fatalf("expected msg2, typ=%d err=%v", typ2, err)
	}
	// Silent: no confirm. Handshake must fail, not authenticate.
	select {
	case r := <-resCh:
		if r.err == nil {
			t.Fatalf("silent post-msg2 peer authenticated (mode=%d); a replayed msg1 must never complete the responder handshake (#15140)", r.mode)
		}
		if r.mode == syncAuthAuthenticated {
			t.Fatalf("silent peer reported authenticated mode")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("responder handshake did not fail for silent post-msg2 peer")
	}
	if got := rec.authenticated.Load(); got != 0 {
		t.Fatalf("recordAuthenticatedPeer fired %d times before confirmation; want 0 (#15140)", got)
	}
}

// TestLegitimatePairStillConnects15140 is the control: a genuine keyed
// pair completes msg1/msg2/confirm and both ends authenticate with
// complementary directional keys, and the authenticated recorder fires
// exactly once per end.
func TestLegitimatePairStillConnects15140(t *testing.T) {
	key := []byte("shared-control-link-secret-15140")
	a, recA := newConfirmSync15140(t, key, 0)
	b, recB := newConfirmSync15140(t, key, 1)

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	ach := runHandshake(a, ca, true)
	bch := runHandshake(b, cb, false)
	ar, br := <-ach, <-bch
	if ar.err != nil || br.err != nil {
		t.Fatalf("legitimate pair must connect after #15140 confirm: a=%v b=%v", ar.err, br.err)
	}
	if ar.mode != syncAuthAuthenticated || br.mode != syncAuthAuthenticated {
		t.Fatalf("legitimate pair modes = %d/%d, want authenticated", ar.mode, br.mode)
	}
	if len(ar.key.writeKey) == 0 || len(br.key.writeKey) == 0 {
		t.Fatal("legitimate pair derived empty frame keys")
	}
	// Directional agreement (same assertion as #7163 happy path).
	if string(ar.key.writeKey) != string(br.key.readKey) || string(ar.key.readKey) != string(br.key.writeKey) {
		t.Fatal("directional keys disagree across legitimate pair")
	}
	if recA.authenticated.Load() != 1 || recB.authenticated.Load() != 1 {
		t.Fatalf("authenticated recorder = %d/%d, want 1/1 after confirm", recA.authenticated.Load(), recB.authenticated.Load())
	}
}

// TestForgedConfirmRejected15140: a confirm sealed under a wrong key (or
// replayed from another exchange) must be rejected and not authenticate.
func TestForgedConfirmRejected15140(t *testing.T) {
	key := []byte("shared-control-link-secret-15140")
	resp, rec := newConfirmSync15140(t, key, 1)

	// Real initiator to obtain a genuine msg2/binding context? The
	// attacker path is simpler: replay msg1, read msg2, then send a
	// garbage confirm. The responder's pending check must reject it.
	_, _, msg1Payload := captureMsg1_15140(t, key)
	srv, cli := net.Pipe()
	defer cli.Close()
	resCh := make(chan handshakeResult, 1)
	go func() {
		mode, keys, err := resp.performSyncHandshake(srv, false, 0)
		resCh <- handshakeResult{mode: mode, key: keys, err: err}
	}()
	if err := writeMsg(cli, syncMsgAuthHello, msg1Payload); err != nil {
		t.Fatalf("replay write: %v", err)
	}
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if typ2, _, err := readSyncFrameRaw(cli); err != nil || typ2 != syncMsgAuthProof {
		t.Fatalf("expected msg2, typ=%d err=%v", typ2, err)
	}
	// Forged confirm: correct shape, wrong MAC bytes.
	forged := make([]byte, 32)
	for i := range forged {
		forged[i] = 0xAB
	}
	// On the pre-fix tree the responder already returned after msg2, so
	// this write may block/time out — that timeout itself proves there
	// was no confirm gate. Ignore the write error and assert on outcome.
	cli.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = writeMsg(cli, syncMsgAuthConfirm, forged)
	select {
	case r := <-resCh:
		if r.err == nil || r.mode == syncAuthAuthenticated {
			t.Fatalf("forged confirm authenticated (mode=%d err=%v); want rejection (#15140)", r.mode, r.err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("responder did not reject forged confirm")
	}
	if got := rec.authenticated.Load(); got != 0 {
		t.Fatalf("recordAuthenticatedPeer fired for forged confirm; want 0")
	}
}
