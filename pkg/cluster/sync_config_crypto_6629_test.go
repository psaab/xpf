package cluster

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// testPSK is the value that must never be readable on the wire. It is a
// distinctive literal so a substring search over the raw frame is meaningful:
// a partial or transformed leak still contains it, and a false negative would
// need the bytes to be genuinely absent.
const testPSK = "PSK-6629-must-never-cross-in-cleartext"

// configWithPSK is the shape ShowActive() renders: the full active tree,
// unredacted, with the control-link PSK as an ordinary leaf.
func configWithPSK() string {
	return "chassis {\n    cluster {\n        authentication-key \"" + testPSK +
		"\";\n        config-synchronization;\n    }\n}\n"
}

// keyExchangePayload builds the wire form of a syncMsgConfigKeyExchange body.
func keyExchangePayload(pub []byte) []byte {
	out := make([]byte, 0, 1+len(pub))
	out = append(out, syncConfigCryptoVersion)
	return append(out, pub...)
}

// readOneFrame reads a single length-framed sync message off conn and returns
// the message type, the payload, and the COMPLETE frame bytes (header
// included) — the last is what a passive observer on the control segment
// actually sees, so it is what the leak assertion searches.
func readOneFrame(t *testing.T, conn net.Conn) (uint8, []byte, []byte) {
	t.Helper()
	hdr := make([]byte, syncHeaderSize)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := binary.LittleEndian.Uint32(hdr[8:12])
	body := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Fatalf("read frame body: %v", err)
		}
	}
	return hdr[4], body, append(append([]byte{}, hdr...), body...)
}

// completeExchange wires two SessionSyncs' ephemeral states together through
// the REAL handler, exactly as two receive loops would.
func completeExchange(t *testing.T, a *SessionSync, aConn net.Conn, b *SessionSync, bConn net.Conn) {
	t.Helper()
	aState := a.configCryptoForConn(aConn)
	bState := b.configCryptoForConn(bConn)
	if aState == nil || bState == nil {
		t.Fatal("both connections must carry ephemeral state after install")
	}
	a.handleConfigKeyExchange(aConn, keyExchangePayload(bState.pub))
	b.handleConfigKeyExchange(bConn, keyExchangePayload(aState.pub))
}

// TestConfigSyncPayloadDoesNotCarryThePSKInCleartext6629 is the primary gate,
// and it asserts BOTH directions in one trajectory.
//
// POSITIVE: the control-link PSK must not appear anywhere in the bytes a
// passive observer on the control segment sees for a config push.
//
// CONTROL: the standby must still receive that config, intact, PSK included.
// Without the control half an "encryption" that garbled or dropped the payload
// would pass the positive cell trivially — and so would one that simply
// stopped sending the config at all.
//
// FAIL-ON-REVERT: drop the seal in QueueConfig (send syncMsgConfig with the
// plaintext payload) and the positive half reds on the substring search. Break
// the decrypt (open with a different key) and the control half reds on the
// delivered text.
func TestConfigSyncPayloadDoesNotCarryThePSKInCleartext6629(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	receiver := NewSessionSync(":0", "10.0.0.1:4785", &mockSweepDP{})
	senderConn, receiverConn := net.Pipe()
	defer senderConn.Close()
	defer receiverConn.Close()

	sender.mu.Lock()
	sender.conn0 = senderConn
	sender.configCrypto0 = newConfigCryptoState()
	sender.mu.Unlock()
	receiver.mu.Lock()
	receiver.conn0 = receiverConn
	receiver.configCrypto0 = newConfigCryptoState()
	receiver.mu.Unlock()

	completeExchange(t, sender, senderConn, receiver, receiverConn)

	cfg := configWithPSK()
	sent := make(chan struct{}, 1)
	go func() { sender.QueueConfig(cfg); sent <- struct{}{} }()

	if err := receiverConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	msgType, payload, raw := readOneFrame(t, receiverConn)
	<-sent

	if msgType != syncMsgConfigEncrypted {
		t.Fatalf("config push must be sealed: got message type %d, want syncMsgConfigEncrypted (%d). "+
			"An unsealed push puts the control-link PSK on the wire in cleartext, on the very "+
			"link it authenticates (#6629)", msgType, syncMsgConfigEncrypted)
	}
	if strings.Contains(string(raw), testPSK) {
		t.Fatal("the control-link PSK is present in the bytes a passive observer sees for a " +
			"config-sync push (#6629): every subsequent HMAC on this link — heartbeat, fabric " +
			"gRPC bearer token, session-sync frame MAC — is forgeable by anyone who captured it")
	}

	// CONTROL: the standby must still get the real config, PSK and all.
	got := make(chan string, 1)
	receiver.OnConfigReceived = func(text string) error {
		got <- text
		return nil
	}
	receiver.handleMessage(receiverConn, msgType, payload)
	select {
	case item := <-receiver.configApplyCh:
		if item.text != cfg {
			t.Fatalf("the decrypted config must be byte-identical to what was pushed.\n got: %q\nwant: %q",
				item.text, cfg)
		}
		if !strings.Contains(item.text, testPSK) {
			t.Fatal("the decrypted config lost the PSK — config sync must not lose the real " +
				"secret (pkg/configstore/store_format.go); an encryption that drops it trades " +
				"a disclosure for a broken standby")
		}
		if item.gen == 0 {
			t.Fatal("the generation trailer must survive the seal: the plaintext is the " +
				"encodeConfigPayload framing, so gen travels inside the ciphertext")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver did not enqueue the decrypted config")
	}
	if sent := sender.Stats(); sent.ConfigsSentCleartext != 0 || sent.CleartextSyncAlarmLatched {
		t.Fatalf("an encrypted send raised cleartext stats: %+v", sent)
	}
	if received := receiver.Stats(); received.ConfigsReceivedCleartext != 0 ||
		received.CleartextSyncAlarmLatched {
		t.Fatalf("an encrypted receive raised cleartext stats: %+v", received)
	}
}

// TestConfigCryptoMixedVersionFallsBackToCleartext6629 pins the accepted
// fallback and its bound.
//
// A peer that predates #6629 never sends a key exchange. Refusing to push
// would break the rolling upgrade — an unconverged standby is worse than a
// readable payload — so the push proceeds in the clear, exactly as it does
// today. That is "no worse than today", which is the property that made
// payload encryption preferable to excluding the leaf: excluding it would have
// driven an old standby UNKEYED, i.e. fail-open.
//
// The bound matters as much as the fallback: the wait must expire and the push
// must still happen. A fallback that blocked forever would convert a
// confidentiality gap into a config-sync outage.
func TestConfigCryptoMixedVersionFallsBackToCleartext6629(t *testing.T) {
	prev := syncConfigKeyWait
	syncConfigKeyWait = 50 * time.Millisecond
	defer func() { syncConfigKeyWait = prev }()

	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	senderConn, peerConn := net.Pipe()
	defer senderConn.Close()
	defer peerConn.Close()

	sender.mu.Lock()
	sender.conn0 = senderConn
	sender.configCrypto0 = newConfigCryptoState()
	sender.mu.Unlock()

	// No key exchange from the peer — a pre-#6629 build.
	cfg := configWithPSK()
	sent := make(chan struct{}, 1)
	go func() { sender.QueueConfig(cfg); sent <- struct{}{} }()

	if err := peerConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	msgType, payload, _ := readOneFrame(t, peerConn)
	if msgType != syncMsgConfig {
		t.Fatalf("a peer that never negotiated must be sent the legacy cleartext message: "+
			"got type %d, want syncMsgConfig (%d)", msgType, syncMsgConfig)
	}
	text, _ := decodeConfigPayload(payload)
	if text != cfg {
		t.Fatalf("the cleartext fallback must be byte-identical to today's push.\n got: %q\nwant: %q",
			text, cfg)
	}
	<-sent

	// The legacy latch must be armed so the NEXT push does not pay the wait
	// again — a per-push stall on the control path is exactly the kind of
	// shared-socket cost CLAUDE.md forbids adding.
	sender.mu.Lock()
	legacy := sender.configCrypto0.legacy
	sender.mu.Unlock()
	if !legacy {
		t.Fatal("the first expired wait must latch the peer as legacy, so a peer that never " +
			"negotiates costs ONE bounded wait per connection rather than one per push")
	}
	stats := sender.Stats()
	if stats.ConfigsSentCleartext != 1 || !stats.CleartextSyncAlarmLatched {
		t.Fatalf("a successful mixed-version fallback must increment and latch cleartext observability, got %+v",
			stats)
	}
}

// TestConfigCryptoReconnectDerivesFreshKey6629 binds forward secrecy across
// connections: the ephemeral keypair is per CONNECTION, so a key recovered
// later cannot open a capture taken on an earlier one.
//
// The two halves are separated so each has a SINGLE-mutation red. A test that
// disconnected between the installs would need BOTH the install-replaces and
// the disconnect-clears behaviours removed before it changed colour, and a
// compound cell localises nothing.
//
//   - Phase 1/2 supersede the slot WITHOUT a disconnect (installConn on an
//     occupied slot — the real supersession path), so the fresh-key assertions
//     are bound to installConn's replacement alone. Guard it with
//     `if s.configCrypto0 == nil` and this reds.
//   - Phase 3 disconnects and checks the slot is cleared, bound to
//     handleDisconnect's clear alone. Drop that line and this reds.
func TestConfigCryptoReconnectDerivesFreshKey6629(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	peer := newConfigCryptoState()
	if peer == nil {
		t.Fatal("could not generate the peer's ephemeral key")
	}

	install := func() ([]byte, []byte, net.Conn) {
		local, remote := net.Pipe()
		t.Cleanup(func() { local.Close(); remote.Close() })
		s.installConn(0, local)
		s.handleConfigKeyExchange(local, keyExchangePayload(peer.pub))
		s.mu.Lock()
		pub := append([]byte{}, s.configCrypto0.pub...)
		key := append([]byte{}, s.configCrypto0.key...)
		s.mu.Unlock()
		return pub, key, local
	}

	pub1, key1, _ := install()
	pub2, key2, conn2 := install()

	if len(key1) != syncConfigKeyLen || len(key2) != syncConfigKeyLen {
		t.Fatalf("both connections must derive a full-length key (got %d and %d)", len(key1), len(key2))
	}
	if string(pub1) == string(pub2) {
		t.Fatal("installing a connection must produce a FRESH ephemeral keypair; reusing it " +
			"means one compromise opens every capture ever taken on this pair (#6629)")
	}
	if string(key1) == string(key2) {
		t.Fatal("a new connection must derive a DIFFERENT config key; an identical key across " +
			"connections is the absence of forward secrecy, whatever the keypair did")
	}

	// handleDisconnect must drop the state with the connection, or a key
	// outlives the exchange that produced it and a later frame on a stale
	// connection could still be opened.
	s.handleDisconnect(conn2)
	s.mu.Lock()
	residual := s.configCrypto0
	s.mu.Unlock()
	if residual != nil {
		t.Fatal("handleDisconnect must drop the connection's ephemeral state with the connection")
	}
}

// TestConfigCryptoBothEndsDeriveTheSameKey6629 pins the canonical ordering of
// the HKDF salt. Each end sees the two public keys in the opposite order, so
// an implementation that concatenated them as (mine, theirs) would derive two
// different keys and every push would fail to open — a bug that only shows up
// against a real peer, never in a single-sided unit test.
func TestConfigCryptoBothEndsDeriveTheSameKey6629(t *testing.T) {
	a, b := newConfigCryptoState(), newConfigCryptoState()
	if a == nil || b == nil {
		t.Fatal("could not generate ephemeral keys")
	}
	if err := a.deriveConfigKey(b.pub); err != nil {
		t.Fatalf("a.derive: %v", err)
	}
	if err := b.deriveConfigKey(a.pub); err != nil {
		t.Fatalf("b.derive: %v", err)
	}
	if string(a.key) != string(b.key) {
		t.Fatal("both ends must derive the same key: the HKDF salt orders the two public keys " +
			"canonically so neither end needs to know which of them dialled")
	}

	// And the key really is a key: a roundtrip through the AEAD must recover
	// the plaintext, and the ciphertext must not contain it.
	plain := []byte(configWithPSK())
	sealed, err := sealConfigPayload(a.key, plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Contains(string(sealed), testPSK) {
		t.Fatal("the sealed payload still contains the PSK")
	}
	opened, err := openConfigPayload(b.key, sealed)
	if err != nil {
		t.Fatalf("open with the peer's independently-derived key: %v", err)
	}
	if string(opened) != string(plain) {
		t.Fatal("the roundtrip must be lossless")
	}
}

// TestConfigCryptoRejectsSealedPayloadWithNoKey6629: a sealed payload arriving
// on a connection that never negotiated must be DROPPED, not opened with some
// other connection's key and not decoded as cleartext.
//
// Decoding it as cleartext is the dangerous failure: decodeConfigPayload
// accepts any bytes (a payload without the generation magic is treated as
// legacy raw config text), so a ciphertext would sail through as a config and
// be handed to the apply path as garbage.
func TestConfigCryptoRejectsSealedPayloadWithNoKey6629(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	s.mu.Lock()
	s.conn0 = local
	s.configCrypto0 = newConfigCryptoState()
	s.mu.Unlock()

	other := newConfigCryptoState()
	if other == nil {
		t.Fatal("could not generate an unrelated key")
	}
	if err := other.deriveConfigKey(newConfigCryptoState().pub); err != nil {
		t.Fatalf("derive: %v", err)
	}
	sealed, err := sealConfigPayload(other.key, encodeConfigPayload(configWithPSK(), 7))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	s.handleMessage(local, syncMsgConfigEncrypted, sealed)
	select {
	case item := <-s.configApplyCh:
		t.Fatalf("an unopenable sealed payload must be dropped, not enqueued: got %q", item.text)
	default:
	}
}

// TestConfigCryptoDropsUndecryptablePayload6629 covers the OTHER unopenable
// case: the connection DID negotiate a key, but the ciphertext does not open
// under it — a corrupted frame, or one sealed by something that is not the
// peer.
//
// It is a separate test from the no-key case above because the two are guarded
// by different branches, and a single test reaches only the first of them: with
// no key the nil-key guard returns before openConfigPayload is ever called, so
// that test cannot see whether a decrypt FAILURE is handled at all. The
// mutation matrix found exactly that — neutering the decrypt-error branch left
// the no-key test green.
//
// Dropping is the only safe answer. decodeConfigPayload accepts ANY bytes (a
// payload without the generation magic is treated as a legacy sender's raw
// config text), so a ciphertext that reached it would sail through as a
// "config" and be handed to the apply path as garbage.
func TestConfigCryptoDropsUndecryptablePayload6629(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	peer := newConfigCryptoState()
	if peer == nil {
		t.Fatal("could not generate the peer's ephemeral key")
	}
	s.mu.Lock()
	s.conn0 = local
	s.configCrypto0 = newConfigCryptoState()
	s.mu.Unlock()
	s.handleConfigKeyExchange(local, keyExchangePayload(peer.pub))
	if s.configKeyForConn(local) == nil {
		t.Fatal("the exchange must complete, or this test degenerates into the no-key case")
	}

	// Sealed under an unrelated key — a corrupt frame or a forgery.
	stranger := newConfigCryptoState()
	other := newConfigCryptoState()
	if stranger == nil || other == nil {
		t.Fatal("could not generate unrelated keys")
	}
	if err := stranger.deriveConfigKey(other.pub); err != nil {
		t.Fatalf("derive: %v", err)
	}
	sealed, err := sealConfigPayload(stranger.key, encodeConfigPayload(configWithPSK(), 9))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	s.handleMessage(local, syncMsgConfigEncrypted, sealed)
	select {
	case item := <-s.configApplyCh:
		t.Fatalf("a payload that failed to decrypt must be dropped, not decoded as config: "+
			"got %q (gen %d). decodeConfigPayload accepts any bytes, so an un-dropped "+
			"ciphertext reaches the apply path as garbage", item.text, item.gen)
	default:
	}
}

// TestConfigCryptoMessageTypesAreUnique6629 mirrors the #6650 guard for the
// two types this adds. An old peer ignores an UNKNOWN type via the receive
// switch's missing default arm — that is the whole no-version-bump argument —
// but it MISPARSES a known one.
func TestConfigCryptoMessageTypesAreUnique6629(t *testing.T) {
	t.Parallel()
	for _, under := range []struct {
		v    int
		name string
	}{
		{syncMsgConfigKeyExchange, "syncMsgConfigKeyExchange"},
		{syncMsgConfigEncrypted, "syncMsgConfigEncrypted"},
	} {
		live := liveSyncMessageTypesExcept(under.v)
		if len(live) < 34 {
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

// TestConfigKeyExchangeSentOnConnectionInstall6629 binds the SEND WIRING
// behaviourally, by driving the real connection-install path and reading the
// frame off the wire — not by looking for the call in the source.
//
// This is the assertion the rest of the suite cannot make. Every other test
// here drives handleConfigKeyExchange directly, so deleting
// `s.sendConfigKeyExchange(conn)` from handleNewConnection leaves all of them
// green while no pair ever negotiates in production: both ends fall back to
// cleartext, the warning fires on every connection, and #6629 is silently
// reopened with a full green board.
//
// A source-text guard would not do: sourceContainsFlat does not strip
// comments, so a comment naming the call satisfies it.
//
// FAIL-ON-REVERT: delete the sendConfigKeyExchange call from
// handleNewConnection and this reds on the deadline.
func TestConfigKeyExchangeSentOnConnectionInstall6629(t *testing.T) {
	// Unkeyed node: performSyncHandshake returns immediately, so the install
	// path runs with no handshake in the way — which is also exactly the
	// posture of the connection that carries the PSK across during first
	// keying, the one #6629 is about.
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	if !s.beginSetup(srv, true) {
		t.Fatal("beginSetup should admit the first inbound connection")
	}
	go s.handleNewConnection(context.Background(), 0, srv, true)

	if err := cli.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	// The install path emits several advisory frames (clock sync, capabilities,
	// key exchange). Scan for ours rather than pinning the order, which is not
	// the property under test.
	found := false
	for i := 0; i < 8 && !found; i++ {
		msgType, payload, _ := readOneFrame(t, cli)
		if msgType != syncMsgConfigKeyExchange {
			continue
		}
		found = true
		if len(payload) != 1+syncConfigECDHPubSize {
			t.Fatalf("key-exchange payload is %d bytes, want %d (version + X25519 public key)",
				len(payload), 1+syncConfigECDHPubSize)
		}
		if payload[0] != syncConfigCryptoVersion {
			t.Fatalf("key-exchange version byte is %d, want %d", payload[0], syncConfigCryptoVersion)
		}
		// It must be THIS connection's public key, not a fresh or shared one:
		// the peer encrypts to it, and only this connection's private half can
		// open the result. Look it up through the INSTALLED connection —
		// handleNewConnection wraps the raw conn in an *authConn before
		// installConn, and every per-slot lookup (send, receive, push,
		// disconnect) keys off that wrapper.
		s.mu.Lock()
		installed := s.conn0
		s.mu.Unlock()
		st := s.configCryptoForConn(installed)
		if st == nil {
			t.Fatal("the installed connection carries no ephemeral state")
		}
		if string(payload[1:]) != string(st.pub) {
			t.Fatal("the advertised public key is not the installed connection's own; the " +
				"peer would encrypt to a key this connection cannot open")
		}
	}
	if !found {
		t.Fatal("the connection-install path never sent a config-sync key exchange, so no " +
			"pair ever negotiates payload encryption: every config push falls back to " +
			"cleartext and #6629 is reopened with the rest of this suite still green")
	}
}
