package cluster

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// readAuthedFrame15041 reads one frame from an authenticated connection:
// header||payload||trailer, verifies the trailer under recv, and returns
// type/payload/full-bytes-as-seen-on-the-wire.
func readAuthedFrame15041(t *testing.T, conn net.Conn, recv *authConn) (uint8, []byte, []byte) {
	t.Helper()
	hdr := make([]byte, syncHeaderSize)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	length := binary.LittleEndian.Uint32(hdr[8:12])
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Fatalf("read frame body: %v", err)
		}
	}
	trailer := make([]byte, syncAuthFrameTrailerSize)
	if _, err := io.ReadFull(conn, trailer); err != nil {
		t.Fatalf("read frame trailer: %v", err)
	}
	if err := recv.verifyFrame(hdr, payload, trailer); err != nil {
		t.Fatalf("frame HMAC/replay verification failed: %v", err)
	}
	raw := append(append(append([]byte{}, hdr...), payload...), trailer...)
	return hdr[4], payload, raw
}

// TestConfigKeySuppressionNeverYieldsCleartextOnAuthedConn15041 is the
// #15041 (A24-03) gate. On an AUTHENTICATED (Noise-keyed, same-version)
// connection the config-payload key exchange is an ordinary droppable
// frame: an on-path relay that drops both syncMsgConfigKeyExchange frames
// leaves neither side with a derived AEAD key, and queueConfigOnConn then
// fell back to cleartext syncMsgConfig after the wait — disclosing the
// control-link PSK and every config secret on a link that IS authenticated.
//
// RED on origin/master: the push is sent as syncMsgConfig with the PSK
// readable in the raw frame. GREEN after the fix: an authenticated
// connection derives its config key from the handshake secret (no
// droppable exchange needed), so the push is syncMsgConfigEncrypted and
// the PSK never appears in cleartext, while the receiver still recovers
// the config byte-identically (control half).
func TestConfigKeySuppressionNeverYieldsCleartextOnAuthedConn15041(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	receiver := NewSessionSync(":0", "10.0.0.1:4785", &mockSweepDP{})
	senderConn, receiverConn := net.Pipe()
	defer senderConn.Close()
	defer receiverConn.Close()

	// Both ends authenticated under the same handshake secret, as
	// wrapSyncConn installs after Noise_NNpsk0. The relay drops every
	// ConfigKeyExchange frame, so the ephemeral exchange NEVER completes:
	// no handleConfigKeyExchange call is made on either side.
	frameKey := []byte("15041-handshake-frame-key-32byte")
	sAC := &authConn{Conn: senderConn, readKey: frameKey, writeKey: frameKey}
	rAC := &authConn{Conn: receiverConn, readKey: frameKey, writeKey: frameKey}

	sender.mu.Lock()
	sender.conn0 = sAC
	sender.configCrypto0 = newConfigCryptoState()
	sender.mu.Unlock()
	receiver.mu.Lock()
	receiver.conn0 = rAC
	receiver.configCrypto0 = newConfigCryptoState()
	receiver.mu.Unlock()

	cfg := configWithPSK()
	done := make(chan bool, 1)
	go func() { done <- sender.queueConfigOnConn(sAC, cfg, nil, 1, nil) }()

	if err := receiverConn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	msgType, payload, raw := readAuthedFrame15041(t, receiverConn, rAC)
	if !<-done {
		t.Fatal("config push must succeed (encrypted), not be dropped")
	}
	if msgType != syncMsgConfigEncrypted {
		t.Fatalf("authenticated connection with suppressed key exchange must NOT send "+
			"cleartext: got type %d, want syncMsgConfigEncrypted (%d) (#15041)", msgType, syncMsgConfigEncrypted)
	}
	if strings.Contains(string(raw), testPSK) {
		t.Fatal("the control-link PSK is readable in the frame an on-path relay sees " +
			"after suppressing the key exchange (#15041)")
	}
	// Control: receiver recovers the config byte-identically.
	receiver.handleMessage(rAC, msgType, payload)
	select {
	case item := <-receiver.configApplyCh:
		if item.text != cfg {
			t.Fatalf("decrypted config must be byte-identical.\n got: %q\nwant: %q", item.text, cfg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not enqueue the decrypted config")
	}
	if st := sender.Stats(); st.ConfigsSentCleartext != 0 || st.CleartextSyncAlarmLatched {
		t.Fatalf("an authenticated encrypted send raised cleartext stats: %+v", st)
	}
}

// TestConfigCryptoUnauthenticatedPeerStillFallsBack15041 is the adjacent
// control: a genuinely unauthenticated (legacy/unkeyed) connection keeps
// the #6629 mixed-version cleartext fallback — refusing there would break
// the rolling upgrade this issue must not change.
func TestConfigCryptoUnauthenticatedPeerStillFallsBack15041(t *testing.T) {
	prev := syncConfigKeyWait
	syncConfigKeyWait = 20 * time.Millisecond
	t.Cleanup(func() { syncConfigKeyWait = prev })

	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	senderConn, peerConn := net.Pipe()
	defer senderConn.Close()
	defer peerConn.Close()
	// Plain net.Conn, no authConn keys: unauthenticated.
	sender.mu.Lock()
	sender.conn0 = senderConn
	sender.configCrypto0 = newConfigCryptoState()
	sender.mu.Unlock()

	cfg := configWithPSK()
	done := make(chan bool, 1)
	go func() { done <- sender.queueConfigOnConn(senderConn, cfg, nil, 1, nil) }()
	if err := peerConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	msgType, payload, _ := readOneFrame(t, peerConn)
	if !<-done {
		t.Fatal("unauthenticated fallback push must still be sent")
	}
	if msgType != syncMsgConfig {
		t.Fatalf("unauthenticated peer must keep legacy cleartext type %d, got %d", syncMsgConfig, msgType)
	}
	if text, _ := decodeConfigPayload(payload); text != cfg {
		t.Fatalf("fallback payload must be byte-identical, got %q", text)
	}
}
