package cluster

// Confidentiality for the config-sync payload (#6629).
//
// THE DEFECT. The control-link PSK is an ordinary config leaf
// (`set chassis cluster authentication-key <key>`, compiled to
// `Chassis.Cluster.ControlLinkAuthKey`), and config sync ships the ACTIVE
// CONFIG TEXT: `d.store.ShowActive()` renders through `ConfigTree.Format()`,
// which does not redact, so the PSK crosses the fabric in cleartext inside a
// `syncMsgConfig` payload. Rendered both ways, the key is present in
// `Format()` and absent from `RedactedClone().Format()` — the cleartext render
// is deliberate (pkg/configstore/store_format.go: the Show* siblings back HA
// config sync, the DR archive, persistence and the on-box CLI, "none of which
// may lose the real secret"), and its security consequence was simply never
// followed through.
//
// The exposure is circular. Before the key is introduced, session-sync has no
// local key, so `performSyncHandshake` leaves the connection unauthenticated,
// and committing a key does NOT restart cluster comms — the restart decision
// compares `clusterTransportKey`, which excludes the auth key, pinned by
// TestAuthKeyChangeDoesNotRestartClusterComms_5078. The config-sync message
// that carries the PSK therefore crosses while that established connection is
// still unauthenticated. #6628 may promote it in place when the peer answers,
// but that promotion happens only after the introducing payload crossed. A
// passive observer on the control segment learns the key AT THE MOMENT IT IS
// INTRODUCED, and can then forge the HMACs used by heartbeat, fabric gRPC and
// session-sync. The rollout defeats itself on first use.
//
// WHAT THIS CLOSES, AND WHAT IT DOES NOT.
//
// It closes a PASSIVE observer. The config payload is sealed under a key
// derived from an ephemeral X25519 exchange performed fresh on every
// connection, so a sniffer holding a full capture of the control segment
// recovers nothing, and a capture taken before a later key compromise stays
// unreadable (forward secrecy).
//
// It does NOT stop an ACTIVE man-in-the-middle. The ephemeral exchange on an
// unkeyed link is itself unauthenticated — there is nothing to authenticate it
// WITH, which is the whole point of the bootstrap problem — so an attacker who
// can intercept and rewrite frames can substitute their own public keys and
// read the payload. That concedes nothing that is not already conceded: on an
// unkeyed control segment an active attacker can drive failover, call the
// allowlisted fabric RPCs, and inject sessions today. That is #6611's own
// stated rationale for requiring a key at all. Do not read this file as
// providing a confidential channel; it removes the passive-capture class from
// one message type.
//
// It is deliberately NOT a change to the frame seal. `sealFrame`
// (sync_auth.go) still provides the HMAC and anti-replay for authenticated
// connections, unchanged. This adds confidentiality to ONE message type; it
// does not replace the authentication scheme.
//
// WHY NOT EXCLUDE THE LEAF FROM THE PAYLOAD. Three shipped positions are
// mutually incompatible, and excluding the leaf resolves the knot in the
// direction that can leave a node FAIL-OPEN:
//
//   - #6629 says the PSK must not cross in cleartext.
//   - TestAuthKeyChangeDoesNotRestartClusterComms_5078 pins the opposite of
//     #6628's fix, because the established connection "must carry the key to
//     the read-only secondary".
//   - The session-sync rollout guidance records that an RG0 secondary with the
//     read-only gate armed returns ErrClusterReadOnly, so config-sync is that
//     node's ONLY writer.
//
// `Store.SyncApply` promotes the received tree WHOLESALE and its compile is
// lenient (`compileTreeLenient` -> `lenientClusterAuthKey`), so #6611's
// validator warns rather than rejects on that path: a payload with the leaf
// removed makes the standby's active config LOSE its own key, and every
// control channel there silently reverts to fail-open dual-accept. Worse
// still on a rolling upgrade, where a new primary would drive an old standby
// unkeyed. Payload encryption's mixed-version fallback is "no worse than
// today" instead. Exclusion-plus-provisioning remains the eventual posture,
// but it lands as ONE design with #6628 and #6630 — never alone.
//
// See docs/session-sync-architecture.md and pkg/cluster/README.md.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

const (
	// syncConfigCryptoVersion is the key-exchange wire version. A receiver
	// that does not recognise the version treats the peer as incapable and
	// falls back to cleartext with the warning below, rather than failing the
	// connection: config sync is load-bearing for HA convergence and must
	// never be taken down by an advisory confidentiality layer.
	syncConfigCryptoVersion = 1

	// syncConfigECDHPubSize is the marshalled X25519 public key length.
	syncConfigECDHPubSize = 32

	// syncConfigNonceSize is the AES-GCM nonce length.
	syncConfigNonceSize = 12

	// syncConfigKeyLen is the derived AEAD key length (AES-256).
	syncConfigKeyLen = 32
)

// syncConfigKeyWait bounds how long a config push waits for the peer's
// ephemeral public key before giving up and sending cleartext.
//
// Both ends send their key exchange from installConn, before the
// OnPeerConnected callback that drives the first push is even dispatched, so on
// a new<->new pair the key is already present and this wait never runs. It
// exists for the ordering edge, not the common case. Against a peer that
// predates this it expires once per connection (the legacy latch below then
// suppresses further waits), which costs one bounded stall on the first push
// rather than on every push.
//
// A var, not a const, so a test can exercise the mixed-version fallback
// without spending the real timeout.
var syncConfigKeyWait = 2 * time.Second

// syncConfigKeyInfo is the HKDF info string binding the derived key to this
// purpose. Changing it changes the key, so a peer on a different string
// produces a decrypt failure rather than a silently mismatched key.
const syncConfigKeyInfo = "xpf cluster config-sync payload v1"

// errConfigDecrypt is returned when a sealed config payload cannot be opened.
var errConfigDecrypt = errors.New("cluster sync: config payload decrypt failed")

// configCryptoState is the per-CONNECTION ephemeral key-exchange state for
// config-payload encryption.
//
// It lives per fabric slot, alongside conn0/conn1 and their conn0Gen/conn1Gen
// incarnation stamps, and is guarded by the same SessionSync.mu. installConn
// REPLACES it with a freshly generated keypair on every install and
// handleDisconnect clears the slot's state, so:
//
//   - a reconnect derives a DIFFERENT key (no reuse across connections), and
//   - a key compromised later cannot open a capture taken on an earlier
//     connection.
//
// Both properties are asserted by
// TestConfigCryptoReconnectDerivesFreshKey_6629.
type configCryptoState struct {
	priv *ecdh.PrivateKey
	pub  []byte

	// key is the derived AEAD key, non-nil only once the peer's public key has
	// arrived and the exchange completed.
	key []byte

	// ready is closed when key becomes non-nil. A push waiting for the peer's
	// key selects on it so the common case costs nothing.
	ready chan struct{}

	// legacy latches once a push has already waited out syncConfigKeyWait on
	// this connection, so a peer that never sends a key exchange costs ONE
	// bounded wait per connection rather than one per push.
	legacy bool
}

// newConfigCryptoState generates this connection's ephemeral X25519 keypair.
// A generation failure returns nil, which degrades that connection to
// cleartext with the fallback warning — never to a dropped fabric.
func newConfigCryptoState() *configCryptoState {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("cluster sync: could not generate config-sync ephemeral key; "+
			"config payloads on this connection will be sent in CLEARTEXT (#6629)", "err", err)
		return nil
	}
	return &configCryptoState{
		priv:  priv,
		pub:   priv.PublicKey().Bytes(),
		ready: make(chan struct{}),
	}
}

// deriveConfigKey completes the exchange against the peer's public key.
//
// The HKDF salt is the two public keys in a CANONICAL order (the numerically
// smaller byte string first), so both ends derive the same key without either
// needing to know which of them dialled. Mirrors syncDeriveFrameKey's ordering
// of the handshake nonces.
func (c *configCryptoState) deriveConfigKey(peerPub []byte) error {
	if c == nil || c.priv == nil {
		return errors.New("cluster sync: no local ephemeral key")
	}
	pk, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return fmt.Errorf("cluster sync: bad peer ephemeral key: %w", err)
	}
	shared, err := c.priv.ECDH(pk)
	if err != nil {
		return fmt.Errorf("cluster sync: config-sync ECDH failed: %w", err)
	}
	lo, hi := c.pub, peerPub
	if string(lo) > string(hi) {
		lo, hi = hi, lo
	}
	salt := make([]byte, 0, len(lo)+len(hi))
	salt = append(salt, lo...)
	salt = append(salt, hi...)
	key, err := hkdf.Key(sha256.New, shared, salt, syncConfigKeyInfo, syncConfigKeyLen)
	if err != nil {
		return fmt.Errorf("cluster sync: config-sync HKDF failed: %w", err)
	}
	c.key = key
	return nil
}

// sealConfigPayload encrypts plaintext under key, returning
// {version, nonce, ciphertext||tag}.
func sealConfigPayload(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, syncConfigNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, syncConfigCryptoVersion)
	out = append(out, nonce...)
	// The version byte is authenticated as additional data so a downgrade to a
	// future weaker version cannot be forged onto an existing ciphertext.
	out = aead.Seal(out, nonce, plaintext, out[:1])
	return out, nil
}

// openConfigPayload reverses sealConfigPayload.
func openConfigPayload(key, payload []byte) ([]byte, error) {
	if len(payload) < 1+syncConfigNonceSize {
		return nil, errConfigDecrypt
	}
	if payload[0] != syncConfigCryptoVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", errConfigDecrypt, payload[0])
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := payload[1 : 1+syncConfigNonceSize]
	plaintext, err := aead.Open(nil, nonce, payload[1+syncConfigNonceSize:], payload[:1])
	if err != nil {
		return nil, errConfigDecrypt
	}
	return plaintext, nil
}

// configCryptoForConnLocked returns the ephemeral state belonging to the slot
// that currently holds conn. Nil for a stale connection the slots no longer
// reference — a payload arriving on one is not decryptable and must not be
// opened with another connection's key.
//
// Caller holds s.mu.
func (s *SessionSync) configCryptoForConnLocked(conn net.Conn) *configCryptoState {
	switch {
	case conn != nil && s.conn0 == conn:
		return s.configCrypto0
	case conn != nil && s.conn1 == conn:
		return s.configCrypto1
	}
	return nil
}

// configCryptoForConn is configCryptoForConnLocked with the lock taken.
func (s *SessionSync) configCryptoForConn(conn net.Conn) *configCryptoState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.configCryptoForConnLocked(conn)
}

// configKeyForConn returns the derived AEAD key for conn's connection, or nil
// when the exchange has not completed (or conn is stale). Read under s.mu:
// the key is published by a receive-loop goroutine and consumed by a push on
// the commit path.
func (s *SessionSync) configKeyForConn(conn net.Conn) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.configCryptoForConnLocked(conn)
	if c == nil {
		return nil
	}
	return c.key
}

// sendConfigKeyExchange advertises this connection's ephemeral public key.
// Called once per installed connection, right beside sendCapabilities.
//
// ADDITIVE and version-bump-free on the #2239/#6650 precedent: the receive
// switch has no default arm, so a peer that predates this ignores the frame
// and the sender falls back to cleartext with a warning. Bumping
// SessionSyncWireVersion instead would make the #1930 INC-3 mixed-base gate
// refuse SESSION sync across exactly the rolling upgrade this must survive.
//
// A send failure is logged and NOT escalated to handleDisconnect, matching
// sendCapabilities: dropping a live fabric because an advisory frame did not
// fit would trade a confidentiality gap for a sync outage.
func (s *SessionSync) sendConfigKeyExchange(conn net.Conn) {
	c := s.configCryptoForConn(conn)
	if c == nil || len(c.pub) != syncConfigECDHPubSize {
		return
	}
	payload := make([]byte, 0, 1+syncConfigECDHPubSize)
	payload = append(payload, syncConfigCryptoVersion)
	payload = append(payload, c.pub...)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgConfigKeyExchange, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: failed to send config-sync key exchange; config payloads "+
			"on this connection will be sent in CLEARTEXT (#6629)", "err", err)
	}
}

// handleConfigKeyExchange completes the exchange for the slot that holds conn.
//
// Idempotent per connection: a second key exchange on the same connection is
// IGNORED rather than re-deriving. Re-deriving would let a peer (or an
// on-path attacker who can inject one frame) roll the key of a live connection
// at will, and there is no legitimate reason to: the keypair is per
// connection, and a reconnect installs a fresh one.
func (s *SessionSync) handleConfigKeyExchange(conn net.Conn, payload []byte) {
	if len(payload) < 1+syncConfigECDHPubSize {
		slog.Warn("cluster sync: config-sync key exchange too short", "len", len(payload))
		return
	}
	if payload[0] != syncConfigCryptoVersion {
		slog.Warn("cluster sync: unsupported config-sync key-exchange version; config payloads "+
			"from this node will be sent in CLEARTEXT (#6629)", "version", payload[0])
		return
	}
	peerPub := payload[1 : 1+syncConfigECDHPubSize]
	s.mu.Lock()
	c := s.configCryptoForConnLocked(conn)
	if c == nil || c.key != nil {
		s.mu.Unlock()
		return
	}
	err := c.deriveConfigKey(peerPub)
	ready := c.ready
	derived := c.key != nil
	s.mu.Unlock()
	if err != nil || !derived {
		slog.Warn("cluster sync: config-sync key exchange failed; config payloads on this "+
			"connection will be sent in CLEARTEXT (#6629)", "err", err)
		return
	}
	close(ready)
	slog.Info("cluster sync: config-sync payload encryption negotiated on this connection (#6629)",
		"remote", connRemoteAddrString(conn))
}

// awaitConfigKey returns the AEAD key for conn's connection, waiting up to
// syncConfigKeyWait for the peer's key exchange to land.
//
// It returns nil when the peer does not speak the exchange, which is the
// mixed-version case: the caller then sends cleartext AND WARNS. The warning
// is not decoration. An operator running a mixed-version pair while first
// keying the cluster is standing in precisely the exposed window, and the
// first push on that connection is the moment the information is actionable.
func (s *SessionSync) awaitConfigKey(conn net.Conn) []byte {
	c := s.configCryptoForConn(conn)
	if c == nil {
		return nil
	}
	s.mu.Lock()
	key, ready, legacy := c.key, c.ready, c.legacy
	s.mu.Unlock()
	if key != nil {
		return key
	}
	if legacy {
		return nil
	}
	timer := time.NewTimer(syncConfigKeyWait)
	defer timer.Stop()
	select {
	case <-ready:
	case <-timer.C:
	}
	s.mu.Lock()
	key = c.key
	if key == nil {
		c.legacy = true
	}
	s.mu.Unlock()
	return key
}
