package snmp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// #5544 — SNMPv3 DES privacy salt must carry the engineBoots prefix
// (RFC 3414 §8.1.1.1).
//
// RFC 3414 §8.1.1.1 RECOMMENDS the DES msgPrivacyParameters be
// snmpEngineBoots(4) || local-integer(4), big-endian, so the DES-CBC IV
// (key-derived preIV XOR salt) is DETERMINISTICALLY unique across a REBOOT: a
// fresh boot advances the high 32 salt bytes no matter where the local
// monotonic counter re-randomizes its start. Before #5544 encryptPDU passed the
// raw 8-byte counter (Agent.nextPrivSalt) verbatim for DES, so salt[0:4] was the
// counter's high bytes, not engineBoots — cross-boot IV uniqueness was only
// probabilistic.
//
// #5544 overlays engineBoots onto salt[0:4] in encryptPDU's DES branch and
// returns THAT salt as privParams (the wire salt MUST equal the IV salt or the
// receiver rebuilds a wrong IV and decodes garbage). The low 32 bits (salt[4:8])
// remain the monotonic counter, so within-boot uniqueness holds for 2^32 PDUs —
// this does NOT reopen #5032 (which was about birthday-bound random salts; the
// counter model is untouched).
//
// The AES path is deliberately UNCHANGED: encryptAES128 already embeds
// engineBoots in its own IV (boots||time||salt), so its returned salt stays the
// raw counter and must NOT be forced to engineBoots.
//
// RED-on-revert: with the boots overlay removed (returning the raw `salt` for
// DES), assertion (1) in TestDESSaltCarriesEngineBoots5544 fails — salt[0:4]
// becomes the monotonic counter's high bytes, not engineBoots.

// newDESPrivAgent builds an agent with one authPriv (SHA / DES) user, a fixed
// engineID, and a controlled engineBoots. Mirrors newAuthPrivAgent but selects
// the DES privacy protocol. Returns the agent and the DES user.
func newDESPrivAgent(t *testing.T, boots int) (*Agent, *usmUser) {
	t.Helper()
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xDE, 0x5A, 0x17, 0x00}
	hashFn, hashLen := authHashFunc("sha")
	authKey := passwordToKey("authpw-des-5544-123456", engineID, hashFn, hashLen)
	privKey := passwordToKey("privpw-des-5544-123456", engineID, hashFn, hashLen)
	a := &Agent{
		engineID:    engineID,
		engineBoots: boots,
		v3Users:     map[string]*usmUser{},
		startTime:   nowMinus(1000),
	}
	user := &usmUser{
		name:      "duser",
		authProto: "sha",
		authKey:   authKey,
		privProto: "des",
		privKey:   privKey,
	}
	a.v3Users["duser"] = user
	return a, user
}

// TestDESSaltCarriesEngineBoots5544 is the fail-on-revert guard for #5544. It
// drives the production encryptPDU DES branch with a known engineBoots and
// asserts the returned privParams (the wire salt): (1) carries engineBoots in
// its high 32 bits, (2) is 8 bytes, (3) a second call keeps the boots prefix
// while advancing the low-32 monotonic counter, and (4) round-trips through
// decryptDES back to the original scopedPDU (IV/salt consistency).
func TestDESSaltCarriesEngineBoots5544(t *testing.T) {
	const boots = 7
	a, user := newDESPrivAgent(t, boots)
	scoped := []byte("scopedPDU-des-salt-boots-5544-roundtrip-check!!")

	enc, salt, err := a.encryptPDU(user, scoped, a.engineTime())
	if err != nil {
		t.Fatalf("encryptPDU(des) error: %v", err)
	}

	// (2) salt is 8 bytes.
	if len(salt) != 8 {
		t.Fatalf("DES privParams must be 8 bytes, got %d", len(salt))
	}
	// (1) engineBoots prefix present in the high 32 bits (RED-on-revert: without
	// the overlay this is the monotonic counter's high bytes, not boots).
	if got := binary.BigEndian.Uint32(salt[0:4]); got != boots {
		t.Fatalf("DES salt[0:4] = %d, want engineBoots = %d "+
			"(RFC 3414 §8.1.1.1 boots prefix missing — #5544 reverted?)", got, boots)
	}
	low1 := binary.BigEndian.Uint32(salt[4:8])

	// (4) round-trip: decryptDES with the RETURNED salt recovers the scopedPDU.
	// encryptDES pads to the DES block size, so the plaintext is a prefix of the
	// decrypted block-aligned buffer.
	dec := decryptDES(user.privKey, salt, enc)
	if dec == nil {
		t.Fatal("decryptDES returned nil (IV/salt inconsistency — wire salt must equal IV salt)")
	}
	if !bytes.HasPrefix(dec, scoped) {
		t.Fatalf("decryptDES round-trip mismatch:\n got  %q\n want prefix %q", dec, scoped)
	}

	// (3) a second encrypt keeps the boots prefix and strictly advances the
	// low-32 monotonic counter.
	_, salt2, err := a.encryptPDU(user, scoped, a.engineTime())
	if err != nil {
		t.Fatalf("encryptPDU(des) second call error: %v", err)
	}
	if got := binary.BigEndian.Uint32(salt2[0:4]); got != boots {
		t.Fatalf("second DES salt[0:4] = %d, want engineBoots = %d", got, boots)
	}
	low2 := binary.BigEndian.Uint32(salt2[4:8])
	if low2 <= low1 {
		t.Fatalf("DES salt low32 not strictly increasing: first=%d second=%d "+
			"(monotonic counter low half broken)", low1, low2)
	}
}

// TestDESvsAESSaltDivergence5544 proves #5544 touched ONLY the DES path. Using a
// deterministic counter seed (injected via the randRead seam so the assertions
// do not depend on crypto/rand), it encrypts under a DES user then an AES user
// on the SAME agent and asserts:
//   - the DES salt's high 32 bits are OVERLAID with engineBoots, and
//   - the AES salt's high 32 bits are NOT — they stay the raw monotonic
//     counter's high bytes (AES gets cross-boot IV uniqueness from its own
//     boots||time||salt IV, so encryptAES128 must remain unchanged).
func TestDESvsAESSaltDivergence5544(t *testing.T) {
	const boots = 7

	// Deterministic seed: high32 = 0x11223344 (!= boots), low32 = 0. nextPrivSalt
	// stores the seed and returns seed+n for the n-th allocation, so the first
	// counter value is 0x1122334400000001 and the second is 0x1122334400000002.
	saved := randRead
	randRead = func(b []byte) (int, error) {
		return copy(b, []byte{0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00}), nil
	}
	defer func() { randRead = saved }()

	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xDE, 0x5A, 0x17, 0x01}
	hashFn, hashLen := authHashFunc("sha")
	authKey := passwordToKey("authpw-div-5544-123456", engineID, hashFn, hashLen)
	privKey := passwordToKey("privpw-div-5544-123456", engineID, hashFn, hashLen)
	a := &Agent{
		engineID:    engineID,
		engineBoots: boots,
		v3Users:     map[string]*usmUser{},
		startTime:   nowMinus(1000),
	}
	desUser := &usmUser{name: "duser", authProto: "sha", authKey: authKey, privProto: "des", privKey: privKey}
	aesUser := &usmUser{name: "auser", authProto: "sha", authKey: authKey, privProto: "aes128", privKey: privKey}
	a.v3Users["duser"] = desUser
	a.v3Users["auser"] = aesUser

	scoped := []byte("divergence scopedPDU bytes")

	// First encrypt: DES. Counter = seed+1 = 0x1122334400000001. The DES branch
	// overlays engineBoots onto the high 32 bits.
	_, desSalt, err := a.encryptPDU(desUser, scoped, a.engineTime())
	if err != nil {
		t.Fatalf("encryptPDU(des): %v", err)
	}
	if got := binary.BigEndian.Uint32(desSalt[0:4]); got != boots {
		t.Fatalf("DES salt[0:4] = %d, want engineBoots = %d", got, boots)
	}
	if got := binary.BigEndian.Uint32(desSalt[4:8]); got != 1 {
		t.Fatalf("DES salt low32 = %d, want 1 (monotonic counter low half)", got)
	}

	// Second encrypt: AES. Counter = seed+2 = 0x1122334400000002. The AES branch
	// returns the counter RAW — salt[0:4] stays the counter's high bytes
	// (0x11223344) and is NOT forced to engineBoots.
	_, aesSalt, err := a.encryptPDU(aesUser, scoped, a.engineTime())
	if err != nil {
		t.Fatalf("encryptPDU(aes): %v", err)
	}
	if got := binary.BigEndian.Uint32(aesSalt[0:4]); got == boots {
		t.Fatalf("AES salt[0:4] must NOT be forced to engineBoots (%d); the AES path "+
			"must stay unchanged — its IV embeds boots separately", boots)
	}
	if got := binary.BigEndian.Uint32(aesSalt[0:4]); got != 0x11223344 {
		t.Fatalf("AES salt[0:4] = %#x, want raw counter high bytes %#x", got, uint32(0x11223344))
	}
	if got := binary.BigEndian.Uint32(aesSalt[4:8]); got != 2 {
		t.Fatalf("AES salt low32 = %d, want 2 (raw counter low half)", got)
	}
}
