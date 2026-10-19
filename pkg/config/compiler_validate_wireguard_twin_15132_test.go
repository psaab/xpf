package config

import (
	"encoding/hex"
	"strings"
	"testing"
)

// #15132 (A91-06, #14373 residual): the small-order denylist was an
// exact-byte match, so the seven bit-255 twins — each listed key with
// byte 31's top bit set — passed every gate. X25519 masks bit 255 of
// the u-coordinate (RFC 7748), so a twin is the SAME small-order point
// and yields the same all-zero DH secret; only its encoding differs by
// one bit. The gates must compare with byte 31 masked (k[31] &= 0x7f).
//
// Fail-on-revert: removing the mask in isDegenerateWireguardKeyHex
// turns every twin cell below GREEN (the config compiles clean), which
// is exactly the pre-fix behaviour captured as RED on origin/master.

// wg15132Bit255Twin returns the twin of a 64-char hex key: the same key
// with bit 255 (the top bit of byte 31, the LAST byte in WireGuard's
// little-endian encoding — the final hex pair) set.
func wg15132Bit255Twin(t *testing.T, hexKey string) string {
	t.Helper()
	if len(hexKey) != 64 {
		t.Fatalf("twin helper needs a 64-char hex key, got %d chars", len(hexKey))
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatalf("twin helper: %v", err)
	}
	b[31] |= 0x80
	return hex.EncodeToString(b)
}

// The canonical (bit-255-clear) spellings, identical to
// wg14373SmallOrderPeerKeys, plus their bit-255 twins derived here so
// the twin relationship is constructed, not transcribed.
var wg15132CanonicalSmallOrder = []string{
	strings.Repeat("0", 64),
	"01" + strings.Repeat("0", 62),
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	"ec" + strings.Repeat("f", 60) + "7f",
	"ed" + strings.Repeat("f", 60) + "7f",
	"ee" + strings.Repeat("f", 60) + "7f",
}

func TestWireguardBit255TwinPeerKeyRefused15132(t *testing.T) {
	for _, canonical := range wg15132CanonicalSmallOrder {
		twin := wg15132Bit255Twin(t, canonical)
		if twin == canonical {
			t.Fatalf("twin derivation must change the encoding (canonical %s)", canonical)
		}
		if !isDegenerateWireguardKeyHex(canonical) {
			t.Fatalf("canonical small-order key %s must be degenerate (control)", canonical)
		}
		if !isDegenerateWireguardKeyHex(twin) {
			t.Errorf("bit-255 twin %s of small-order key %s must be degenerate; X25519 masks bit 255 so it is the same point (#15132)", twin, canonical)
		}
		_, err := CompileConfig(buildTree4953(t, wg14373Lines(wg14373ValidPriv, twin, "")))
		if err == nil {
			t.Errorf("strict commit must refuse bit-255 twin peer public key %s (twin of %s); DH against it is zero/enumerable (#15132)", twin, canonical)
		} else if !strings.Contains(err.Error(), "degenerate") {
			t.Errorf("error must name the degenerate key, got: %v", err)
		}
		// The twin spelled in upper-case hex is the same key.
		upper := strings.ToUpper(twin)
		if !isDegenerateWireguardKeyHex(upper) {
			t.Errorf("upper-case bit-255 twin %s must be degenerate (#15132)", upper)
		}
	}
}

func TestWireguardBit255TwinPrivAndPSKRefused15132(t *testing.T) {
	// A bit-255 twin as the LOCAL private key: the authored value is a
	// small-order encoding, so the commit gate refuses it like the
	// canonical spelling (the private-key leg of isDegenerateWireguardKeyHex).
	twinPriv := wg15132Bit255Twin(t, "01"+strings.Repeat("0", 62))
	if !isDegenerateWireguardKeyHex(twinPriv) {
		t.Errorf("bit-255 twin private key %s must be degenerate (#15132)", twinPriv)
	}
	_, err := CompileConfig(buildTree4953(t, wg14373Lines(twinPriv, wg14373ValidPeer, "")))
	if err == nil {
		t.Fatal("strict commit must refuse a bit-255 twin private key (#15132)")
	} else if !strings.Contains(err.Error(), "degenerate") {
		t.Errorf("error must name the degenerate key, got: %v", err)
	} else if strings.Contains(err.Error(), twinPriv) {
		t.Errorf("error must not echo private-key material, got: %v", err)
	}

	// A bit-255 twin as an EXPLICIT preshared key.
	twinPSK := wg15132Bit255Twin(t, wg15132CanonicalSmallOrder[3])
	if !isDegenerateWireguardKeyHex(twinPSK) {
		t.Errorf("bit-255 twin preshared key %s must be degenerate (#15132)", twinPSK)
	}
	_, err = CompileConfig(buildTree4953(t, wg14373Lines(wg14373ValidPriv, wg14373ValidPeer, twinPSK)))
	if err == nil {
		t.Fatal("strict commit must refuse a bit-255 twin preshared key (#15132)")
	} else if !strings.Contains(err.Error(), "degenerate") {
		t.Errorf("error must name the degenerate key, got: %v", err)
	} else if strings.Contains(err.Error(), twinPSK) {
		t.Errorf("error must not echo preshared-key material, got: %v", err)
	}
}

func TestWireguardBit255ControlsUnchanged15132(t *testing.T) {
	// Canonical small-order keys stay refused (no regression).
	for _, canonical := range wg15132CanonicalSmallOrder {
		if !isDegenerateWireguardKeyHex(canonical) {
			t.Errorf("canonical small-order key %s must stay degenerate", canonical)
		}
	}
	// Valid random keys keep bit 255 CLEAR in their fixtures; setting
	// bit 255 on a random key yields a DIFFERENT (still non-degenerate)
	// point — masking must not over-refuse legitimate keys whose top
	// bit happens to be set.
	for _, valid := range []string{wg14373ValidPriv, wg14373ValidPeer, wg14373ValidPSK} {
		twin := wg15132Bit255Twin(t, valid)
		if isDegenerateWireguardKeyHex(twin) {
			t.Errorf("bit-255 variant %s of valid key %s must NOT be degenerate; masking compares only against the denylist (#15132)", twin, valid)
		}
		if _, err := CompileConfig(buildTree4953(t, wg14373Lines(wg14373ValidPriv, twin, ""))); err != nil {
			t.Errorf("bit-255 variant of a valid peer key must commit, got: %v", err)
		}
	}
	// A repeated-byte key whose masked form is NOT small-order (0xAB…)
	// is still refused by the repeated-byte leg, unchanged.
	if !isDegenerateWireguardKeyHex(strings.Repeat("ab", 32)) {
		t.Error("repeated-byte key must stay degenerate via the repeated-byte leg")
	}
	// Near-miss: flip a LOW bit of a canonical key — a genuinely
	// different point, must not be refused by the small-order leg.
	nearMiss := "02" + strings.Repeat("0", 62)
	if isDegenerateWireguardKeyHex(nearMiss) {
		t.Errorf("near-miss key %s (u=2) must not be degenerate", nearMiss)
	}
}
