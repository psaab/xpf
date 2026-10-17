package config

import (
	"strings"
	"testing"
)

// #14373 (DR4-H1 + folded DR4-H1-ext): the WireGuard key gates were
// shape-only — isWireguardKeyHex checked 64 hex chars and nothing else —
// so degenerate X25519 keys committed clean:
//
//   - an all-zero (or any all-same-byte) local private key clamps to a
//     publicly known scalar, so anyone can complete a handshake as ANY
//     configured peer (Variant B);
//   - an all-zero / small-order peer public key makes every DH output
//     zero or one of a handful of enumerable values, so a remote
//     attacker who knows no secret completes the handshake as that peer
//     (Variant A);
//   - an explicit all-zero / all-same-byte preshared key is a publicly
//     known constant, not a secret.
//
// The fix rejects degenerate keys at commit (strict: error; lenient:
// warning, the #1960 no-brick load posture) and drops the row at the
// Rust hydrate / refuses the peer at engine reconcile, so a
// leniently-loaded degenerate config fails closed in the dataplane too.
//
// Fail-on-revert: deleting the degenerate gate from
// validateOneWireguardTunnel turns every "refused" cell below GREEN
// (the config compiles clean), which is exactly the pre-fix behaviour
// captured as RED on origin/master.

// Fixed random keys (generated once with crypto/rand; NOT repeated-byte
// patterns — a repeated-byte "valid" key is exactly what this gate
// refuses).
var (
	wg14373ValidPriv = "9228c745ba1a1715ff6a7e7f078b4273e5729c3ac050d221da04752d93f58fc2"
	wg14373ValidPeer = "2077fd1510f948a6bb4fac19bd890db6d14f2d73d67f07e8400a59e880a6f8db"
	wg14373ValidPSK  = "d802c9a5b4653cb228ee5ab85724f67762b7d17a810ec09a61bc4520bb2d7973"
)

func wg14373Lines(priv, peer, psk string) []string {
	lines := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + priv,
	}
	peerLine := "set interfaces wg0 tunnel wireguard peer " + peer + " allowed-ips 10.73.0.2/32"
	if psk != "" {
		peerLine += " preshared-key " + psk
	}
	return append(lines, peerLine)
}

// The complete small-order denylist, in WireGuard's little-endian hex
// encoding. Every entry is an F_p-rational Montgomery point of order
// dividing 8 (verified by execution against the Montgomery ladder), so
// X25519(clamped scalar, point) is the all-zero output or enumerable
// over at most 4 values.
var wg14373SmallOrderPeerKeys = []struct {
	name string
	hex  string
}{
	{"u=0 order 2", strings.Repeat("0", 64)},
	{"u=1 order 4", "01" + strings.Repeat("0", 62)},
	{"order 8 (e0eb…b800)", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
	{"order 8 (5f9c…1157)", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"},
	{"u=p-1 order 2 (ecff…7f)", "ec" + strings.Repeat("f", 60) + "7f"},
	{"non-canonical order 2 (edff…7f)", "ed" + strings.Repeat("f", 60) + "7f"},
	{"order 4 twin (eeff…7f)", "ee" + strings.Repeat("f", 60) + "7f"},
}

func TestWireguardDegeneratePrivateKeyRefused14373(t *testing.T) {
	for _, tc := range []struct{ name, priv string }{
		{"all-zero", strings.Repeat("0", 64)},
		{"all-ff", strings.Repeat("f", 64)},
		{"all-aa repeated byte", strings.Repeat("a", 64)},
		{"scalar one (u=1 encoding)", "01" + strings.Repeat("0", 62)},
		{"order-8 encoding as private key", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree4953(t, wg14373Lines(tc.priv, wg14373ValidPeer, "")))
			if err == nil {
				t.Fatalf("strict commit must refuse a degenerate WireGuard private key (%s); it clamps to a publicly known scalar", tc.name)
			}
			if !strings.Contains(err.Error(), "degenerate") {
				t.Errorf("error must name the degenerate key, got: %v", err)
			}
			// The private key is secret: the error must never echo it.
			if strings.Contains(err.Error(), tc.priv) {
				t.Errorf("error must not echo private-key material, got: %v", err)
			}
		})
	}
}

func TestWireguardDegeneratePeerKeyRefused14373(t *testing.T) {
	for _, tc := range wg14373SmallOrderPeerKeys {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree4953(t, wg14373Lines(wg14373ValidPriv, tc.hex, "")))
			if err == nil {
				t.Fatalf("strict commit must refuse small-order peer public key %s; DH against it is zero/enumerable", tc.name)
			}
			if !strings.Contains(err.Error(), "degenerate") {
				t.Errorf("error must name the degenerate key, got: %v", err)
			}
		})
	}
	// An all-same-byte peer key that is not itself small-order (0xFF…FF
	// masks to u=p-1) is still a publicly known constant.
	_, err := CompileConfig(buildTree4953(t, wg14373Lines(wg14373ValidPriv, strings.Repeat("f", 64), "")))
	if err == nil {
		t.Fatal("strict commit must refuse an all-0xFF peer public key (publicly known constant)")
	}
}

func TestWireguardDegeneratePresharedKeyRefused14373(t *testing.T) {
	for _, tc := range []struct{ name, psk string }{
		{"all-zero explicit PSK", strings.Repeat("0", 64)},
		{"all-ff explicit PSK", strings.Repeat("f", 64)},
		{"small-order explicit PSK", "01" + strings.Repeat("0", 62)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree4953(t, wg14373Lines(wg14373ValidPriv, wg14373ValidPeer, tc.psk)))
			if err == nil {
				t.Fatalf("strict commit must refuse a degenerate explicit preshared key (%s); it is a publicly known constant, not a secret", tc.name)
			}
			if !strings.Contains(err.Error(), "degenerate") {
				t.Errorf("error must name the degenerate key, got: %v", err)
			}
			if strings.Contains(err.Error(), tc.psk) {
				t.Errorf("error must not echo preshared-key material, got: %v", err)
			}
		})
	}
}

// The direct validator entry point named by the issue's regression
// criterion, exercised without the config-text layer.
func TestWireguardDegenerateValidatorDirect14373(t *testing.T) {
	base := func() *TunnelConfig {
		return &TunnelConfig{
			WgListenPort:      51820,
			WgLocalPrivkeyHex: Secret(wg14373ValidPriv),
			WgPeers: []WgPeerConfig{{
				PublicKeyHex: wg14373ValidPeer,
				AllowedIPs:   []string{"10.73.0.2/32"},
			}},
		}
	}
	if err := validateOneWireguardTunnel(base()); err != nil {
		t.Fatalf("valid random keys must pass the validator, got: %v", err)
	}
	zeroPriv := base()
	zeroPriv.WgLocalPrivkeyHex = Secret(strings.Repeat("0", 64))
	if err := validateOneWireguardTunnel(zeroPriv); err == nil {
		t.Fatal("all-zero private key must be refused by validateOneWireguardTunnel")
	}
	zeroPeer := base()
	zeroPeer.WgPeers[0].PublicKeyHex = strings.Repeat("0", 64)
	if err := validateOneWireguardTunnel(zeroPeer); err == nil {
		t.Fatal("all-zero peer public key must be refused by validateOneWireguardTunnel")
	}
	zeroPSK := base()
	zeroPSK.WgPeers[0].PresharedKeyHex = Secret(strings.Repeat("0", 64))
	if err := validateOneWireguardTunnel(zeroPSK); err == nil {
		t.Fatal("explicit all-zero preshared key must be refused by validateOneWireguardTunnel")
	}
}

func TestWireguardValidKeysStillCommit14373(t *testing.T) {
	// Valid keys + a real PSK commit clean.
	if _, err := CompileConfig(buildTree4953(t, wg14373Lines(wg14373ValidPriv, wg14373ValidPeer, wg14373ValidPSK))); err != nil {
		t.Fatalf("valid keys with a preshared key must commit, got: %v", err)
	}
	// Absent PSK still means "no PSK" — the degenerate gate must not
	// change that semantics (the all-zero Noise PSK is the protocol's
	// own no-PSK value; only an EXPLICIT degenerate string is refused).
	if _, err := CompileConfig(buildTree4953(t, wg14373Lines(wg14373ValidPriv, wg14373ValidPeer, ""))); err != nil {
		t.Fatalf("valid keys without a preshared key must commit, got: %v", err)
	}
	// Case is not degeneracy: the same key spelled in upper-case hex is
	// the same valid key.
	upper := wg14373Lines(strings.ToUpper(wg14373ValidPriv), strings.ToUpper(wg14373ValidPeer), "")
	if _, err := CompileConfig(buildTree4953(t, upper)); err != nil {
		t.Fatalf("upper-case spelling of valid keys must commit, got: %v", err)
	}
	// A key that merely STARTS with a zero byte is not degenerate.
	almostZero := "00" + strings.Repeat("b7", 31)
	if _, err := CompileConfig(buildTree4953(t, wg14373Lines(almostZero, wg14373ValidPeer, ""))); err != nil {
		t.Fatalf("a key with one leading zero byte must commit, got: %v", err)
	}
}

// The lenient load path keeps the #1960 no-brick posture: a persisted
// degenerate config still LOADS, but the refusal becomes a warning so
// the operator sees why the tunnel will not come up (the Rust hydrate
// drops the row fail-closed).
func TestWireguardDegenerateLenientWarns14373(t *testing.T) {
	tree := buildTree4953(t, wg14373Lines(strings.Repeat("0", 64), wg14373ValidPeer, ""))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not brick on a degenerate key, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "degenerate") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient load must warn about the degenerate private key, warnings: %v", cfg.Warnings)
	}
}
