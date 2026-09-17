package config

import (
	"strings"
	"testing"
)

const (
	wg9998PrivLower = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	wg9998PrivOther = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	wg9998PeerX     = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	wg9998PeerA     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func wg9998Base() []string {
	return []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wg9998PrivLower,
		"set interfaces wg0 tunnel wireguard peer " + wg9998PeerX + " allowed-ips 10.100.0.0/24",
	}
}

// TestUnitWireguardIdentityOverrideCaseVariantAccepted9998 pins that a unit
// restating the SAME private key in a different hex case is not an identity
// override. Hex is case-insensitive by definition; the override gate compares
// key identity (bytes), not string spelling.
//
// FAIL-ON-REVERT: with the exact `!=` string compare, the upper/mixed
// restatements are falsely rejected at commit.
func TestUnitWireguardIdentityOverrideCaseVariantAccepted9998(t *testing.T) {
	upper := strings.ToUpper(wg9998PrivLower)
	var mixed strings.Builder
	mixed.Grow(len(wg9998PrivLower))
	for i := 0; i < len(wg9998PrivLower); i++ {
		c := wg9998PrivLower[i]
		if i%2 == 0 && c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		mixed.WriteByte(c)
	}
	cases := []struct {
		name   string
		privkey string
	}{
		{name: "upper-case restatement", privkey: upper},
		{name: "mixed-case restatement", privkey: mixed.String()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.privkey == wg9998PrivLower {
				t.Fatalf("fixture is blind: %q equals the stored key, so the case gate is not exercised", tc.name)
			}
			cmds := append(wg9998Base(),
				"set interfaces wg0 unit 1 tunnel wireguard private-key "+tc.privkey,
				"set interfaces wg0 unit 1 tunnel wireguard peer "+wg9998PeerA+" allowed-ips 10.200.1.0/24",
			)
			cfg, err := compileSet(t, cmds)
			if err != nil {
				t.Fatalf("a unit restating the same private key in a different hex case must commit; "+
					"hex is case-insensitive, so %q is the same identity, not an override: %v",
					tc.name, err)
			}
			if cfg == nil {
				t.Fatalf("compile returned nil config without error for %q", tc.name)
			}
		})
	}
}

// TestUnitWireguardIdentityOverrideDifferentKeyStillRejected9998 is the
// over-acceptance guard: a genuinely different private key under an
// interface-level WireGuard tunnel must still be refused, and the diagnostic
// must not echo key material.
func TestUnitWireguardIdentityOverrideDifferentKeyStillRejected9998(t *testing.T) {
	cmds := append(wg9998Base(),
		"set interfaces wg0 unit 1 tunnel wireguard private-key "+wg9998PrivOther,
		"set interfaces wg0 unit 1 tunnel wireguard peer "+wg9998PeerA+" allowed-ips 10.200.1.0/24",
	)
	_, err := compileSet(t, cmds)
	if err == nil {
		t.Fatalf("a unit overriding the WireGuard private-key with a genuinely different key must " +
			"still be refused at commit; the case-insensitive fix must not accept a second identity")
	}
	if !strings.Contains(err.Error(), "private-key") {
		t.Errorf("rejection message does not name %q: %v", "private-key", err)
	}
	for _, secret := range []string{wg9998PrivLower, wg9998PrivOther, strings.ToUpper(wg9998PrivLower)} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("rejection diagnostic leaks private-key material %q: %v", secret[:8]+"...", err)
		}
	}
	if strings.Contains(err.Error(), SecretRedacted) {
		t.Errorf("rejection diagnostic should not need a redaction sentinel: %v", err)
	}
}
