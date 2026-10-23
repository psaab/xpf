package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15991 (+ fold, loader semantics): an `ascii-text` PSK that
// literally reads `0x<hex digits>` must reach charon as its literal
// ASCII bytes. Two defects stacked: (1) the renderer discarded
// provenance — the lone-value emission treated any `0x`-prefixed
// string as a hex key and rendered it unquoted, and the grouped fold
// collapsed an ASCII `0x<digits>` with a hexadecimal `<digits>`
// member; (2) quoting does NOT protect the value: swanctl's loader
// (strongSwan 6.1.0 load_creds.c load_secret) strips the settings
// quotes, then hex-decodes ANY value with a `0x` prefix (either
// case) and base64-decodes any `0s` value before the VICI
// load-shared call — verified live against charon 6.1.0 in a
// two-daemon lab (docs/log/15991.md), where quoted `"0x61626364"`
// authenticated against the hex-decoded bytes, not the literal
// string. The fix therefore keeps {value, hex} provenance through
// the fold AND emits a loader-facing token: hex stays `0x<hex>`,
// a colliding ASCII value (`0x`/`0X`/`0s`/`0S` prefix) is
// base64-armored as `0s<base64 of the literal bytes>` so charon
// base64-decodes it back to exactly the authored string, and any
// other ASCII value renders as itself.
//
// FAIL-ON-REVERT: restoring either the string-prefix emission or
// the merely-quoted render (`secret = "0x61626364"`) makes the
// ascii-0x cells below go RED — the quoted form still hex-decodes
// at load, so the token assertions are the decisive check.

func asciiHexFixture15991(vpns map[string]*config.IPsecVPN, gateways map[string]*config.IPsecGateway) *config.IPsecConfig {
	return &config.IPsecConfig{
		VPNs: vpns,
		IKEProposals: map[string]*config.IKEProposal{
			"ike-psk": {
				Name: "ike-psk", AuthMethod: "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol": {Name: "pol", Proposals: []string{"ike-psk"}},
		},
		Gateways: gateways,
	}
}

func TestASCIIHexPrefixedPSK15991(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("lone ascii 0x is base64-armored, lone hex renders raw", func(t *testing.T) {
		cfg := asciiHexFixture15991(
			map[string]*config.IPsecVPN{
				"ascii-0x": {Gateway: "gw-a", PSK: config.NewSecret("0x61626364")},
				"hex":      {Gateway: "gw-b", PSK: config.NewSecret("61626364"), PSKHex: true},
				// Uppercase + base64-prefix controls: strcasepfx is
				// case-insensitive, so both collide at load too.
				"ascii-0X": {Gateway: "gw-c", PSK: config.NewSecret("0X61626364")},
				"ascii-0s": {Gateway: "gw-d", PSK: config.NewSecret("0sQUJD")},
			},
			map[string]*config.IPsecGateway{
				"gw-a": {Name: "gw-a", Address: "203.0.113.1", IKEPolicy: "pol"},
				"gw-b": {Name: "gw-b", Address: "203.0.113.2", IKEPolicy: "pol"},
				"gw-c": {Name: "gw-c", Address: "203.0.113.3", IKEPolicy: "pol"},
				"gw-d": {Name: "gw-d", Address: "203.0.113.4", IKEPolicy: "pol"},
			})
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] || !rendered["gw-b"] || !rendered["gw-c"] || !rendered["gw-d"] {
			t.Fatalf("all VPNs must render, rendered=%v:\n%s", rendered, text)
		}
		doc := parseSwanctlDoc(t, text)
		// base64("0x61626364") = MHg2MTYyNjM2NA== — charon
		// base64-decodes the 0s token back to the literal string.
		// A merely quoted "0x61626364" would hex-decode at load.
		doc.at(t, "secrets", "ike-gw-a").requireSetting(t, "secret", `"0sMHg2MTYyNjM2NA=="`)
		// Hex control (#15027): unquoted raw bytes, unchanged.
		doc.at(t, "secrets", "ike-gw-b").requireSetting(t, "secret", "0x61626364")
		doc.at(t, "secrets", "ike-gw-c").requireSetting(t, "secret", `"0sMFg2MTYyNjM2NA=="`)
		doc.at(t, "secrets", "ike-gw-d").requireSetting(t, "secret", `"0sMHNRVUpE"`)
	})

	t.Run("policy-fallback ascii 0x is base64-armored", func(t *testing.T) {
		cfg := asciiHexFixture15991(
			map[string]*config.IPsecVPN{
				"site": {Gateway: "gw-a"},
			},
			map[string]*config.IPsecGateway{
				"gw-a": {Name: "gw-a", Address: "203.0.113.1", IKEPolicy: "pol"},
			})
		cfg.IKEPolicies["pol"].PSK = config.NewSecret("0x61626364")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] {
			t.Fatalf("policy-fallback VPN must render:\n%s", text)
		}
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw-a").requireSetting(t, "secret", `"0sMHg2MTYyNjM2NA=="`)
	})

	t.Run("grouped ascii 0x and hex same digits stay distinct", func(t *testing.T) {
		cfg := asciiHexFixture15991(
			map[string]*config.IPsecVPN{
				"ascii-0x": {Gateway: "gw", PSK: config.NewSecret("0x61626364")},
				"hex":      {Gateway: "gw", PSK: config.NewSecret("61626364"), PSKHex: true},
			},
			map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "pol"},
			})
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		// Both credentials survive as distinct comma elements (sorted
		// member order, ascii-0x first): the ASCII member armored, the
		// hex member as its 0x token. Pre-fix these collapsed to one
		// raw-hex token (or, armored wrongly, would hex-decode at load).
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw").requireSetting(t, "secret", `"0sMHg2MTYyNjM2NA==,0x61626364"`)
	})

	t.Run("grouped identical ascii 0x dedupes, ascii 0x plus plain", func(t *testing.T) {
		cfg := asciiHexFixture15991(
			map[string]*config.IPsecVPN{
				"a1":    {Gateway: "gw", PSK: config.NewSecret("0x61626364")},
				"a2":    {Gateway: "gw", PSK: config.NewSecret("0x61626364")},
				"plain": {Gateway: "gw", PSK: config.NewSecret("other")},
			},
			map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "pol"},
			})
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw").requireSetting(t, "secret", `"0sMHg2MTYyNjM2NA==,other"`)
	})

	t.Run("grouped plain members unchanged", func(t *testing.T) {
		cfg := asciiHexFixture15991(
			map[string]*config.IPsecVPN{
				"a1": {Gateway: "gw", PSK: config.NewSecret("secret-one")},
				"a2": {Gateway: "gw", PSK: config.NewSecret("secret-two")},
			},
			map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "pol"},
			})
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		// Byte-identical to the pre-#15991 grouped render.
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw").requireSetting(t, "secret", `"secret-one,secret-two"`)
	})

	t.Run("lone 0x with non-hex tail is base64-armored", func(t *testing.T) {
		cfg := asciiHexFixture15991(
			map[string]*config.IPsecVPN{
				"ascii-0x": {Gateway: "gw-a", PSK: config.NewSecret("0xzzzz")},
			},
			map[string]*config.IPsecGateway{
				"gw-a": {Name: "gw-a", Address: "203.0.113.1", IKEPolicy: "pol"},
			})
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		// Bare or merely quoted, "0xzzzz" would fail chunk_from_hex
		// at load (empty secret); armored it loads as the literal
		// string. base64("0xzzzz") = MHh6enp6.
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw-a").requireSetting(t, "secret", `"0sMHh6enp6"`)
	})

	t.Run("collision predicate boundaries", func(t *testing.T) {
		for _, tc := range []struct {
			v    string
			want bool
		}{
			{"0x61626364", true}, {"0X61626364", true}, {"0sQUJD", true}, {"0SQUJD", true},
			{"0x", true}, {"0s", true},
			{"0", false}, {"", false}, {"00x1", false}, {"x0x1", false}, {"secret", false}, {" 0x1", false},
		} {
			if got := asciiValueCollidesWithSwanctlEncoding(tc.v); got != tc.want {
				t.Errorf("asciiValueCollidesWithSwanctlEncoding(%q) = %v, want %v", tc.v, got, tc.want)
			}
		}
		if got := swanctlSecretToken(pskValue{value: "0x61626364", hex: true}); got != "0x0x61626364" {
			t.Errorf("hex token must prefix verbatim, got %q", got)
		}
	})
}

// End-to-end through the real compiler: `ascii-text 0x61626364` keeps
// PSKHex=false and renders base64-armored so charon loads the literal
// string — the exact authored spelling #15991 names (mirrors
// TestPSKHexadecimalEndToEnd15027 for the hex leg).
func TestASCIIHexPrefixedPSKEndToEnd15991(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set security ike proposal p1 authentication-method pre-shared-keys",
		"set security ike proposal p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal p1 authentication-algorithm sha-256",
		"set security ike proposal p1 dh-group group14",
		"set security ike policy pol proposals p1",
		"set security ike policy pol pre-shared-key ascii-text 0x61626364",
		"set security ike gateway gw1 ike-policy pol",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ipsec proposal esp1 protocol esp",
		"set security ipsec proposal esp1 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp1 authentication-algorithm hmac-sha-256-128",
		"set security ipsec policy ipol proposals esp1",
		"set security ipsec vpn v1 ike gateway gw1",
		"set security ipsec vpn v1 ike ipsec-policy ipol",
		"set security ipsec vpn v1 bind-interface st0.0",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if pol := cfg.Security.IPsec.IKEPolicies["pol"]; pol == nil || pol.PSK.Reveal() != "0x61626364" || pol.PSKHex {
		t.Fatalf("ascii-text 0x… must compile unflagged, got %+v", pol)
	}
	text, rendered, err := (&Manager{}).renderConfig(&cfg.Security.IPsec)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if !rendered["gw1"] {
		t.Fatalf("ascii 0x VPN must render:\n%s", text)
	}
	parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw1").requireSetting(t, "secret", `"0sMHg2MTYyNjM2NA=="`)
}
