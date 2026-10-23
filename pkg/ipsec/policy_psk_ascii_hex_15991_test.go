package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15991: an `ascii-text` PSK that literally reads `0x<hex digits>` loses
// its ASCII provenance at decode; the lone-value secret emission treated
// any `0x`-prefixed pskValue as a hex key and rendered it unquoted, so
// strongSwan hex-decoded the credential instead of using the literal
// ASCII string the operator authored. The grouped-secret fold likewise
// collapsed an ASCII `0x<digits>` and a hexadecimal `<digits>` key into
// one element. Provenance ({value, hex}) now travels through the fold
// and decides emission — never the string prefix.
//
// FAIL-ON-REVERT: restoring the string-prefix emission (a lone
// `strings.HasPrefix(v, "0x")` check, or the `"0x"+d` string-space fold)
// makes the ascii-0x cells below render `secret = 0x61626364` unquoted
// (or collapse to a single element) and every assertion goes RED.

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

	t.Run("lone ascii 0x renders quoted, lone hex renders raw", func(t *testing.T) {
		cfg := asciiHexFixture15991(
			map[string]*config.IPsecVPN{
				"ascii-0x": {Gateway: "gw-a", PSK: config.NewSecret("0x61626364")},
				"hex":      {Gateway: "gw-b", PSK: config.NewSecret("61626364"), PSKHex: true},
				// Uppercase ASCII control: also a literal string, never hex.
				"ascii-0X": {Gateway: "gw-c", PSK: config.NewSecret("0X61626364")},
			},
			map[string]*config.IPsecGateway{
				"gw-a": {Name: "gw-a", Address: "203.0.113.1", IKEPolicy: "pol"},
				"gw-b": {Name: "gw-b", Address: "203.0.113.2", IKEPolicy: "pol"},
				"gw-c": {Name: "gw-c", Address: "203.0.113.3", IKEPolicy: "pol"},
			})
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] || !rendered["gw-b"] || !rendered["gw-c"] {
			t.Fatalf("all VPNs must render, rendered=%v:\n%s", rendered, text)
		}
		doc := parseSwanctlDoc(t, text)
		// ASCII provenance decides: quoted even though the value starts
		// with "0x". Decisive check from #15991.
		doc.at(t, "secrets", "ike-gw-a").requireSetting(t, "secret", `"0x61626364"`)
		// Hex control (#15027): unquoted raw bytes, unchanged.
		doc.at(t, "secrets", "ike-gw-b").requireSetting(t, "secret", "0x61626364")
		doc.at(t, "secrets", "ike-gw-c").requireSetting(t, "secret", `"0X61626364"`)
	})

	t.Run("policy-fallback ascii 0x renders quoted", func(t *testing.T) {
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
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw-a").requireSetting(t, "secret", `"0x61626364"`)
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
		// Pre-fix the fold's string-space dedupe collapsed both to the
		// single raw-hex token; both credentials must survive, in sorted
		// member order (ascii-0x first).
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw").requireSetting(t, "secret", `"0x61626364,0x61626364"`)
	})

	t.Run("grouped identical ascii 0x dedupes, ascii 0x plus plain stays quoted", func(t *testing.T) {
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
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw").requireSetting(t, "secret", `"0x61626364,other"`)
	})

	t.Run("lone 0x with non-hex tail renders quoted", func(t *testing.T) {
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
		// Never raw hex bytes — and not degenerate: "0xzzzz" is not valid
		// hex, but as ASCII it is a legitimate literal credential.
		parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw-a").requireSetting(t, "secret", `"0xzzzz"`)
	})
}

// End-to-end through the real compiler: `ascii-text 0x61626364` keeps
// PSKHex=false and renders quoted — the exact authored spelling #15991
// names (mirrors TestPSKHexadecimalEndToEnd15027 for the hex leg).
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
	parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw1").requireSetting(t, "secret", `"0x61626364"`)
}
