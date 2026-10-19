package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15027 (A16-04): a hexadecimal PSK (PSKHex) must render as
// `secret = 0x<hex>` (raw bytes) — the issue's acceptance probe is
// 6162636431323334 — while an ascii-text PSK keeps the quoted render,
// and a hex-flagged value that is not valid hex (directly constructed
// / peer-synced, bypassing the strict commit gate) is skipped like
// every other malformed-PSK class instead of rendering as ASCII.
//
// FAIL-ON-REVERT: pre-fix there was no PSKHex, so the hex VPN rendered
// `secret = "6162636431323334"` (ASCII digits) and the bad-hex VPN
// rendered too; both assertions go RED.
func TestPSKHexadecimalRender15027(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"hex-vpn":   {Gateway: "gw-a", PSK: "6162636431323334", PSKHex: true},
			"ascii-vpn": {Gateway: "gw-b", PSK: "secret123"},
			"bad-hex":   {Gateway: "gw-c", PSK: "zz11", PSKHex: true},
			"odd-hex":   {Gateway: "gw-d", PSK: "616", PSKHex: true},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-psk": {
				Name: "ike-psk", AuthMethod: "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol": {Name: "pol", Proposals: []string{"ike-psk"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", IKEPolicy: "pol"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", IKEPolicy: "pol"},
			"gw-c": {Name: "gw-c", Address: "203.0.113.3", IKEPolicy: "pol"},
			"gw-d": {Name: "gw-d", Address: "203.0.113.4", IKEPolicy: "pol"},
		},
	}

	text, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	// #15024: the rendered set is keyed by CONNECTION name — each
	// fixture VPN has its own named gateway, so connections carry
	// the gateway names, and each secret block is ike-<gateway>.
	if !rendered["gw-a"] || !rendered["gw-b"] {
		t.Errorf("hex/ascii VPNs must render, rendered=%v:\n%s", rendered, text)
	}
	if rendered["gw-c"] || rendered["gw-d"] {
		t.Errorf("malformed hex VPNs must be skipped, rendered=%v:\n%s", rendered, text)
	}
	doc := parseSwanctlDoc(t, text)
	// The secret value must be the bare 0x-prefixed hex token, not a
	// quoted ASCII string — requireSetting compares the exact parsed
	// value at the exact path (#6824 structural assertion).
	doc.at(t, "secrets", "ike-gw-a").requireSetting(t, "secret", "0x6162636431323334")
	doc.at(t, "secrets", "ike-gw-b").requireSetting(t, "secret", `"secret123"`)
	secrets := doc.at(t, "secrets")
	secrets.hasNoChild(t, "ike-gw-c")
	secrets.hasNoChild(t, "ike-gw-d")
}

// The IKE-policy fallback carries the encoding too: a VPN with no key
// of its own whose policy holds a hexadecimal key renders 0x<hex>.
func TestPSKHexadecimalPolicyFallback15027(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site": {Gateway: "gw-a"},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-psk": {
				Name: "ike-psk", AuthMethod: "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol": {Name: "pol", Proposals: []string{"ike-psk"}, PSK: config.Secret("deadbeef01"), PSKHex: true},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", IKEPolicy: "pol"},
		},
	}
	text, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if !rendered["gw-a"] {
		t.Fatalf("policy-fallback hex VPN must render:\n%s", text)
	}
	parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw-a").requireSetting(t, "secret", "0xdeadbeef01")
}

// End-to-end through the real compiler: the authored hexadecimal
// spelling survives CompileConfig and renders 0x-prefixed — the exact
// path the issue's probe exercises.
func TestPSKHexadecimalEndToEnd15027(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set security ike proposal p1 authentication-method pre-shared-keys",
		"set security ike proposal p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal p1 authentication-algorithm sha-256",
		"set security ike proposal p1 dh-group group14",
		"set security ike policy pol proposals p1",
		"set security ike policy pol pre-shared-key hexadecimal 6162636431323334",
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
	text, rendered, err := (&Manager{}).renderConfig(&cfg.Security.IPsec)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if !rendered["gw1"] {
		t.Fatalf("hex VPN must render:\n%s", text)
	}
	parseSwanctlDoc(t, text).at(t, "secrets", "ike-gw1").requireSetting(t, "secret", "0x6162636431323334")
}
