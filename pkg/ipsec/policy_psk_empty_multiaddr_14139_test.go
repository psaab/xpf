package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestPSKEmptySecretSkipped14139 is the #14139 (D5-06a) regression: a
// PSK-authenticated VPN whose effective secret is empty (neither the VPN
// PSK nor the IKE-policy fallback PSK) must be skipped like every other
// unrenderable VPN, instead of rendering a live auth=psk connection with
// no secret of its own in secrets{} (which lets strongSwan consult
// another VPN's matching secret).
func TestPSKEmptySecretSkipped14139(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"no-secret": {Gateway: "gw-a"},
			"healthy":   {Gateway: "gw-b", PSK: "healthy-secret"},
			// VPN PSK empty, IKE-policy fallback PSK present: renders.
			"policy-psk": {Gateway: "gw-c"},
			// Cert (pubkey) VPN legitimately has no PSK: must render.
			"cert-vpn": {Gateway: "gw-d"},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-psk": {
				Name: "ike-psk", AuthMethod: "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14,
			},
			"ike-cert": {
				Name: "ike-cert", AuthMethod: "rsa-signatures",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol-psk":  {Name: "pol-psk", Proposals: []string{"ike-psk"}, PSK: config.Secret("policy-secret")},
			"pol-cert": {Name: "pol-cert", Proposals: []string{"ike-cert"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2"},
			"gw-c": {Name: "gw-c", Address: "203.0.113.3", IKEPolicy: "pol-psk"},
			"gw-d": {Name: "gw-d", Address: "203.0.113.4", IKEPolicy: "pol-cert", LocalCertificate: "fw-cert"},
		},
	}

	text, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if rendered["no-secret"] {
		t.Errorf("PSK VPN with empty effective secret was rendered; want skip-by-name:\n%s", text)
	}
	if !rendered["healthy"] || !rendered["policy-psk"] || !rendered["cert-vpn"] {
		t.Errorf("healthy/policy-psk/cert VPNs must render, rendered=%v:\n%s", rendered, text)
	}

	doc := parseSwanctlDoc(t, text)
	connections := doc.at(t, "connections")
	connections.hasNoChild(t, "no-secret")

	blocks := parseSecretBlocks(t, text)
	if _, ok := blocks["ike-no-secret"]; ok {
		t.Errorf("empty-PSK VPN emitted an orphan secret block")
	}
	if blk, ok := blocks["ike-policy-psk"]; !ok || blk.secret != "policy-secret" {
		t.Errorf("IKE-policy fallback PSK secret = %+v (present=%v), want policy-secret", blk, ok)
	}
	if _, ok := blocks["ike-cert-vpn"]; ok {
		t.Errorf("pubkey VPN must not emit a PSK secret block")
	}
}

// TestPSKIDSelectorsMultiAddress14139 is the #14139 (D5-06c1) regression:
// a gateway address carrying a comma-separated multi-address list (the
// same list rendered verbatim into remote_addrs) must scope the PSK with
// one id-<n> selector per address, not a single comma-joined literal that
// is not an IKE identity and matches no peer.
func TestPSKIDSelectorsMultiAddress14139(t *testing.T) {
	for _, addr := range []string{"203.0.113.1,203.0.113.2", "203.0.113.1, 203.0.113.2"} {
		m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"multi": {Gateway: "gw", PSK: "multi-secret"},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: addr},
			},
		}
		text := m.generateConfig(cfg)
		blocks := parseSecretBlocks(t, text)
		blk, ok := blocks["ike-multi"]
		if !ok {
			t.Fatalf("addr %q: missing ike-multi secret block:\n%s", addr, text)
		}
		if !containsStr(blk.ids, "203.0.113.1") || !containsStr(blk.ids, "203.0.113.2") {
			t.Errorf("addr %q: id selectors %v, want one selector per peer address", addr, blk.ids)
		}
		for _, id := range blk.ids {
			for _, r := range id {
				if r == ',' {
					t.Errorf("addr %q: id selector %q is a comma-joined literal, not an IKE identity", addr, id)
				}
			}
		}
	}
}
