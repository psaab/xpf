package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15752 (G18-02/03): pubkey VPN without an effective local certificate is
// skipped at render; psk renders no certs; policy cert is the fallback;
// DN/key-id identities render typed.

func certCfg15752(auth, gwCert, polCert string) *config.IPsecConfig {
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"p1": {Name: "p1", AuthMethod: auth, EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol1": {Name: "pol1", Proposals: []string{"p1"}, LocalCertificate: polCert},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {Name: "gw1", Address: "203.0.113.1", IKEPolicy: "pol1", LocalCertificate: gwCert},
		},
		VPNs: map[string]*config.IPsecVPN{
			"v1": {Name: "v1", Gateway: "gw1"},
		},
	}
	if auth == "pre-shared-keys" {
		cfg.IKEPolicies["pol1"].PSK = config.Secret("secret")
	}
	return cfg
}

func TestCertAuthRender15752(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("pubkey without cert skipped", func(t *testing.T) {
		for _, auth := range []string{"rsa-signatures", "ecdsa-signatures", "ecdsa-signatures-256", "ecdsa-signatures-384"} {
			text, rendered, err := m.renderConfig(certCfg15752(auth, "", ""))
			if err != nil {
				t.Fatalf("%s renderConfig: %v", auth, err)
			}
			if rendered["gw1"] {
				t.Fatalf("%s pubkey without cert must be skipped, rendered=%v\n%s", auth, rendered, text)
			}
		}
	})

	t.Run("pubkey with gateway cert renders certs", func(t *testing.T) {
		text, rendered, err := m.renderConfig(certCfg15752("ecdsa-signatures-256", "GwCert", ""))
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw1"] {
			t.Fatalf("pubkey with cert must render:\n%s", text)
		}
		doc := parseSwanctlDoc(t, text)
		local := doc.at(t, "connections", "gw1", "local")
		local.requireSetting(t, "auth", "pubkey")
		local.requireSetting(t, "certs", `"GwCert"`)
	})

	t.Run("pubkey with policy cert renders policy certs", func(t *testing.T) {
		text, rendered, err := m.renderConfig(certCfg15752("rsa-signatures", "", "Hub"))
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw1"] {
			t.Fatalf("pubkey with policy cert must render:\n%s", text)
		}
		doc := parseSwanctlDoc(t, text)
		doc.at(t, "connections", "gw1", "local").requireSetting(t, "certs", `"Hub"`)
	})

	t.Run("gateway cert wins over policy cert", func(t *testing.T) {
		text, _, err := m.renderConfig(certCfg15752("rsa-signatures", "GwCert", "Hub"))
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		doc := parseSwanctlDoc(t, text)
		doc.at(t, "connections", "gw1", "local").requireSetting(t, "certs", `"GwCert"`)
	})

	t.Run("psk renders no certs even with certs configured", func(t *testing.T) {
		text, rendered, err := m.renderConfig(certCfg15752("pre-shared-keys", "GwCert", "Hub"))
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw1"] {
			t.Fatalf("psk must render:\n%s", text)
		}
		doc := parseSwanctlDoc(t, text)
		local := doc.at(t, "connections", "gw1", "local")
		local.requireSetting(t, "auth", "psk")
		local.hasNoSetting(t, "certs")
		doc.hasNoSettingAnywhere(t, "certs")
	})

	t.Run("ecdsa variants map to pubkey", func(t *testing.T) {
		for _, auth := range []string{"ecdsa-signatures-256", "ecdsa-signatures-384"} {
			got, err := authMethodToSwan(auth)
			if err != nil || got != "pubkey" {
				t.Fatalf("authMethodToSwan(%q) = %q, %v; want pubkey", auth, got, err)
			}
		}
	})
}

func TestFormatIdentity15752(t *testing.T) {
	cases := []struct{ typ, val, want string }{
		{"hostname", "vpn.example.com", "@vpn.example.com"},
		{"fqdn", "peer.example.com", "@peer.example.com"},
		{"key-id", "mykey", "@#mykey"},
		{"distinguished-name", "CN=peer", "CN=peer"},
		{"distinguished-name", "", ""},
		{"inet", "10.0.0.1", "10.0.0.1"},
		{"user-at-hostname", "user@example.com", "user@example.com"},
		{"email", "user@example.com", "user@example.com"},
	}
	for _, tc := range cases {
		if got := formatIdentity(tc.typ, tc.val); got != tc.want {
			t.Errorf("formatIdentity(%q,%q) = %q, want %q", tc.typ, tc.val, got, tc.want)
		}
	}
	// Rendered: DN remote id as-is, key-id local id as @#.
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := certCfg15752("pre-shared-keys", "", "")
	cfg.Gateways["gw1"].LocalIDType = "key-id"
	cfg.Gateways["gw1"].LocalIDValue = "mykey"
	cfg.Gateways["gw1"].RemoteIDType = "distinguished-name"
	cfg.Gateways["gw1"].RemoteIDValue = "CN=peer"
	text, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if !rendered["gw1"] {
		t.Fatalf("must render:\n%s", text)
	}
	doc := parseSwanctlDoc(t, text)
	doc.at(t, "connections", "gw1", "local").requireSetting(t, "id", `"@#mykey"`)
	doc.at(t, "connections", "gw1", "remote").requireSetting(t, "id", `"CN=peer"`)
}
