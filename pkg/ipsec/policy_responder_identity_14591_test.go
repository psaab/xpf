package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14591 (Y09-04): a responder-only (dynamic, %any) PSK VPN whose gateway
// has a configured remote-identity must scope its secret to that identity,
// and a responder-only PSK VPN with no remote-identity must not render at
// all. Before the fix the rw secret carried no id selector, so strongSwan's
// best-match key selection by claimed IDi let a holder of another site's
// PSK authenticate into the rw connection by claiming that site's identity.

// crossPSKCfg14591 builds the decisive two-VPN shape from the issue: a
// fixed-address site VPN and a responder-only rw VPN, each with its own PSK.
func crossPSKCfg14591(rwRemoteIDType, rwRemoteIDValue string) *config.IPsecConfig {
	rwGW := &config.IPsecGateway{Name: "gw-rw", ResponderOnly: true, LocalAddress: "198.51.100.10"}
	if rwRemoteIDValue != "" {
		rwGW.RemoteIDType = rwRemoteIDType
		rwGW.RemoteIDValue = rwRemoteIDValue
	}
	return &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {Gateway: "gw-site", PSK: "site-secret"},
			"rw":     {Gateway: "gw-rw", PSK: "rw-secret"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-site": {Name: "gw-site", Address: "203.0.113.1", LocalAddress: "198.51.100.10"},
			"gw-rw":   rwGW,
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
}

func TestResponderOnlyPSKScoping14591(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("rw secret is scoped to its configured identity only", func(t *testing.T) {
		cfg := crossPSKCfg14591("hostname", "rw.example.com")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["site-a"] || !rendered["rw"] {
			t.Fatalf("both VPNs must render, rendered=%v:\n%s", rendered, text)
		}
		// The rw connection pins the remote identity it will accept.
		conn := parseSwanctlDoc(t, text).at(t, "connections", "rw")
		conn.requireSetting(t, "remote_addrs", "%any")
		conn.at(t, "remote").requireSetting(t, "id", `"@rw.example.com"`)

		blocks := parseSecretBlocks(t, text)
		rw, ok := blocks["ike-rw"]
		if !ok {
			t.Fatalf("missing ike-rw secret block:\n%s", text)
		}
		if rw.secret != "rw-secret" {
			t.Errorf("ike-rw secret = %q, want rw-secret", rw.secret)
		}
		if !containsStr(rw.ids, "@rw.example.com") {
			t.Errorf("ike-rw id selectors %v missing its configured identity @rw.example.com", rw.ids)
		}
		// Credential isolation: the rw secret must never claim the site
		// peer's identity, and the site secret must never claim the rw
		// identity — otherwise claimed-IDi key selection crosses VPNs.
		if containsStr(rw.ids, "203.0.113.1") {
			t.Errorf("ike-rw id selectors %v wrongly claim site-a's peer", rw.ids)
		}
		site, ok := blocks["ike-site-a"]
		if !ok {
			t.Fatalf("missing ike-site-a secret block:\n%s", text)
		}
		if !containsStr(site.ids, "203.0.113.1") {
			t.Errorf("ike-site-a id selectors %v missing its peer 203.0.113.1", site.ids)
		}
		if containsStr(site.ids, "@rw.example.com") {
			t.Errorf("ike-site-a id selectors %v wrongly claim the rw identity", site.ids)
		}
	})

	t.Run("rw vpn with no remote identity is skipped, sibling renders", func(t *testing.T) {
		cfg := crossPSKCfg14591("", "")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["rw"] {
			t.Errorf("responder-only PSK VPN with no remote-identity was rendered; want skip-by-name:\n%s", text)
		}
		if !rendered["site-a"] {
			t.Errorf("healthy site-a VPN must still render, rendered=%v:\n%s", rendered, text)
		}
		doc := parseSwanctlDoc(t, text)
		doc.at(t, "connections").hasNoChild(t, "rw")
		if _, ok := parseSecretBlocks(t, text)["ike-rw"]; ok {
			t.Errorf("skipped rw VPN emitted an orphan secret block:\n%s", text)
		}
	})

	t.Run("single rw vpn with no remote identity is skipped", func(t *testing.T) {
		// No sibling VPN does not make an unscoped secret safe: with no
		// id selector the secret matches any peer identity, so a lone
		// responder-only PSK VPN without a remote-identity must not load.
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"rw": {Gateway: "gw-rw", PSK: "rw-secret"},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw-rw": {Name: "gw-rw", ResponderOnly: true, LocalAddress: "198.51.100.10"},
			},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["rw"] {
			t.Errorf("single responder-only PSK VPN with no remote-identity was rendered; want skip:\n%s", text)
		}
	})
}
