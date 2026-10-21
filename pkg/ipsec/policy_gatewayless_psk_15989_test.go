package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15989 (H-4): a gateway-less PSK VPN (Gateway == "", rendered with no
// remote_addrs, so charon defaults to %any as responder) has no peer
// address or identity to scope its secret to. Pre-fix its secret carried
// a lone id-1 = "%any" selector, so a holder of any on-box PSK could
// authenticate into the tunnel by claiming the intended peer's identity.
// The render belt must skip it (no connection, no orphan secret, no
// "%any" anywhere), while healthy siblings — fixed-address and inline
// endpoints, whose peer address scopes the secret — keep rendering.
func TestGatewaylessPSK15989(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	gatewayless := func() *config.IPsecConfig {
		return &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"gwless": {Gateway: "", PSK: "gwless-secret", BindInterface: "st0.0"},
			},
			Gateways:  map[string]*config.IPsecGateway{},
			Proposals: map[string]*config.IPsecProposal{},
		}
	}

	t.Run("single gateway-less PSK VPN renders no lone %any secret", func(t *testing.T) {
		text, rendered, err := m.renderConfig(gatewayless())
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["gwless"] {
			t.Fatalf("gateway-less PSK VPN was rendered, want skip:\n%s", text)
		}
		doc := parseSwanctlDoc(t, text)
		doc.at(t, "connections").hasNoChild(t, "gwless")
		doc.at(t, "secrets").hasNoChild(t, "ike-gwless")
		if strings.Contains(text, "%any") {
			t.Fatalf("rendered swanctl contains a %%any selector:\n%s", text)
		}
	})

	t.Run("gateway-less PSK VPN skipped, healthy siblings render", func(t *testing.T) {
		cfg := gatewayless()
		cfg.Gateways["gw-site"] = &config.IPsecGateway{
			Name: "gw-site", Address: "203.0.113.1", LocalAddress: "198.51.100.10",
		}
		cfg.VPNs["site-a"] = &config.IPsecVPN{Gateway: "gw-site", PSK: "site-secret"}
		cfg.VPNs["inline"] = &config.IPsecVPN{Gateway: "192.0.2.9", PSK: "inline-secret"}

		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["gwless"] {
			t.Fatalf("gateway-less PSK VPN was rendered, want skip:\n%s", text)
		}
		if !rendered["gw-site"] {
			t.Fatalf("healthy named-gateway VPN must render, rendered=%v:\n%s", rendered, text)
		}
		if !rendered["inline"] {
			t.Fatalf("healthy inline-endpoint VPN must render, rendered=%v:\n%s", rendered, text)
		}
		doc := parseSwanctlDoc(t, text)
		doc.at(t, "connections").hasNoChild(t, "gwless")
		doc.at(t, "secrets").hasNoChild(t, "ike-gwless")

		blocks := parseSecretBlocks(t, text)
		// No secret in the render may carry "%any" as its SOLE selector
		// (#15989 acceptance). Healthy VPNs scope by peer address; the
		// #15193 local-owner %any may only accompany a peer selector.
		for name, blk := range blocks {
			if len(blk.ids) == 1 && blk.ids[0] == "%any" {
				t.Errorf("secret %s carries a lone %%any selector %v:\n%s", name, blk.ids, text)
			}
		}
		site, ok := blocks["ike-gw-site"]
		if !ok {
			t.Fatalf("missing ike-gw-site secret block:\n%s", text)
		}
		if !containsStr(site.ids, "203.0.113.1") {
			t.Errorf("ike-gw-site id selectors %v missing its peer 203.0.113.1", site.ids)
		}
		inline, ok := blocks["ike-inline"]
		if !ok {
			t.Fatalf("missing ike-inline secret block:\n%s", text)
		}
		if !containsStr(inline.ids, "192.0.2.9") {
			t.Errorf("ike-inline id selectors %v missing its peer 192.0.2.9", inline.ids)
		}
	})
}
