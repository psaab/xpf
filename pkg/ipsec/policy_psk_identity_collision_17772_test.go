package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPSKIdentityCollisionRender17772(t *testing.T) {
	manager := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	build := func(gateways map[string]*config.IPsecGateway, vpns map[string]*config.IPsecVPN) *config.IPsecConfig {
		return &config.IPsecConfig{
			Gateways:  gateways,
			VPNs:      vpns,
			Proposals: map[string]*config.IPsecProposal{},
		}
	}
	assertSkipped := func(t *testing.T, cfg *config.IPsecConfig, names ...string) (string, map[string]bool) {
		t.Helper()
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		blocks := parseSecretBlocks(t, text)
		for _, name := range names {
			if rendered[name] {
				t.Errorf("colliding connection %q must not render: %s", name, text)
			}
			if _, ok := blocks["ike-"+name]; ok {
				t.Errorf("colliding connection %q emitted a PSK secret: %s", name, text)
			}
		}
		return text, rendered
	}

	t.Run("shared remote identity skips both colliding connections but keeps unrelated VPN", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "shared.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "fqdn", RemoteIDValue: "SHARED.EXAMPLE.COM"},
			"gw-c": {Name: "gw-c", Address: "203.0.113.3"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
			"c": {Gateway: "gw-c", PSK: config.NewSecret("secret-c")},
		})
		text, rendered := assertSkipped(t, cfg, "gw-a", "gw-b")
		if !rendered["gw-c"] {
			t.Fatalf("unrelated connection must render alongside skips:\n%s", text)
		}
	})

	t.Run("distinct remote identities render both connections", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "a.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "b.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("distinct peer identities must render both connections: rendered=%v\n%s", rendered, text)
		}
	})

	t.Run("remote identity equal to another connection local identity skips both", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "shared.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalIDType: "fqdn", LocalIDValue: "SHARED.EXAMPLE.COM"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		assertSkipped(t, cfg, "gw-a", "gw-b")
	})

	t.Run("mixed hostname and IP without remote identity skips connection", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "peer.example.test, 203.0.113.1"},
		}, map[string]*config.IPsecVPN{
			"site": {Gateway: "gw", PSK: config.NewSecret("site-secret")},
		})
		assertSkipped(t, cfg, "gw")
	})

	t.Run("explicit remote identity scopes mixed hostname and IP connection", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "peer.example.test, 203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "peer.example.test"},
		}, map[string]*config.IPsecVPN{
			"site": {Gateway: "gw", PSK: config.NewSecret("site-secret")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("explicit remote-identity must preserve mixed gateway render:\n%s", text)
		}
		block := parseSecretBlocks(t, text)["ike-gw"]
		if len(block.ids) != 1 || block.ids[0] != "@peer.example.test" {
			t.Fatalf("mixed gateway selectors = %v, want exactly [@peer.example.test]", block.ids)
		}
	})

	t.Run("same remote identity with same PSK remains renderable", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "hostname", RemoteIDValue: "shared.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "fqdn", RemoteIDValue: "shared.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("same-secret")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("same-secret")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("identical shared credentials may render: rendered=%v\n%s", rendered, text)
		}
	})
}
