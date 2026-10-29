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

	t.Run("cross-type rendered-identical owner with the same PSK renders both", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "inet", RemoteIDValue: "peer@corp.example"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "email", RemoteIDValue: "peer@corp.example"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("same-secret")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("same-secret")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("same PSK may share an identical rendered owner: rendered=%v err=%v\n%s", rendered, err, text)
		}
		blocks := parseSecretBlocks(t, text)
		for _, name := range []string{"gw-a", "gw-b"} {
			block, ok := blocks["ike-"+name]
			if !ok || len(block.ids) != 1 || block.ids[0] != "peer@corp.example" {
				t.Fatalf("%s secret selectors = %+v, want [peer@corp.example]\n%s", name, block, text)
			}
		}
	})
	t.Run("RFC822 aliases collide and retain unrelated VPN", func(t *testing.T) {
		pairs := []struct{ aType, a, bType, b string }{
			{"rfc822", "peer@corp.example", "user-at-hostname", "peer@CORP.EXAMPLE"},
			{"email", "peer@corp.example", "user-at-hostname", "Peer@Corp.Example"},
			{"email", "peer@corp.example", "rfc822", "PEER@CORP.EXAMPLE"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.aType+"_"+pair.bType, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
					"gw-c": {Name: "gw-c", Address: "203.0.113.3"},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
					"c": {Gateway: "gw-c", PSK: config.NewSecret("secret-c")},
				})
				text, rendered := assertSkipped(t, cfg, "gw-a", "gw-b")
				if !rendered["gw-c"] {
					t.Fatalf("unrelated VPN must render alongside RFC822 skips:\n%s", text)
				}
			})
		}
	})

	t.Run("canonical atodn spellings skip both secrets", func(t *testing.T) {
		pairs := []struct{ name, a, b string }{
			{"separator spacing and case", "CN=peer, O=Org", "cn=PEER,o=ORG"},
			{"RDN order", "CN=peer,O=Org", "O=ORG,CN=PEER"},
			{"slash separator", "/CN=peer/O=Org", "O=ORG,CN=PEER"},
			{"PrintableString case", "SN=Smith", "sn=SMITH"},
			{"email attribute aliases", "E=Peer@corp.example,O=Org", "emailAddress=PEER@CORP.EXAMPLE,o=ORG"},
			{"employeeNumber aliases", "EN=12345", "employeeNumber=12345"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "distinguished-name", RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "distinguished-name", RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				assertSkipped(t, cfg, "gw-a", "gw-b")
			})
		}
	})

	t.Run("key-id spellings compare chunk_from_hex bytes", func(t *testing.T) {
		pairs := []struct{ name, a, b string }{
			{"invalid nibble maps to zero", "zz", "00"},
			{"hex case", "7a7a", "7A7A"},
			{"0x prefix and colon separators", "0x7a7a", "7a:7a"},
			{"odd nibble is left padded", "7a7", "07A7"},
			{"two zero bytes with separators", "0000", "00:00"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "key-id", RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "key-id", RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				assertSkipped(t, cfg, "gw-a", "gw-b")
			})
		}
	})

	t.Run("DN syntax is checked before rendered identity prefixes", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"hostname selector falls back to literal KEY_ID", "hostname", "CN=peer", "key-id", "40434e3d70656572"},
			{"unsupported DN falls back to literal KEY_ID", "distinguished-name", "broken=peer", "key-id", "62726f6b656e3d70656572"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				assertSkipped(t, cfg, "gw-a", "gw-b")
			})
		}
	})

	t.Run("distinct strongSwan identities render both secrets", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"one zero byte versus two", "key-id", "zz", "key-id", "0000"},
			{"odd padded bytes versus ASCII hex text", "key-id", "7a7", "key-id", "376137"},
			{"unknown DN attribute case", "distinguished-name", "broken=peer", "distinguished-name", "BROKEN=PEER"},
			{"internal DN whitespace", "distinguished-name", "CN=Peer   Name", "distinguished-name", "CN=peer name"},
			{"UTF8 DN sharp-s", "distinguished-name", "CN=Straße", "distinguished-name", "CN=STRASSE"},
			{"plus remains in DN value", "distinguished-name", "CN=peer+OU=VPN", "distinguished-name", "OU=vpn+CN=PEER"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				text, rendered, err := manager.renderConfig(cfg)
				if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
					t.Fatalf("distinct strongSwan identities must both render: rendered=%v err=%v\n%s", rendered, err, text)
				}
			})
		}
	})

	t.Run("remote peer identity equal to default local address skips both", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "inet", RemoteIDValue: "198.51.100.7"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalAddress: "198.51.100.7", RemoteIDType: "hostname", RemoteIDValue: "gw-b.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		assertSkipped(t, cfg, "gw-a", "gw-b")
	})

	t.Run("VPN local-address override participates in default identity collision", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "inet", RemoteIDValue: "198.51.100.7"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "gw-b.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", LocalAddr: "198.51.100.7", PSK: config.NewSecret("secret-b")},
		})
		assertSkipped(t, cfg, "gw-a", "gw-b")
	})

	t.Run("different default local address renders both", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "inet", RemoteIDValue: "198.51.100.7"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalAddress: "198.51.100.8", RemoteIDType: "hostname", RemoteIDValue: "gw-b.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("different local address must preserve both connections: rendered=%v err=%v\n%s", rendered, err, text)
		}
	})

	t.Run("RFC822 and FQDN remain distinct in rendered owners", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "email", RemoteIDValue: "peer@corp.example"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "peer@corp.example"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("RFC822 and FQDN are distinct identity namespaces: rendered=%v err=%v\n%s", rendered, err, text)
		}
	})

	t.Run("cross-type rendered-identical owners skip both secrets", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"inet and inet6 same value", "inet", "198.51.100.7", "inet6", "198.51.100.7"},
			{"inet and email same user-at-host", "inet", "peer@corp.example", "email", "peer@corp.example"},
			{"inet and DN same string", "inet", "CN=peer", "distinguished-name", "CN=peer"},
			{"email and DN same string", "email", "CN=peer", "distinguished-name", "CN=peer"},
			{"inet and email same IP string", "inet", "198.51.100.7", "email", "198.51.100.7"},
			{"hostname adorned equals inet literal @fqdn", "hostname", "peer.example", "inet", "@peer.example"},
			{"key-id rendered equals inet literal @#zz", "key-id", "zz", "inet", "@#zz"},
			{"hostname starting hash equals key-id rendered", "hostname", "#zz", "key-id", "zz"},
			{"hostname containing DN syntax falls back to matching key-id bytes", "hostname", "CN=peer", "key-id", "40434e3d70656572"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
					"gw-c": {Name: "gw-c", Address: "203.0.113.3"},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
					"c": {Gateway: "gw-c", PSK: config.NewSecret("secret-c")},
				})
				text, rendered := assertSkipped(t, cfg, "gw-a", "gw-b")
				if !rendered["gw-c"] {
					t.Fatalf("unrelated VPN must render alongside rendered-form skips:\n%s", text)
				}
			})
		}
	})

	t.Run("cross-type distinct rendered owners render both", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"email and hostname render differently", "email", "peer@corp.example", "hostname", "peer@corp.example"},
			{"hostname and key-id render differently", "hostname", "zz", "key-id", "zz"},
		}
		for _, pair := range pairs {
			pair := pair
			t.Run(pair.name, func(t *testing.T) {
				cfg := build(map[string]*config.IPsecGateway{
					"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: pair.aType, RemoteIDValue: pair.a},
					"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: pair.bType, RemoteIDValue: pair.b},
				}, map[string]*config.IPsecVPN{
					"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
					"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
				})
				text, rendered, err := manager.renderConfig(cfg)
				if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
					t.Fatalf("distinct rendered owners must both render: rendered=%v err=%v\n%s", rendered, err, text)
				}
			})
		}
	})

	t.Run("DN and FQDN remain distinct in rendered owners", func(t *testing.T) {
		cfg := build(map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", RemoteIDType: "distinguished-name", RemoteIDValue: "CN=peer.example.com"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", RemoteIDType: "hostname", RemoteIDValue: "peer.example.com"},
		}, map[string]*config.IPsecVPN{
			"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
			"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
		})
		text, rendered, err := manager.renderConfig(cfg)
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("DN and FQDN are distinct identity namespaces: rendered=%v err=%v\n%s", rendered, err, text)
		}
	})

}
