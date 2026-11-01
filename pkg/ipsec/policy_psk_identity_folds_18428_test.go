package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18428 review folds, render belt side. config.IPsecPSKIdentityConflicts is
// shared with commit validation; these cells pin the renderer's use of it:
// cross-type DN/raw-encoding owners render (strongSwan's matches() is
// type-strict, so neither selects the other's secret) whatever the gateway
// order, an ID_ANY remote-identity under any unprefixed type never becomes a
// PSK owner, and the conflict carries both selectors and the equality rule.
func TestPSKIdentityFoldsRender18428(t *testing.T) {
	manager := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	pair := func(aType, a, bType, b, addrA, addrB string) *config.IPsecConfig {
		return &config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"gw-a": {Name: "gw-a", Address: addrA, RemoteIDType: aType, RemoteIDValue: a},
				"gw-b": {Name: "gw-b", Address: addrB, RemoteIDType: bType, RemoteIDValue: b},
			},
			VPNs: map[string]*config.IPsecVPN{
				"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
				"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
			},
			Proposals: map[string]*config.IPsecProposal{},
		}
	}

	t.Run("cross-type DN/KEY_ID pairs render both connections in either gateway order", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"textual DN versus rendered KEY_ID", "distinguished-name", "CN=peer", "key-id", "300f310d300b0603550403130470656572"},
			{"asn1dn versus keyid prefix", "inet", "asn1dn:#300f310d300b0603550403130470656572", "inet", "keyid:#300f310d300b0603550403130470656572"},
		}
		for _, p := range pairs {
			for _, swapped := range []bool{false, true} {
				aType, a, bType, b := p.aType, p.a, p.bType, p.b
				if swapped {
					aType, a, bType, b = bType, b, aType, a
				}
				text, rendered, err := manager.renderConfig(pair(aType, a, bType, b, "203.0.113.1", "203.0.113.2"))
				if err != nil {
					t.Fatalf("%s (swapped=%v): renderConfig: %v", p.name, swapped, err)
				}
				if !rendered["gw-a"] || !rendered["gw-b"] {
					t.Errorf("%s (swapped=%v): cross-type owners must both render: rendered=%v\n%s", p.name, swapped, rendered, text)
				}
			}
		}
	})

	t.Run("ID_ANY remote identity under an unprefixed type is not a PSK owner", func(t *testing.T) {
		text, rendered, err := manager.renderConfig(pair("distinguished-name", "0.0.0.0", "email", "::", "203.0.113.1", "203.0.113.2"))
		if err != nil || !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("IP-addressed gateways with wildcard remote identities scope by address and render: rendered=%v err=%v\n%s", rendered, err, text)
		}
		blocks := parseSecretBlocks(t, text)
		for name, want := range map[string]string{"ike-gw-a": "203.0.113.1", "ike-gw-b": "203.0.113.2"} {
			block, ok := blocks[name]
			if !ok {
				t.Fatalf("missing secret %s:\n%s", name, text)
			}
			if len(block.ids) != 1 || block.ids[0] != want {
				t.Errorf("secret %s owners = %q, want only the gateway IP %s (never the ID_ANY selector)", name, block.ids, want)
			}
		}
		// The wildcard is never the PSK connection's remote id either: a sole
		// gateway address supplies the default remote.id (#17875).
		doc := parseSwanctlDoc(t, text)
		doc.at(t, "connections", "gw-a", "remote").requireSetting(t, "id", `"203.0.113.1"`)
		doc.at(t, "connections", "gw-b", "remote").requireSetting(t, "id", `"203.0.113.2"`)
	})

	t.Run("ID_ANY remote identity on a hostname-addressed gateway is skipped", func(t *testing.T) {
		text, rendered, err := manager.renderConfig(pair("distinguished-name", "0.0.0.0", "hostname", "b.example.com", "peer-a.example.com", "203.0.113.2"))
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["gw-a"] {
			t.Errorf("a PSK gateway whose only selector is an ID_ANY remote identity must be skipped (#16845):\n%s", text)
		}
		if !rendered["gw-b"] {
			t.Errorf("the unrelated gateway must still render:\n%s", text)
		}
	})

	t.Run("conflict names both selectors and the equality rule", func(t *testing.T) {
		conflicts := config.IPsecPSKIdentityConflicts(pair("distinguished-name", "CN=Peer,O=Corp", "user-at-hostname", "cn=peer,o=corp", "203.0.113.1", "203.0.113.2"))
		if len(conflicts) != 1 {
			t.Fatalf("want one conflict, got %+v", conflicts)
		}
		c := conflicts[0]
		if c.Identity != "CN=Peer,O=Corp" || c.OtherIdentity != "cn=peer,o=corp" ||
			!strings.HasPrefix(c.Rule, "DN equality") {
			t.Fatalf("conflict = identity %q other %q rule %q, want both rendered selectors and the DN rule",
				c.Identity, c.OtherIdentity, c.Rule)
		}
	})
}
