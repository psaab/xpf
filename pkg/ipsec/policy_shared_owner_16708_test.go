package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16708 (R3-VA16-S1): #15193 added a local owner to every non-responder
// PSK secret — %any, or the pinned local address / local-id, all shared by
// every VPN on the box. charon's credential set enumerates a secret when
// ANY owner matches EITHER side of the (me, other) pair, and the IKEv2 PSK
// verifier tries every enumerated secret against the peer's AUTH, so every
// such secret verified every peer: (a) a peer at a fixed gateway's address
// holding a different VPN's PSK was authenticated as that gateway's peer;
// (b) a peer at any address holding a fixed VPN's PSK and claiming a
// responder-only `dynamic hostname` VPN's identity was authenticated into
// that VPN (reopening #14591). The fix drops the local owner entirely:
// secrets carry peer selectors only, and the #15193 initiator cells still
// establish via the pinned remote.id (docs/log/16708.md lab). A
// hostname-addressed PSK VPN with no remote-identity has no peer selector
// and is skipped at render / rejected at commit instead of carrying a
// local-owner-only secret.
//
// FAIL-ON-REVERT: restoring the local-owner switch in pskPeerSelectors'
// caller (or the %any / local-address / local-id owners) turns every cell
// below red: the two-VPN cells regain a shared selector, the dynamic cell
// regains a cross-matching fixed secret, and the hostname cells render
// again with a local-owner-only secret.

func TestSharedOwner16708(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("two fixed VPNs share no selector and keep peer isolation", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
				"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
			},
			Gateways: map[string]*config.IPsecGateway{
				// Same pinned local address on both: pre-fix both
				// secrets carried 198.51.100.1 (and %any without it).
				"gw-a": {Name: "gw-a", Address: "203.0.113.1", LocalAddress: "198.51.100.1"},
				"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalAddress: "198.51.100.1"},
			},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("both VPNs must render, rendered=%v:\n%s", rendered, text)
		}
		blocks := parseSecretBlocks(t, text)
		a, b := blocks["ike-gw-a"], blocks["ike-gw-b"]
		if len(a.ids) != 1 || a.ids[0] != "203.0.113.1" {
			t.Errorf("ike-gw-a selectors %v, want exactly [203.0.113.1]", a.ids)
		}
		if len(b.ids) != 1 || b.ids[0] != "203.0.113.2" {
			t.Errorf("ike-gw-b selectors %v, want exactly [203.0.113.2]", b.ids)
		}
		assertNoSharedSelectors(t, blocks)
	})

	t.Run("fixed plus dynamic hostname VPNs share no selector", func(t *testing.T) {
		// Case (b) shape: gw1 fixed (keyOne) + gwd responder-only
		// dynamic-hostname (keyTwo). Pre-fix ike-gw1 carried %any, so a
		// peer claiming @site-d.example with keyOne verified against
		// ike-gw1 via the responder's own side.
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"vpn1": {Gateway: "gw1", PSK: config.NewSecret("keyOne"), BindInterface: "st0.1"},
				"vpnd": {Gateway: "gwd", PSK: config.NewSecret("keyTwo"), BindInterface: "st0.2"},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw1": {Name: "gw1", Address: "203.0.113.3"},
				"gwd": {Name: "gwd", ResponderOnly: true, DynamicHostname: "site-d.example", LocalAddress: "198.51.100.2"},
			},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw1"] || !rendered["gwd"] {
			t.Fatalf("both VPNs must render, rendered=%v:\n%s", rendered, text)
		}
		blocks := parseSecretBlocks(t, text)
		fixed, dyn := blocks["ike-gw1"], blocks["ike-gwd"]
		if len(fixed.ids) != 1 || fixed.ids[0] != "203.0.113.3" {
			t.Errorf("ike-gw1 selectors %v, want exactly [203.0.113.3] (no %%any local owner)", fixed.ids)
		}
		if len(dyn.ids) != 1 || dyn.ids[0] != "@site-d.example" {
			t.Errorf("ike-gwd selectors %v, want exactly [@site-d.example]", dyn.ids)
		}
		assertNoSharedSelectors(t, blocks)
	})

	t.Run("shared local-id does not cross VPNs", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
				"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw-a": {Name: "gw-a", Address: "203.0.113.1", LocalIDType: "hostname", LocalIDValue: "fw.example.com"},
				"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalIDType: "hostname", LocalIDValue: "fw.example.com"},
			},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		blocks := parseSecretBlocks(t, text)
		for name, blk := range blocks {
			if containsStr(blk.ids, "@fw.example.com") {
				t.Errorf("%s selectors %v carry the box-shared local-id @fw.example.com (#16708)", name, blk.ids)
			}
		}
		assertNoSharedSelectors(t, blocks)
	})

	t.Run("hostname gateway without remote identity skipped, sibling renders", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"host": {Gateway: "gw-host", PSK: config.NewSecret("host-secret")},
				"site": {Gateway: "gw-site", PSK: config.NewSecret("site-secret")},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw-host": {Name: "gw-host", Address: "peer.example.test"},
				"gw-site": {Name: "gw-site", Address: "203.0.113.9"},
			},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["gw-host"] {
			t.Errorf("hostname PSK VPN with no remote-identity must be skipped (#16708):\n%s", text)
		}
		if !rendered["gw-site"] {
			t.Fatalf("fixed-address sibling must render, rendered=%v:\n%s", rendered, text)
		}
		if _, ok := parseSecretBlocks(t, text)["ike-gw-host"]; ok {
			t.Errorf("skipped hostname VPN must not emit a secret block:\n%s", text)
		}
	})

	t.Run("hostname gateway with remote identity renders scoped by it", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "peer.example.test",
			RemoteIDType: "hostname", RemoteIDValue: "peer.example.test",
		}, "site-secret")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("hostname VPN with explicit remote-identity must render, rendered=%v:\n%s", rendered, text)
		}
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || blk.ids[0] != "@peer.example.test" {
			t.Errorf("ike-gw selectors %v, want exactly [@peer.example.test]", blk.ids)
		}
	})

	t.Run("mixed hostname and IP gateway renders scoped by IP only", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "peer.example.test, 203.0.113.1",
		}, "site-secret")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("mixed hostname+IP VPN must render on its IP selector, rendered=%v:\n%s", rendered, text)
		}
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || blk.ids[0] != "203.0.113.1" {
			t.Errorf("ike-gw selectors %v, want exactly [203.0.113.1]", blk.ids)
		}
	})

	t.Run("single default-shape VPN carries peer selector only", func(t *testing.T) {
		// The acceptance carve-out ("unless it is the only VPN") needs
		// no special case: a lone secret with no shared owner is the
		// same peer-only shape as with many VPNs.
		cfg := initiatorCfg15193(&config.IPsecGateway{Name: "gw", Address: "203.0.113.1"}, "only-secret")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("single VPN must render, rendered=%v:\n%s", rendered, text)
		}
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || blk.ids[0] != "203.0.113.1" {
			t.Errorf("ike-gw selectors %v, want exactly [203.0.113.1]", blk.ids)
		}
	})
}

// assertNoSharedSelectors is the #16708 acceptance invariant: no selector
// value may appear on two different secrets in the same render (the only
// VPN on the box trivially satisfies it).
func assertNoSharedSelectors(t *testing.T, blocks map[string]secretBlock) {
	t.Helper()
	seen := map[string]string{}
	for name, blk := range blocks {
		for _, sel := range blk.ids {
			if prev, dup := seen[sel]; dup {
				t.Errorf("selector %q shared between %s and %s (#16708: a shared owner matches every peer)", sel, prev, name)
			}
			seen[sel] = name
		}
	}
}
