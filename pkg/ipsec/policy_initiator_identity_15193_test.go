package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15193 (D04-01) / #16708 (R3-VA16-S1): the #3952 PSK id selector scopes
// the secret to the peer ADDRESS only, and no remote.id is rendered for a
// fixed-address gateway. With no remote-identity/local-identity (the Junos
// default shape) the #15193 fix added a box-shared local owner (%any /
// pinned local address / local-id) so charon's initiator lookup would hit.
// #16708 measured that owner matching the responder side of every exchange
// (charon tries every secret whose ANY owner matches either side), so a
// holder of one VPN's PSK authenticated into every other VPN. The local
// owner is therefore REMOVED: secrets carry peer selectors only. The
// initiator cells still establish because the render pins remote.id (the
// peer identity charon initiates against), so the initiator lookup
// carries the peer as other_id — re-measured in the charon netns lab
// (docs/log/16708.md) for IKEv2 in both directions.
//
// Contract pinned here:
//
//   - fixed-address GW, no identities, no explicit local-address: remote.id
//     is the peer address and the secret owner is exactly {peer address}.
//   - fixed-address GW, no identities, explicit LocalAddress: secret owner
//     is exactly {peer address} (no local address, no %any).
//   - multi-address GW: remote.id is NOT pinned to one address (#15766);
//     the secret carries one selector per peer address, nothing else.
//   - local-identity configured (no remote-identity): local.id unchanged,
//     remote.id defaults to the peer address, secret owner is exactly
//     {peer address} (no local-id owner — a box-shared local-id would
//     cross VPNs sharing it, #16708).
//   - remote-identity configured: remote.id / local.id unchanged, secret
//     owner is exactly {remote-id}.
//   - IPv6 fixed address: same treatment with the v6 peer address.
//   - two fixed-address default-shape VPNs: each secret is claimed by its
//     own peer only; no selector value is shared between the two secrets.

func initiatorCfg15193(gw *config.IPsecGateway, psk string) *config.IPsecConfig {
	return &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: gw.Name, PSK: config.NewSecret(psk), EstablishTunnels: "immediately"},
		},
		Gateways:  map[string]*config.IPsecGateway{gw.Name: gw},
		Proposals: map[string]*config.IPsecProposal{},
	}
}

func TestInitiatorDefaultIdentity15193(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("fixed address no identities no local addr", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{Name: "gw", Address: "203.0.113.1"}, "site-secret")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("default-shape VPN must render, rendered=%v:\n%s", rendered, text)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.requireSetting(t, "remote_addrs", "203.0.113.1")
		// Junos default remote identity = the peer address.
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)
		// Local side with no explicit id keeps strongSwan's address default.
		conn.at(t, "local").hasNoSetting(t, "id")

		blocks := parseSecretBlocks(t, text)
		blk, ok := blocks["ike-gw"]
		if !ok {
			t.Fatalf("missing ike-gw secret block:\n%s", text)
		}
		if blk.secret != "site-secret" {
			t.Errorf("ike-gw secret = %q, want site-secret", blk.secret)
		}
		// Peer selector only (#16708): no local owner may be emitted — a
		// box-shared owner matches the responder side of every exchange.
		if len(blk.ids) != 1 || !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("ike-gw id selectors %v, want exactly [203.0.113.1] (peer selector only, #16708)", blk.ids)
		}
	})

	t.Run("fixed address no identities explicit local address", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "203.0.113.1", LocalAddress: "198.51.100.1",
		}, "site-secret")
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.requireSetting(t, "local_addrs", "198.51.100.1")
		conn.requireSetting(t, "remote_addrs", "203.0.113.1")
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)
		conn.at(t, "local").hasNoSetting(t, "id")

		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("id selectors %v, want exactly [203.0.113.1] (peer selector only; the pinned local address is a box-shared owner, #16708)", blk.ids)
		}
	})

	t.Run("multi address pins no remote id and scopes every address", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "203.0.113.1, 203.0.113.2", LocalAddress: "198.51.100.1",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		// #15766: remote.id is single-valued in swanctl; pinning the
		// first address would reject the peer presenting from the
		// second, so no default id is rendered for a multi-address GW.
		conn.at(t, "remote").hasNoSetting(t, "id")

		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 2 || !containsStr(blk.ids, "203.0.113.1") || !containsStr(blk.ids, "203.0.113.2") {
			t.Errorf("id selectors %v, want exactly [203.0.113.1 203.0.113.2] (one selector per peer address, no local owner, #16708)", blk.ids)
		}
	})

	t.Run("ipv6 fixed address no identities", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "2001:db8:ffff::1", LocalAddress: "2001:db8:1::1",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "remote").requireSetting(t, "id", `"2001:db8:ffff::1"`)
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || !containsStr(blk.ids, "2001:db8:ffff::1") {
			t.Errorf("id selectors %v, want exactly [2001:db8:ffff::1] (peer selector only, #16708)", blk.ids)
		}
	})

	t.Run("local identity only still defaults remote id and scopes local id", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "203.0.113.1", LocalAddress: "198.51.100.1",
			LocalIDType: "hostname", LocalIDValue: "fw.example.com",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "local").requireSetting(t, "id", `"@fw.example.com"`)
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)

		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("id selectors %v, want exactly [203.0.113.1] (peer selector only; a shared local-id owner crosses VPNs, #16708)", blk.ids)
		}
	})

	t.Run("explicit remote identity unchanged control", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "203.0.113.1", LocalAddress: "198.51.100.1",
			RemoteIDType: "hostname", RemoteIDValue: "peer.example.com",
			LocalIDType: "hostname", LocalIDValue: "fw.example.com",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "remote").requireSetting(t, "id", `"@peer.example.com"`)
		conn.at(t, "local").requireSetting(t, "id", `"@fw.example.com"`)

		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || !containsStr(blk.ids, "@peer.example.com") {
			t.Errorf("id selectors %v, want exactly [@peer.example.com] (peer selector only, #16708)", blk.ids)
		}
	})

	t.Run("two default-shape VPNs share no selector value", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"a": {Gateway: "gw-a", PSK: config.NewSecret("secret-a")},
				"b": {Gateway: "gw-b", PSK: config.NewSecret("secret-b")},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw-a": {Name: "gw-a", Address: "203.0.113.1"},
				"gw-b": {Name: "gw-b", Address: "203.0.113.2"},
			},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw-a"] || !rendered["gw-b"] {
			t.Fatalf("both default-shape VPNs must render, rendered=%v:\n%s", rendered, text)
		}
		blocks := parseSecretBlocks(t, text)
		a, b := blocks["ike-gw-a"], blocks["ike-gw-b"]
		if !containsStr(a.ids, "203.0.113.1") || containsStr(a.ids, "203.0.113.2") {
			t.Errorf("ike-gw-a selectors %v must claim 203.0.113.1 only among peers", a.ids)
		}
		if !containsStr(b.ids, "203.0.113.2") || containsStr(b.ids, "203.0.113.1") {
			t.Errorf("ike-gw-b selectors %v must claim 203.0.113.2 only among peers", b.ids)
		}
		// #16708 acceptance: no selector value is shared between the two
		// secrets (pre-fix both carried the %any local owner).
		for _, av := range a.ids {
			if containsStr(b.ids, av) {
				t.Errorf("selector %q shared between ike-gw-a %v and ike-gw-b %v (#16708)", av, a.ids, b.ids)
			}
		}
	})

	t.Run("cert gateway unaffected no remote id invented", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "gw"},
			},
			IKEProposals: map[string]*config.IKEProposal{
				"ike-cert": {Name: "ike-cert", AuthMethod: "rsa-signatures", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			},
			IKEPolicies: map[string]*config.IKEPolicy{
				"pol-cert": {Name: "pol-cert", Proposals: []string{"ike-cert"}},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: "203.0.113.20", LocalCertificate: "fw-cert", IKEPolicy: "pol-cert"},
			},
		}
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "remote").requireSetting(t, "auth", "pubkey")
		// The default remote.id is a PSK-initiator-lookup mechanism; pubkey
		// connections keep their pre-fix shape (no invented expected id).
		conn.at(t, "remote").hasNoSetting(t, "id")
		if _, ok := parseSecretBlocks(t, text)["ike-gw"]; ok {
			t.Errorf("cert VPN must not emit a PSK secret block:\n%s", text)
		}
	})
}
