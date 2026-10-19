package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15193 (D04-01): the #3952 PSK id selector scopes the secret to the peer
// ADDRESS only, and no remote.id is rendered for a fixed-address gateway.
// With no remote-identity/local-identity (the Junos default shape), charon
// acting as INITIATOR looks the key up as (local-ip, %any), finds no secret
// whose id list contains the local identity, and aborts IKE_AUTH. Every
// xpf-initiated path fails; only peer-initiated SAs come up and two xpf
// boxes in this shape never establish the tunnel either way.
//
// Contract pinned here (fix direction: render remote id = peer address AND
// add this side's local identity/address as a second secret owner, so both
// selector spells required by charon's lookups resolve):
//
//   - fixed-address GW, no identities, no explicit local-address: remote.id
//     is the peer address and the secret owners include the local side
//     (%any) so the initiator lookup (<local ip>, %any) matches regardless of
//     which local source address charon picks.
//   - fixed-address GW, no identities, explicit LocalAddress: secret owners
//     are exactly {peer address, local address} — the peer selector keeps
//     #3952/#14591 isolation (no cross-peer claim) and the local address is
//     the exact initiator lookup key.
//   - multi-address GW: remote.id is the FIRST address (Junos default
//     remote identity = gateway address) and the secret carries one selector
//     per peer address plus the local address.
//   - local-identity configured (no remote-identity): local.id unchanged,
//     remote.id defaults to the peer address, secret owners include the
//     configured local identity (never re-adds the raw local address when an
//     explicit local identity exists — strongSwan uses the configured id).
//   - remote-identity configured: both ids and the secret owners are
//     byte-identical to pre-fix (#3952 control).
//   - IPv6 fixed address: same treatment with the v6 peer/local addresses.
//   - two fixed-address default-shape VPNs: each secret is claimed by its
//     own peer only; the shared %any owner alone never lets one VPN's secret
//     match the other peer (isolation comes from the peer selector — an
//     extra local owner can never cause a wrong-peer match).

func initiatorCfg15193(gw *config.IPsecGateway, psk string) *config.IPsecConfig {
	return &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: gw.Name, PSK: config.Secret(psk), EstablishTunnels: "immediately"},
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
		// Peer selector (responder + discriminating owner, #3952 kept).
		if !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("ike-gw id selectors %v missing peer 203.0.113.1", blk.ids)
		}
		// Initiator owner: charon looks the key up as (<local ip>, %any)
		// when we initiate with no local identity/address; without an
		// owner matching that lookup the secret is never selected.
		if !containsStr(blk.ids, "%any") {
			t.Errorf("ike-gw id selectors %v missing local initiator owner %%any (charon initiator lookup (<local ip>, %%any) finds no key)", blk.ids)
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
		if !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("id selectors %v missing peer 203.0.113.1", blk.ids)
		}
		// Exact initiator key: with local_addrs pinned, charon's lookup is
		// (198.51.100.1, 203.0.113.1) — the local address must be an owner.
		if !containsStr(blk.ids, "198.51.100.1") {
			t.Errorf("id selectors %v missing local initiator owner 198.51.100.1", blk.ids)
		}
		if containsStr(blk.ids, "%any") {
			t.Errorf("id selectors %v: %%any owner must not be emitted when the local address is the exact key (peer-address discrimination depends on it)", blk.ids)
		}
	})

	t.Run("multi address defaults remote id to first and scopes every address", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "203.0.113.1, 203.0.113.2", LocalAddress: "198.51.100.1",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		// remote.id is single-valued in swanctl: Junos's default is the
		// gateway address — the first of the list.
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)

		blk := parseSecretBlocks(t, text)["ike-gw"]
		for _, want := range []string{"203.0.113.1", "203.0.113.2", "198.51.100.1"} {
			if !containsStr(blk.ids, want) {
				t.Errorf("id selectors %v missing %q (one selector per peer address plus local owner)", blk.ids, want)
			}
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
		if !containsStr(blk.ids, "2001:db8:ffff::1") || !containsStr(blk.ids, "2001:db8:1::1") {
			t.Errorf("id selectors %v, want peer 2001:db8:ffff::1 and local 2001:db8:1::1", blk.ids)
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
		if !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("id selectors %v missing peer 203.0.113.1", blk.ids)
		}
		if !containsStr(blk.ids, "@fw.example.com") {
			t.Errorf("id selectors %v missing configured local identity @fw.example.com (initiator lookup key)", blk.ids)
		}
		if containsStr(blk.ids, "198.51.100.1") {
			t.Errorf("id selectors %v: raw local address must not be added when an explicit local identity is configured (strongSwan uses the configured id)", blk.ids)
		}
		if containsStr(blk.ids, "%any") {
			t.Errorf("id selectors %v: %%any must not be added when a local identity is configured", blk.ids)
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
		if len(blk.ids) != 2 || !containsStr(blk.ids, "@peer.example.com") || !containsStr(blk.ids, "@fw.example.com") {
			t.Errorf("id selectors %v, want exactly [@peer.example.com @fw.example.com] (pre-fix #3952 shape)", blk.ids)
		}
	})

	t.Run("two default-shape VPNs keep peer isolation under shared initiator owner", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"a": {Gateway: "gw-a", PSK: "secret-a"},
				"b": {Gateway: "gw-b", PSK: "secret-b"},
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
		// Each secret claims its own peer; the peer selector is what keeps
		// charon from binding secret-a to peer 203.0.113.2.
		if !containsStr(a.ids, "203.0.113.1") || containsStr(a.ids, "203.0.113.2") {
			t.Errorf("ike-gw-a selectors %v must claim 203.0.113.1 only among peers", a.ids)
		}
		if !containsStr(b.ids, "203.0.113.2") || containsStr(b.ids, "203.0.113.1") {
			t.Errorf("ike-gw-b selectors %v must claim 203.0.113.2 only among peers", b.ids)
		}
		// Both carry the initiator owner so each can initiate; a shared
		// local owner cannot cross peers because the peer selector differs.
		if !containsStr(a.ids, "%any") || !containsStr(b.ids, "%any") {
			t.Errorf("initiator owners: a=%v b=%v, want %%any on both", a.ids, b.ids)
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
