package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16680 (R3-A16-02): a PSK gateway addressed by a hostname
// (`address peer.example.test`) with no remote-identity rendered
// remote { id = "peer.example.test" } — the bare hostname as an FQDN
// IKE identity — and scoped the PSK secret by that same hostname
// string. Junos defaults the peer identity to the resolved IP and
// strongSwan defaults to its own IP, so a default-identity peer is
// refused in both directions (AUTH_FAILED) and the tunnel never
// establishes, with no commit warning.
//
// Fix contract pinned here (hostname cells updated by #16708):
//   - hostname-addressed gateway, no remote-identity: NO remote.id is
//     rendered (no hostname identity pin, #16680) — and since #16708 the
//     VPN is SKIPPED at render (commit rejects it): the hostname yields
//     no peer selector, and the pre-#16708 local-owner-only secret
//     (%any / pinned local address) matched every peer on the box.
//     Configure a remote-identity (or use an IP literal) to render it.
//   - inline hostname endpoint (no gateway object): same — skipped.
//   - IP-literal control (gateway and inline): remote.id = the IP and
//     the secret peer selector = the IP, byte-identical to pre-fix
//     (#15193/#3952 control).
//   - explicit remote-identity on a hostname gateway still wins
//     (rendered exactly as configured and used as the sole peer
//     selector) — the documented workaround is unchanged, and it is now
//     REQUIRED for hostname gateways to render at all.
//   - IPv6 literal control keeps its pin (the IP check is
//     family-agnostic, not v4-only).
//   - mixed multi-address list (hostname + IP): only the IP element
//     becomes a peer selector; the hostname element contributes none,
//     and the VPN still renders on the strength of the IP selector.
//
// FAIL-ON-REVERT: reverting the netip.ParseAddr gate in
// defaultRemoteID, the inline arm, or pskPeerSelectors restores the
// hostname remote.id / hostname selector; reverting the #16708 render
// belt restores the local-owner-only secret — both turn the hostname
// cells red, while the IP controls stay green.

func TestHostnameAddressNoRemoteID16680(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("hostname gateway no remote id is skipped by 16708 belt", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "peer.example.test",
		}, "site-secret")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		// #16680: no hostname remote.id. #16708: with no peer selector
		// the VPN must not render at all (commit rejects it too) —
		// pre-fix it rendered with a lone %any local-owner secret.
		if rendered["gw"] {
			t.Fatalf("hostname-addressed PSK VPN with no remote-identity must be skipped (#16708), rendered=%v:\n%s", rendered, text)
		}
		if _, ok := parseSecretBlocks(t, text)["ike-gw"]; ok {
			t.Errorf("skipped hostname VPN must not emit a secret block:\n%s", text)
		}
	})

	t.Run("hostname gateway with local address is skipped by 16708 belt", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "peer.example.test", LocalAddress: "198.51.100.1",
		}, "site-secret")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["gw"] {
			t.Fatalf("hostname+local-address PSK VPN with no remote-identity must be skipped (#16708; a pinned local address is still a box-shared owner), rendered=%v:\n%s", rendered, text)
		}
		if _, ok := parseSecretBlocks(t, text)["ike-gw"]; ok {
			t.Errorf("skipped hostname VPN must not emit a secret block:\n%s", text)
		}
	})

	t.Run("inline hostname endpoint is skipped by 16708 belt", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "peer.example.test", PSK: config.NewSecret("k")},
			},
			Gateways:  map[string]*config.IPsecGateway{},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["tun"] {
			t.Fatalf("inline hostname PSK VPN with no remote-identity must be skipped (#16708), rendered=%v:\n%s", rendered, text)
		}
		if _, ok := parseSecretBlocks(t, text)["ike-tun"]; ok {
			t.Errorf("skipped inline hostname VPN must not emit a secret block:\n%s", text)
		}
	})

	t.Run("ip literal gateway control unchanged", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "203.0.113.1",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.requireSetting(t, "remote_addrs", "203.0.113.1")
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("id selectors %v missing IP peer selector 203.0.113.1 (control)", blk.ids)
		}
	})

	t.Run("inline ip endpoint control unchanged", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "203.0.113.1", PSK: config.NewSecret("k")},
			},
			Gateways:  map[string]*config.IPsecGateway{},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "tun")
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)
		blk := parseSecretBlocks(t, text)["ike-tun"]
		if !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("inline id selectors %v missing IP peer selector 203.0.113.1 (control)", blk.ids)
		}
	})

	t.Run("ipv6 literal control unchanged", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "2001:db8:ffff::1",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "remote").requireSetting(t, "id", `"2001:db8:ffff::1"`)
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if !containsStr(blk.ids, "2001:db8:ffff::1") {
			t.Errorf("id selectors %v missing IPv6 peer selector (control)", blk.ids)
		}
	})

	t.Run("explicit remote identity on hostname gateway still wins", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "peer.example.test",
			RemoteIDType: "hostname", RemoteIDValue: "peer.example.test",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.requireSetting(t, "remote_addrs", "peer.example.test")
		// Explicit identity is an @FQDN — distinct from the bare
		// hostname default that #16680 removes.
		conn.at(t, "remote").requireSetting(t, "id", `"@peer.example.test"`)
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if !containsStr(blk.ids, "@peer.example.test") {
			t.Errorf("id selectors %v missing explicit remote identity @peer.example.test", blk.ids)
		}
		if containsStr(blk.ids, "peer.example.test") {
			t.Errorf("id selectors %v contain bare hostname alongside explicit identity", blk.ids)
		}
	})

	t.Run("mixed hostname and ip list scopes ip only", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "peer.example.test, 203.0.113.1",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		// Multi-address: no single remote.id pin (#15766), and the
		// hostname element must not become a selector either.
		conn.at(t, "remote").hasNoSetting(t, "id")
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if containsStr(blk.ids, "peer.example.test") {
			t.Errorf("id selectors %v contain hostname selector from mixed list", blk.ids)
		}
		if !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("id selectors %v missing IP selector 203.0.113.1 from mixed list", blk.ids)
		}
	})

	// Direct helper pins so a future refactor cannot silently route
	// around the render-level cells above.
	t.Run("defaultRemoteID helper", func(t *testing.T) {
		cases := []struct {
			addr string
			want string
		}{
			{"peer.example.test", ""},
			{"203.0.113.1", "203.0.113.1"},
			{"2001:db8::1", "2001:db8::1"},
			{"203.0.113.1, 203.0.113.2", ""},
			{"", ""},
		}
		for _, tc := range cases {
			gw := &config.IPsecGateway{Name: "gw", Address: tc.addr}
			if got := defaultRemoteID(gw); got != tc.want {
				t.Errorf("defaultRemoteID(Address=%q) = %q, want %q", tc.addr, got, tc.want)
			}
		}
	})
}
