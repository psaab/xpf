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
// Fix contract pinned here:
//   - hostname-addressed gateway, no remote-identity: remote_addrs
//     still dials the hostname (strongSwan DNS-resolves it), but NO
//     remote.id is rendered (no hostname identity pin) and the secret
//     carries no hostname peer selector; the local owner (%any /
//     pinned local address / local-id) remains so charon's initiator
//     lookup can still select the secret.
//   - inline hostname endpoint (no gateway object): same — no
//     remote.id pin, no hostname secret selector.
//   - IP-literal control (gateway and inline): remote.id = the IP and
//     the secret peer selector = the IP, byte-identical to pre-fix
//     (#15193/#3952 control).
//   - explicit remote-identity on a hostname gateway still wins
//     (rendered exactly as configured and used as the sole peer
//     selector) — the documented workaround is unchanged.
//   - IPv6 literal control keeps its pin (the IP check is
//     family-agnostic, not v4-only).
//   - mixed multi-address list (hostname + IP): only the IP element
//     becomes a peer selector; the hostname element contributes none.
//
// FAIL-ON-REVERT: reverting the netip.ParseAddr gate in
// defaultRemoteID, the inline arm, or pskIDSelectorsLocal restores the
// hostname remote.id / hostname selector and turns the hostname cells
// red, while the IP controls stay green.

func TestHostnameAddressNoRemoteID16680(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("hostname gateway no remote id no hostname selector", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "peer.example.test",
		}, "site-secret")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("hostname-addressed VPN must render, rendered=%v:\n%s", rendered, text)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		// The hostname is still the dial target.
		conn.requireSetting(t, "remote_addrs", "peer.example.test")
		// #16680 core: no hostname identity may be pinned.
		conn.at(t, "remote").hasNoSetting(t, "id")
		conn.at(t, "local").hasNoSetting(t, "id")

		blk, ok := parseSecretBlocks(t, text)["ike-gw"]
		if !ok {
			t.Fatalf("missing ike-gw secret block:\n%s", text)
		}
		if containsStr(blk.ids, "peer.example.test") {
			t.Errorf("id selectors %v contain hostname peer selector peer.example.test; a hostname is not the identity the peer presents (its resolved IP is)", blk.ids)
		}
		// Initiator selection must still work: with no local address
		// or local-id configured the local owner is %any (#15193).
		if !containsStr(blk.ids, "%any") {
			t.Errorf("id selectors %v missing local initiator owner %%any; charon initiator lookup would find no key", blk.ids)
		}
	})

	t.Run("hostname gateway with local address keeps local owner only", func(t *testing.T) {
		cfg := initiatorCfg15193(&config.IPsecGateway{
			Name: "gw", Address: "peer.example.test", LocalAddress: "198.51.100.1",
		}, "site-secret")
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.requireSetting(t, "remote_addrs", "peer.example.test")
		conn.at(t, "remote").hasNoSetting(t, "id")
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if containsStr(blk.ids, "peer.example.test") {
			t.Errorf("id selectors %v contain hostname selector", blk.ids)
		}
		if !containsStr(blk.ids, "198.51.100.1") {
			t.Errorf("id selectors %v missing pinned local owner 198.51.100.1", blk.ids)
		}
		if containsStr(blk.ids, "%any") {
			t.Errorf("id selectors %v: %%any must not be added when the local address is pinned", blk.ids)
		}
	})

	t.Run("inline hostname endpoint no remote id", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "peer.example.test", PSK: config.NewSecret("k")},
			},
			Gateways:  map[string]*config.IPsecGateway{},
			Proposals: map[string]*config.IPsecProposal{},
		}
		text := m.generateConfig(cfg)
		conn := parseSwanctlDoc(t, text).at(t, "connections", "tun")
		conn.requireSetting(t, "remote_addrs", "peer.example.test")
		conn.at(t, "remote").hasNoSetting(t, "id")
		blk, ok := parseSecretBlocks(t, text)["ike-tun"]
		if !ok {
			t.Fatalf("missing ike-tun secret block:\n%s", text)
		}
		if containsStr(blk.ids, "peer.example.test") {
			t.Errorf("inline id selectors %v contain hostname selector peer.example.test", blk.ids)
		}
		if !containsStr(blk.ids, "%any") {
			t.Errorf("inline id selectors %v missing local owner %%any", blk.ids)
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
