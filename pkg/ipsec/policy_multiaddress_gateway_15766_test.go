package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestIKEGatewayMultiAddressCompileValidateAndRender is the #15766
// (G16-01) regression: a multi-address IKE gateway authored as repeated
// `address` leaves, a bracket list `address [ ip1 ip2 ]`, or a single
// comma-separated `address ip1,ip2` token must compile (both the
// `security ike` and `security ipsec` gateway containers), pass strict
// endpoint validation per address, and render every peer address into
// swanctl `remote_addrs` — instead of keeping only the last address
// (schema lacked `multi: true`; compileIKE/compileIPsec assigned
// gw.Address = v last-wins), failing strict validation on the comma
// list, or pinning a single `remote.id` for a peer that may present
// either address.
//
// remote.id contract for a multi-address peer (report direction 3, as
// narrowed against strongSwan reality): `remote.id` is single-valued in
// swanctl, so a default pinned to ONE address would reject the same
// peer presenting from the other configured address. The renderer must
// therefore NOT pin a single default remote.id when the gateway (or an
// inline endpoint) carries more than one address; identity scoping is
// carried by the PSK selectors, which already emit one id-<n> per peer
// address (#14139). A single-address gateway keeps the #15193 default
// (remote.id = that address) — the control arm below.
func TestIKEGatewayMultiAddressCompileValidateAndRender(t *testing.T) {
	compileLines := func(t *testing.T, lines []string) *config.IPsecConfig {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, line := range lines {
			path, err := config.ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return &cfg.Security.IPsec
	}

	base := func(gwPrefix string, addrLines ...string) []string {
		lines := []string{
			"set security ike proposal p1 authentication-method pre-shared-keys",
			"set security ike proposal p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal p1 authentication-algorithm sha-256",
			"set security ike proposal p1 dh-group group14",
			"set security ike policy pol1 proposals p1",
			"set security ike policy pol1 pre-shared-key ascii-text secret",
			"set security ike gateway gw1 ike-policy pol1",
			"set security ipsec proposal esp1 protocol esp",
			"set security ipsec proposal esp1 encryption-algorithm aes-256-cbc",
			"set security ipsec proposal esp1 authentication-algorithm hmac-sha-256-128",
			"set security ipsec policy epol1 proposals esp1",
			"set security ipsec vpn vpn1 bind-interface st0.0",
			"set security ipsec vpn vpn1 ike gateway gw1",
			"set security ipsec vpn vpn1 ike ipsec-policy epol1",
		}
		_ = gwPrefix
		lines = append(lines, addrLines...)
		lines = append(lines,
			gwPrefix+" local-address 198.51.100.10")
		return lines
	}

	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	renderAndCheck := func(t *testing.T, ipsecCfg *config.IPsecConfig) string {
		t.Helper()
		gw := ipsecCfg.Gateways["gw1"]
		if gw == nil {
			t.Fatalf("gateway gw1 missing: %+v", ipsecCfg.Gateways)
		}
		// Both peer addresses survive compilation, comma-joined in
		// authored order (the form remote_addrs renders verbatim).
		if gw.Address != "198.51.100.1,198.51.100.2" {
			t.Fatalf("gw.Address = %q, want %q (all peer addresses accumulated)", gw.Address, "198.51.100.1,198.51.100.2")
		}
		text, rendered, err := m.renderConfig(ipsecCfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw1"] {
			t.Fatalf("multi-address VPN must render, rendered=%v:\n%s", rendered, text)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw1")
		conn.requireSetting(t, "remote_addrs", "198.51.100.1,198.51.100.2")
		conn.requireSetting(t, "local_addrs", "198.51.100.10")
		// No single remote.id may be pinned: the peer can present from
		// either configured address, and swanctl remote.id takes one
		// identity. PSK selectors (below) carry the scoping instead.
		conn.at(t, "remote").hasNoSetting(t, "id")
		blk, ok := parseSecretBlocks(t, text)["ike-gw1"]
		if !ok {
			t.Fatalf("missing ike-gw1 secret block:\n%s", text)
		}
		for _, want := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.10"} {
			if !containsStr(blk.ids, want) {
				t.Errorf("ike-gw1 id selectors %v missing %q (one selector per peer address plus local owner)", blk.ids, want)
			}
		}
		return text
	}

	// Both gateway containers: compileIKE (`security ike gateway`) and
	// compileIPsec (`security ipsec gateway`) each carry their own
	// address reader; fixing one leaves the other last-wins.
	for _, gwPrefix := range []string{
		"set security ike gateway gw1",
		"set security ipsec gateway gw1",
	} {
		t.Run("repeated address "+gwPrefix, func(t *testing.T) {
			cfg := compileLines(t, base(gwPrefix,
				gwPrefix+" address 198.51.100.1",
				gwPrefix+" address 198.51.100.2"))
			renderAndCheck(t, cfg)
		})
		t.Run("bracket address "+gwPrefix, func(t *testing.T) {
			cfg := compileLines(t, base(gwPrefix,
				gwPrefix+" address [ 198.51.100.1 198.51.100.2 ]"))
			renderAndCheck(t, cfg)
		})
		t.Run("comma address "+gwPrefix, func(t *testing.T) {
			cfg := compileLines(t, base(gwPrefix,
				gwPrefix+" address 198.51.100.1,198.51.100.2"))
			renderAndCheck(t, cfg)
		})
		t.Run("comma-space address "+gwPrefix, func(t *testing.T) {
			// Comma-separated with a space still arrives as ONE value
			// slot: normalization keeps both endpoints.
			cfg := compileLines(t, []string{
				"set security ike proposal p1 authentication-method pre-shared-keys",
				"set security ike proposal p1 encryption-algorithm aes-256-cbc",
				"set security ike proposal p1 authentication-algorithm sha-256",
				"set security ike proposal p1 dh-group group14",
				"set security ike policy pol1 proposals p1",
				"set security ike policy pol1 pre-shared-key ascii-text secret",
				"set security ike gateway gw1 ike-policy pol1",
				gwPrefix + " address 198.51.100.1, 198.51.100.2",
				gwPrefix + " local-address 198.51.100.10",
				"set security ipsec proposal esp1 protocol esp",
				"set security ipsec proposal esp1 encryption-algorithm aes-256-cbc",
				"set security ipsec proposal esp1 authentication-algorithm hmac-sha-256-128",
				"set security ipsec policy epol1 proposals esp1",
				"set security ipsec vpn vpn1 bind-interface st0.0",
				"set security ipsec vpn vpn1 ike gateway gw1",
				"set security ipsec vpn vpn1 ike ipsec-policy epol1",
			})
			// The trailing "198.51.100.2" token must not be silently
			// dropped; at minimum address .1 with the full list is
			// required. (If the grammar rejects the extra token at
			// strict compile, that is a loud failure, not a silent
			// truncation — compileLines would have failed above.)
			renderAndCheck(t, cfg)
		})
	}

	// Control: a single-address gateway keeps the #15193 default
	// remote.id pin and renders exactly one remote address.
	t.Run("single address control keeps default remote id", func(t *testing.T) {
		cfg := compileLines(t, base("set security ike gateway gw1",
			"set security ike gateway gw1 address 198.51.100.1"))
		gw := cfg.Gateways["gw1"]
		if gw.Address != "198.51.100.1" {
			t.Fatalf("gw.Address = %q, want single address", gw.Address)
		}
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw1")
		conn.requireSetting(t, "remote_addrs", "198.51.100.1")
		conn.at(t, "remote").requireSetting(t, "id", `"198.51.100.1"`)
	})

	// A malformed SECOND endpoint must still fail strict validation:
	// splitting on commas must not launder a bad address past the
	// #5630 endpoint gate.
	t.Run("malformed second address rejected", func(t *testing.T) {
		lines := base("set security ike gateway gw1",
			"set security ike gateway gw1 address 198.51.100.1",
			"set security ike gateway gw1 address 10.0.0.999")
		tree := &config.ConfigTree{}
		for _, line := range lines {
			path, err := config.ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		if _, err := config.CompileConfig(tree); err == nil ||
			!strings.Contains(err.Error(), "10.0.0.999") {
			t.Fatalf("strict compile must reject malformed second gateway address, got %v", err)
		}
	})

	// Direct-constructed multi-address gateway (tolerant load / peer
	// sync shape): render must not pin the first address as remote.id.
	t.Run("direct multi-address gateway renders no pinned remote id", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "gw", PSK: "k", EstablishTunnels: "immediately"},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: "203.0.113.1, 203.0.113.2", LocalAddress: "198.51.100.1"},
			},
		}
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "remote").hasNoSetting(t, "id")
		blk := parseSecretBlocks(t, text)["ike-gw"]
		for _, want := range []string{"203.0.113.1", "203.0.113.2"} {
			if !containsStr(blk.ids, want) {
				t.Errorf("ike-gw id selectors %v missing %q", blk.ids, want)
			}
		}
	})

	// Inline multi-address endpoint (no gateway object): same rule —
	// no single remote.id pin for a multi-address dial target.
	t.Run("inline multi-address endpoint renders no pinned remote id", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "203.0.113.1,203.0.113.2", PSK: "k"},
			},
		}
		text, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "tun")
		conn.at(t, "remote").hasNoSetting(t, "id")
	})
}

// TestAddressFamilyHintMultiAddress15766 pins direction 2's second
// half: the family hint must classify from the first literal element
// of a comma-joined list, not fail net.ParseIP on the joined string
// and silently return the family-agnostic hint.
func TestAddressFamilyHintMultiAddress15766(t *testing.T) {
	if got := addressFamilyHint("198.51.100.1,198.51.100.2"); got != 4 {
		t.Errorf("addressFamilyHint(v4 list) = %d, want 4", got)
	}
	if got := addressFamilyHint("2001:db8::1, 2001:db8::2"); got != 6 {
		t.Errorf("addressFamilyHint(v6 list) = %d, want 6", got)
	}
	if got := addressFamilyHint("198.51.100.1"); got != 4 {
		t.Errorf("addressFamilyHint(single v4) = %d, want 4 (control)", got)
	}
	if got := addressFamilyHint("peer.example.com"); got != 0 {
		t.Errorf("addressFamilyHint(hostname) = %d, want 0 (control)", got)
	}
	gw := &config.IPsecGateway{Name: "gw", Address: "2001:db8::1,198.51.100.1"}
	if got := gatewayRemoteFamilyHint(gw); got != 6 {
		t.Errorf("gatewayRemoteFamilyHint(mixed list) = %d, want 6 (first literal)", got)
	}
}
