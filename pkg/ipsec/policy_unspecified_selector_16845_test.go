package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17875: a fixed gateway whose remote-identity is an ID_ANY spelling
// (e.g. inet 0.0.0.0) is rescued at commit by its real address
// (#16845 strict validator), and the PSK selector drop already scopes
// the secret by that address — but the connection render pinned
// remote.id = "0.0.0.0", telling charon to expect any identity. Treat
// an ID_ANY remote-identity as no explicit identity and fall back to
// the default (single) peer address, exactly as the PSK selector does.
func TestRemoteIDAnyNotRendered17875(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	mk := func(gw *config.IPsecGateway) *config.IPsecConfig {
		cfg := &config.IPsecConfig{
			VPNs:      map[string]*config.IPsecVPN{},
			Gateways:  map[string]*config.IPsecGateway{},
			Proposals: map[string]*config.IPsecProposal{},
		}
		cfg.VPNs["site"] = &config.IPsecVPN{Gateway: "gw", PSK: config.NewSecret("site-secret")}
		cfg.Gateways["gw"] = gw
		return cfg
	}

	t.Run("fixed gateway ID_ANY remote-identity rescued by real address renders address id", func(t *testing.T) {
		gw := &config.IPsecGateway{
			Name:          "gw",
			Address:       "203.0.113.1",
			RemoteIDType:  "inet",
			RemoteIDValue: "0.0.0.0",
		}
		text, rendered, err := m.renderConfig(mk(gw))
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("rescued fixed gateway must render, rendered=%v:\n%s", rendered, text)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)
		blk, ok := parseSecretBlocks(t, text)["ike-gw"]
		if !ok || len(blk.ids) != 1 || !containsStr(blk.ids, "203.0.113.1") {
			t.Errorf("PSK selectors = %v, want exactly [203.0.113.1]", blk.ids)
		}
	})

	t.Run("discriminating remote-identity still renders verbatim", func(t *testing.T) {
		gw := &config.IPsecGateway{
			Name:          "gw",
			Address:       "203.0.113.1",
			RemoteIDType:  "inet",
			RemoteIDValue: "203.0.113.2",
		}
		text, rendered, err := m.renderConfig(mk(gw))
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("gateway must render, rendered=%v:\n%s", rendered, text)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.2"`)
	})

	t.Run("no remote-identity keeps address default", func(t *testing.T) {
		gw := &config.IPsecGateway{Name: "gw", Address: "203.0.113.1"}
		text, rendered, err := m.renderConfig(mk(gw))
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("gateway must render, rendered=%v:\n%s", rendered, text)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)
	})
}

// #16845 (R3-F15-02): the render belts treated only "" / hostname as
// "no peer selector". A gateway addressed 0.0.0.0/::, an inline
// endpoint 0.0.0.0, and a responder-only gateway with
// remote-identity inet 0.0.0.0 rendered remote_addrs = 0.0.0.0,
// remote.id = "0.0.0.0" and PSK owners [0.0.0.0 %any] — ID_ANY, the
// unscoped PSK #15989/#14591 exist to refuse. The belts now skip every
// ID_ANY-spelled PSK VPN (peer selectors carry no unspecified entry);
// real-address and discriminating remote-id controls render unchanged.
func TestUnspecifiedSelector16845(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	mk := func(vpnName, gwName string, gw *config.IPsecGateway, inline string) *config.IPsecConfig {
		cfg := &config.IPsecConfig{
			VPNs:      map[string]*config.IPsecVPN{},
			Gateways:  map[string]*config.IPsecGateway{},
			Proposals: map[string]*config.IPsecProposal{},
		}
		gwRef := gwName
		if inline != "" {
			gwRef = inline
		}
		cfg.VPNs[vpnName] = &config.IPsecVPN{Gateway: gwRef, PSK: config.NewSecret("site-secret")}
		if gw != nil {
			cfg.Gateways[gwName] = gw
		}
		// Healthy sibling that must always render.
		cfg.VPNs["good"] = &config.IPsecVPN{Gateway: "gw-good", PSK: config.NewSecret("good-secret")}
		cfg.Gateways["gw-good"] = &config.IPsecGateway{Name: "gw-good", Address: "203.0.113.9"}
		return cfg
	}
	assertSkipped := func(t *testing.T, cfg *config.IPsecConfig, conn string) {
		t.Helper()
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered[conn] {
			t.Errorf("ID_ANY PSK VPN must be skipped at render (#16845):\n%s", text)
		}
		if !rendered["gw-good"] {
			t.Fatalf("healthy sibling must render, rendered=%v:\n%s", rendered, text)
		}
		blocks := parseSecretBlocks(t, text)
		if _, ok := blocks["ike-"+conn]; ok {
			t.Errorf("skipped ID_ANY VPN must not emit a secret block:\n%s", text)
		}
		for name, blk := range blocks {
			for _, id := range blk.ids {
				if id == "0.0.0.0" || id == "::" || id == "%any" || id == "%any6" || id == "*" {
					t.Errorf("secret %s carries ID_ANY selector %q (#16845):\n%s", name, id, text)
				}
			}
		}
	}

	t.Run("gateway address 0.0.0.0 skipped", func(t *testing.T) {
		assertSkipped(t, mk("site", "gw", &config.IPsecGateway{Name: "gw", Address: "0.0.0.0"}, ""), "gw")
	})
	t.Run("gateway address :: skipped", func(t *testing.T) {
		assertSkipped(t, mk("site", "gw", &config.IPsecGateway{Name: "gw", Address: "::"}, ""), "gw")
	})
	t.Run("inline gateway 0.0.0.0 skipped", func(t *testing.T) {
		// Inline endpoints render under the VPN name.
		assertSkipped(t, mk("site", "", nil, "0.0.0.0"), "site")
	})
	t.Run("responder-only remote-identity inet 0.0.0.0 skipped", func(t *testing.T) {
		assertSkipped(t, mk("site", "gw", &config.IPsecGateway{
			Name: "gw", ResponderOnly: true, LocalAddress: "198.51.100.10",
			RemoteIDType: "inet", RemoteIDValue: "0.0.0.0",
		}, ""), "gw")
	})
	t.Run("responder-only remote-identity inet6 :: skipped", func(t *testing.T) {
		assertSkipped(t, mk("site", "gw", &config.IPsecGateway{
			Name: "gw", ResponderOnly: true, LocalAddress: "198.51.100.10",
			RemoteIDType: "inet6", RemoteIDValue: "::",
		}, ""), "gw")
	})

	t.Run("real address control renders scoped", func(t *testing.T) {
		cfg := mk("site", "gw", &config.IPsecGateway{Name: "gw", Address: "203.0.113.1"}, "")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("real-address VPN must render (control), rendered=%v:\n%s", rendered, text)
		}
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || blk.ids[0] != "203.0.113.1" {
			t.Errorf("ike-gw selectors %v, want exactly [203.0.113.1]", blk.ids)
		}
		conn := parseSwanctlDoc(t, text).at(t, "connections", "gw")
		conn.requireSetting(t, "remote_addrs", "203.0.113.1")
		conn.at(t, "remote").requireSetting(t, "id", `"203.0.113.1"`)
	})

	t.Run("responder-only discriminating remote-id control renders scoped", func(t *testing.T) {
		cfg := mk("site", "gw", &config.IPsecGateway{
			Name: "gw", ResponderOnly: true, LocalAddress: "198.51.100.10",
			RemoteIDType: "inet", RemoteIDValue: "198.51.100.77",
		}, "")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("discriminating responder VPN must render (control), rendered=%v:\n%s", rendered, text)
		}
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || blk.ids[0] != "198.51.100.77" {
			t.Errorf("ike-gw selectors %v, want exactly [198.51.100.77]", blk.ids)
		}
	})

	t.Run("mixed unspecified and real address renders on real selector only", func(t *testing.T) {
		cfg := mk("site", "gw", &config.IPsecGateway{Name: "gw", Address: "0.0.0.0, 203.0.113.1"}, "")
		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("mixed VPN must render on its real selector, rendered=%v:\n%s", rendered, text)
		}
		blk := parseSecretBlocks(t, text)["ike-gw"]
		if len(blk.ids) != 1 || blk.ids[0] != "203.0.113.1" {
			t.Errorf("ike-gw selectors %v, want exactly [203.0.113.1] (no 0.0.0.0)", blk.ids)
		}
	})

	t.Run("pubkey wildcard gateway is unaffected", func(t *testing.T) {
		// Cert VPNs carry no PSK to scope; the belts are PSK-only.
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"cert": {Gateway: "gw"},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: "0.0.0.0", LocalCertificate: "fw-cert", IKEPolicy: "pol"},
			},
			IKEPolicies: map[string]*config.IKEPolicy{
				"pol": {Name: "pol", Proposals: []string{"p1"}},
			},
			IKEProposals: map[string]*config.IKEProposal{
				"p1": {Name: "p1", AuthMethod: "rsa-signatures", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			},
			Proposals: map[string]*config.IPsecProposal{},
		}
		_, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["gw"] {
			t.Fatalf("pubkey VPN must not be skipped by the PSK belt, rendered=%v", rendered)
		}
	})
}
