package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15989 (H-4): a gateway-less PSK VPN (Gateway == "", rendered with no
// remote_addrs, so charon defaults to %any as responder) has no peer
// address or identity to scope its secret to. Pre-fix its secret carried
// a lone id-1 = "%any" selector, so a holder of any on-box PSK could
// authenticate into the tunnel by claiming the intended peer's identity.
// The render belt must skip it (no connection, no orphan secret, no
// "%any" anywhere), while healthy siblings — fixed-address and inline
// endpoints, whose peer address scopes the secret — keep rendering.
func TestGatewaylessPSK15989(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	gatewayless := func() *config.IPsecConfig {
		return &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"gwless": {Gateway: "", PSK: "gwless-secret", BindInterface: "st0.0"},
			},
			Gateways:  map[string]*config.IPsecGateway{},
			Proposals: map[string]*config.IPsecProposal{},
		}
	}

	t.Run("single gateway-less PSK VPN renders no lone %any secret", func(t *testing.T) {
		text, rendered, err := m.renderConfig(gatewayless())
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["gwless"] {
			t.Fatalf("gateway-less PSK VPN was rendered, want skip:\n%s", text)
		}
		doc := parseSwanctlDoc(t, text)
		doc.at(t, "connections").hasNoChild(t, "gwless")
		doc.at(t, "secrets").hasNoChild(t, "ike-gwless")
		if strings.Contains(text, "%any") {
			t.Fatalf("rendered swanctl contains a %%any selector:\n%s", text)
		}
	})

	t.Run("gateway-less PSK VPN skipped, healthy siblings render", func(t *testing.T) {
		cfg := gatewayless()
		cfg.Gateways["gw-site"] = &config.IPsecGateway{
			Name: "gw-site", Address: "203.0.113.1", LocalAddress: "198.51.100.10",
		}
		cfg.VPNs["site-a"] = &config.IPsecVPN{Gateway: "gw-site", PSK: "site-secret"}
		cfg.VPNs["inline"] = &config.IPsecVPN{Gateway: "192.0.2.9", PSK: "inline-secret"}

		text, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["gwless"] {
			t.Fatalf("gateway-less PSK VPN was rendered, want skip:\n%s", text)
		}
		if !rendered["gw-site"] {
			t.Fatalf("healthy named-gateway VPN must render, rendered=%v:\n%s", rendered, text)
		}
		if !rendered["inline"] {
			t.Fatalf("healthy inline-endpoint VPN must render, rendered=%v:\n%s", rendered, text)
		}
		doc := parseSwanctlDoc(t, text)
		doc.at(t, "connections").hasNoChild(t, "gwless")
		doc.at(t, "secrets").hasNoChild(t, "ike-gwless")

		blocks := parseSecretBlocks(t, text)
		// No secret in the render may carry "%any" as its SOLE selector
		// (#15989 acceptance). Healthy VPNs scope by peer address; the
		// #15193 local-owner %any may only accompany a peer selector.
		for name, blk := range blocks {
			if len(blk.ids) == 1 && blk.ids[0] == "%any" {
				t.Errorf("secret %s carries a lone %%any selector %v:\n%s", name, blk.ids, text)
			}
		}
		site, ok := blocks["ike-gw-site"]
		if !ok {
			t.Fatalf("missing ike-gw-site secret block:\n%s", text)
		}
		if !containsStr(site.ids, "203.0.113.1") {
			t.Errorf("ike-gw-site id selectors %v missing its peer 203.0.113.1", site.ids)
		}
		inline, ok := blocks["ike-inline"]
		if !ok {
			t.Fatalf("missing ike-inline secret block:\n%s", text)
		}
		if !containsStr(inline.ids, "192.0.2.9") {
			t.Errorf("ike-inline id selectors %v missing its peer 192.0.2.9", inline.ids)
		}
	})
}

// collisionCfg15989 is the #15989-fold name collision: a skipped
// gateway-less PSK VPN named "aaa" and a healthy VPN "site" referencing
// the addressed IKE gateway also named "aaa". The healthy render is
// connection "aaa" with only child "site"; the skipped VPN must never
// borrow that connection in name-based projections.
func collisionCfg15989(sitePSK string) *config.IPsecConfig {
	return &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"aaa":  {Gateway: "", PSK: "gwless-secret", BindInterface: "st0.0", EstablishTunnels: "immediately"},
			"site": {Gateway: "aaa", PSK: config.Secret(sitePSK), BindInterface: "st0.1", EstablishTunnels: "immediately"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"aaa": {Name: "aaa", Address: "203.0.113.1", LocalAddress: "198.51.100.10"},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
}

// TestGatewaylessNameCollision15989 pins the fold: name projections must
// derive from actually-rendered per-VPN membership, not connection-name
// presence. On tolerant load / HA sync (strict commit refuses the
// gateway-less VPN), the skipped "aaa" must be absent from
// ConnectionNamesForVPN/RenderedVPNSet, ExpectedLoadedConns must equal
// the actual parsed render (child "site" only, concrete endpoints), and
// a changed live "aaa" connection must re-initiate child "site", never
// the unrendered child "aaa".
func TestGatewaylessNameCollision15989(t *testing.T) {
	cfg := collisionCfg15989("site-secret")
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	text, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if !rendered["aaa"] {
		t.Fatalf("healthy gateway connection aaa must render, rendered=%v:\n%s", rendered, text)
	}
	doc := parseSwanctlDoc(t, text)
	conn := doc.at(t, "connections", "aaa")
	conn.requireSetting(t, "local_addrs", "198.51.100.10")
	conn.requireSetting(t, "remote_addrs", "203.0.113.1")
	children := conn.at(t, "children")
	if got := children.childNames(); len(got) != 1 || got[0] != "site" {
		t.Fatalf("actual rendered children = %v, want [site]:\n%s", got, text)
	}

	full := &config.Config{}
	full.Security.IPsec = *cfg
	if got := ConnectionNamesForVPN(full); got["aaa"] != "" || got["site"] != "aaa" {
		t.Fatalf("ConnectionNamesForVPN = %v, want only site->aaa (skipped aaa absent)", got)
	}
	if got := RenderedVPNSet(full); got["aaa"] || !got["site"] {
		t.Fatalf("RenderedVPNSet = %v, want site only (skipped aaa absent)", got)
	}
	if idx := BuildSANameIndex(cfg); len(idx["aaa"]) != 1 || idx["aaa"][0] != "site" {
		t.Fatalf("BuildSANameIndex[aaa] = %v, want [site] (skipped aaa unindexed)", idx["aaa"])
	}

	want, err := expectedLoadedConns(cfg, nil)
	if err != nil {
		t.Fatalf("expectedLoadedConns: %v", err)
	}
	lc := want["aaa"]
	if lc == nil {
		t.Fatalf("ExpectedLoadedConns missing connection aaa: %v", want)
	}
	if len(lc.Children) != 1 || lc.Children[0] != "site" {
		t.Fatalf("ExpectedLoadedConns children = %v, want [site] (actual render)", lc.Children)
	}
	if len(lc.RemoteAddrs) != 1 || lc.RemoteAddrs[0] != "203.0.113.1" {
		t.Fatalf("ExpectedLoadedConns remote = %v, want [203.0.113.1] (actual render)", lc.RemoteAddrs)
	}
	if len(lc.LocalAddrs) != 1 || lc.LocalAddrs[0] != "198.51.100.10" {
		t.Fatalf("ExpectedLoadedConns local = %v, want [198.51.100.10] (actual render)", lc.LocalAddrs)
	}

	// Changed live connection "aaa": terminate it, then re-initiate the
	// rendered child "site" — never the skipped VPN's unrendered child.
	rec := &swanctlRecorder{}
	rm := newRecordingManager(t, rec)
	if err := rm.Apply(collisionCfg15989("old-secret")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	rec.listSAs = liveSAForVPN("site", "aaa")
	if err := rm.Apply(collisionCfg15989("rotated-secret")); err != nil {
		t.Fatalf("changed Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 1 || got[0] != "aaa" {
		t.Fatalf("terminate calls = %v, want [aaa]", got)
	}
	if got := rec.initiateCalls(); len(got) != 1 || got[0] != "site" {
		t.Fatalf("initiate calls = %v, want [site] (never skipped aaa)", got)
	}
}
