package ipsec

import (
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16676 (R3-A16-01): an inline-endpoint VPN named "siteA" and a gateway
// object "siteA" referenced by VPN "zzz" share one swanctl connection
// namespace since #15024. Pre-fix both folded into connection "siteA",
// the first sorted member supplied the peer, and the other VPN's
// children (incl. its st0 if_id) negotiated with the wrong peer.
//
// DEFECT cell: gateway siteA (10.200.0.3) <- zzz (st0.0); inline VPN
// siteA -> 10.200.0.1 (st0.1). Post-fix render = two connections:
// "siteA" (zzz, remote 10.200.0.3) and "inline-siteA" (siteA, remote
// 10.200.0.1), each with only its own child/if_id, so initiating zzz's
// child never reaches 10.200.0.1 and vice versa. CONTROL cell: two VPNs
// sharing the SAME gateway object still render one gateway connection.

func collisionCfg16676() *config.IPsecConfig {
	cfg := gatewayGroupCfg15024()
	// Gateway object siteA at 10.200.0.3, referenced by zzz.
	cfg.Gateways = map[string]*config.IPsecGateway{
		"siteA": {Name: "siteA", Address: "10.200.0.3", IKEPolicy: "ike-pol"},
	}
	cfg.VPNs = map[string]*config.IPsecVPN{
		"zzz": {PSK: config.NewSecret("zzz-secret"), Name: "zzz", Gateway: "siteA", IPsecPolicy: "ipsec-pol", BindInterface: "st0.0",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"ts1": {Name: "ts1", LocalIP: "10.1.0.0/24", RemoteIP: "10.9.1.0/24"},
			}},
		// Inline VPN named siteA dialing a DIFFERENT peer.
		"siteA": {PSK: config.NewSecret("inline-secret"), Name: "siteA", Gateway: "10.200.0.1", IPsecPolicy: "ipsec-pol", BindInterface: "st0.1",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"ts1": {Name: "ts1", LocalIP: "10.2.0.0/24", RemoteIP: "10.9.2.0/24"},
			}},
	}
	return cfg
}

func TestGatewayNameCollision16676(t *testing.T) {
	cfg := collisionCfg16676()
	m := &Manager{}
	text, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if len(rendered) != 2 || !rendered["siteA"] || !rendered["inline-siteA"] {
		t.Fatalf("rendered = %v, want {siteA inline-siteA} (two connections)\n%s", rendered, text)
	}
	doc := parseSwanctlDoc(t, text)
	conns := doc.at(t, "connections")
	if got := conns.childNames(); !reflect.DeepEqual(got, []string{"inline-siteA", "siteA"}) {
		t.Fatalf("connections = %v, want [inline-siteA siteA]\n%s", got, text)
	}
	// Gateway connection keeps its own peer and only zzz's child.
	gwConn := conns.at(t, "siteA")
	gwConn.requireSetting(t, "remote_addrs", "10.200.0.3")
	if got := gwConn.at(t, "children").childNames(); !reflect.DeepEqual(got, []string{"zzz-ts1"}) {
		t.Fatalf("siteA children = %v, want [zzz-ts1]\n%s", got, text)
	}
	zzzChild := gwConn.at(t, "children", "zzz-ts1")
	// st0.0 -> if_id (0<<16)|1 = 1.
	zzzChild.requireSetting(t, "if_id_in", "1")
	zzzChild.requireSetting(t, "if_id_out", "1")
	// Inline connection keeps its own peer and only its own child.
	inlineConn := conns.at(t, "inline-siteA")
	inlineConn.requireSetting(t, "remote_addrs", "10.200.0.1")
	if got := inlineConn.at(t, "children").childNames(); !reflect.DeepEqual(got, []string{"siteA-ts1"}) {
		t.Fatalf("inline-siteA children = %v, want [siteA-ts1]\n%s", got, text)
	}
	siteChild := inlineConn.at(t, "children", "siteA-ts1")
	// st0.1 -> if_id (0<<16)|2 = 2, on the inline peer's connection only.
	siteChild.requireSetting(t, "if_id_in", "2")
	siteChild.requireSetting(t, "if_id_out", "2")

	// Projections agree with the actual render.
	full := &config.Config{Security: config.SecurityConfig{IPsec: *cfg}}
	cm := ConnectionNamesForVPN(full)
	if cm["zzz"] != "siteA" || cm["siteA"] != "inline-siteA" {
		t.Fatalf("ConnectionNamesForVPN = %v, want zzz->siteA siteA->inline-siteA", cm)
	}
	if got := RenderedVPNSet(full); !got["zzz"] || !got["siteA"] {
		t.Fatalf("RenderedVPNSet = %v, want both", got)
	}
	loaded, err := ExpectedLoadedConns(full)
	if err != nil {
		t.Fatalf("ExpectedLoadedConns: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("ExpectedLoadedConns = %v, want 2 conns", loaded)
	}
	if lc := loaded["siteA"]; lc == nil || !reflect.DeepEqual(lc.Children, []string{"zzz-ts1"}) || !reflect.DeepEqual(lc.RemoteAddrs, []string{"10.200.0.3"}) {
		t.Fatalf("loaded siteA = %+v, want children [zzz-ts1] remote [10.200.0.3]", lc)
	}
	if lc := loaded["inline-siteA"]; lc == nil || !reflect.DeepEqual(lc.Children, []string{"siteA-ts1"}) || !reflect.DeepEqual(lc.RemoteAddrs, []string{"10.200.0.1"}) {
		t.Fatalf("loaded inline-siteA = %+v, want children [siteA-ts1] remote [10.200.0.1]", lc)
	}
	idx := BuildSANameIndex(cfg)
	if got := idx.VPNs("siteA"); !reflect.DeepEqual(got, []string{"zzz"}) {
		t.Errorf("index siteA = %v, want [zzz]", got)
	}
	if got := idx.VPNs("inline-siteA"); !reflect.DeepEqual(got, []string{"siteA"}) {
		t.Errorf("index inline-siteA = %v, want [siteA]", got)
	}
	if cols := idx.Collisions(); len(cols) != 0 {
		t.Errorf("index collisions = %v, want none after separation", cols)
	}
	// Secrets are per-connection, not folded.
	secrets := doc.at(t, "secrets")
	if got := secrets.childNames(); !reflect.DeepEqual(got, []string{"ike-inline-siteA", "ike-siteA"}) {
		t.Fatalf("secrets = %v, want [ike-inline-siteA ike-siteA]\n%s", got, text)
	}
	if !strings.Contains(text, "10.200.0.1") || !strings.Contains(text, "10.200.0.3") {
		t.Fatalf("both peers must appear in render:\n%s", text)
	}

	// CONTROL: two VPNs sharing the SAME gateway object still fold
	// into one gateway-named connection (#15024 unchanged).
	ctrl := gatewayGroupCfg15024()
	ctext, crendered, err := (&Manager{}).renderConfig(ctrl)
	if err != nil {
		t.Fatalf("control renderConfig: %v", err)
	}
	if len(crendered) != 1 || !crendered["gw"] {
		t.Fatalf("CONTROL rendered = %v, want {gw}\n%s", crendered, ctext)
	}
}

// #17731: the single "inline-" escape is NOT injective. Config:
//   - gateway siteA (10.200.0.3) <- zzz
//   - gateway inline-siteA (10.200.0.4) <- w
//   - inline VPN siteA -> 10.200.0.1
//
// Inline siteA collides with gateway siteA, so legacy code keys it
// inline-siteA — exactly the bare key of gateway inline-siteA. On the
// tolerant path the render belt then silently skips one distinct peer.
// Desired: three distinct connections/gateway groups: siteA (zzz),
// inline-siteA (w), inline-inline-siteA (inline siteA), with children and
// projections agreeing, so no peer is silently skipped.
func TestGatewayNameCollisionInlinePrefixedGateway17731(t *testing.T) {
	cfg := gatewayGroupCfg15024()
	cfg.Gateways = map[string]*config.IPsecGateway{
		"siteA":        {Name: "siteA", Address: "10.200.0.3", IKEPolicy: "ike-pol"},
		"inline-siteA": {Name: "inline-siteA", Address: "10.200.0.4", IKEPolicy: "ike-pol"},
	}
	cfg.VPNs = map[string]*config.IPsecVPN{
		"zzz": {PSK: config.NewSecret("zzz-secret"), Name: "zzz", Gateway: "siteA", IPsecPolicy: "ipsec-pol", BindInterface: "st0.0",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"ts1": {Name: "ts1", LocalIP: "10.1.0.0/24", RemoteIP: "10.9.1.0/24"},
			}},
		"w": {PSK: config.NewSecret("w-secret"), Name: "w", Gateway: "inline-siteA", IPsecPolicy: "ipsec-pol", BindInterface: "st0.1",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"ts1": {Name: "ts1", LocalIP: "10.2.0.0/24", RemoteIP: "10.9.2.0/24"},
			}},
		"siteA": {PSK: config.NewSecret("inline-secret"), Name: "siteA", Gateway: "10.200.0.1", IPsecPolicy: "ipsec-pol", BindInterface: "st0.2",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"ts1": {Name: "ts1", LocalIP: "10.3.0.0/24", RemoteIP: "10.9.3.0/24"},
			}},
	}
	wantInlineKey := "inline-inline-siteA"
	m := &Manager{}
	text, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if len(rendered) != 3 || !rendered["siteA"] || !rendered["inline-siteA"] || !rendered[wantInlineKey] {
		t.Fatalf("rendered = %v, want {siteA inline-siteA %s} (three connections)\n%s", rendered, wantInlineKey, text)
	}
	doc := parseSwanctlDoc(t, text)
	conns := doc.at(t, "connections")
	if got := conns.childNames(); !reflect.DeepEqual(got, []string{wantInlineKey, "inline-siteA", "siteA"}) {
		t.Fatalf("connections = %v, want [%s inline-siteA siteA]\n%s", got, wantInlineKey, text)
	}
	gwConn := conns.at(t, "siteA")
	gwConn.requireSetting(t, "remote_addrs", "10.200.0.3")
	if got := gwConn.at(t, "children").childNames(); !reflect.DeepEqual(got, []string{"zzz-ts1"}) {
		t.Fatalf("siteA children = %v, want [zzz-ts1]\n%s", got, text)
	}
	inlineGwConn := conns.at(t, "inline-siteA")
	inlineGwConn.requireSetting(t, "remote_addrs", "10.200.0.4")
	if got := inlineGwConn.at(t, "children").childNames(); !reflect.DeepEqual(got, []string{"w-ts1"}) {
		t.Fatalf("inline-siteA children = %v, want [w-ts1]\n%s", got, text)
	}
	wChild := inlineGwConn.at(t, "children", "w-ts1")
	wChild.requireSetting(t, "if_id_in", "2")
	wChild.requireSetting(t, "if_id_out", "2")
	inlineConn := conns.at(t, wantInlineKey)
	inlineConn.requireSetting(t, "remote_addrs", "10.200.0.1")
	if got := inlineConn.at(t, "children").childNames(); !reflect.DeepEqual(got, []string{"siteA-ts1"}) {
		t.Fatalf("%s children = %v, want [siteA-ts1]\n%s", wantInlineKey, got, text)
	}
	siteChild := inlineConn.at(t, "children", "siteA-ts1")
	siteChild.requireSetting(t, "if_id_in", "3")
	siteChild.requireSetting(t, "if_id_out", "3")
	full := &config.Config{Security: config.SecurityConfig{IPsec: *cfg}}
	cm := ConnectionNamesForVPN(full)
	if cm["zzz"] != "siteA" || cm["w"] != "inline-siteA" || cm["siteA"] != wantInlineKey {
		t.Fatalf("ConnectionNamesForVPN = %v, want zzz->siteA w->inline-siteA siteA->%s", cm, wantInlineKey)
	}
	if got := RenderedVPNSet(full); !got["zzz"] || !got["w"] || !got["siteA"] {
		t.Fatalf("RenderedVPNSet = %v, want all three VPNs", got)
	}
	if _, _, renderedMembers, err := m.renderConfigMembers(cfg); err != nil {
		t.Fatalf("renderConfigMembers: %v", err)
	} else if !renderedMembers["zzz"] || !renderedMembers["w"] || !renderedMembers["siteA"] {
		t.Fatalf("renderedMembers = %v, want all three VPNs", renderedMembers)
	}
	loaded, err := ExpectedLoadedConns(full)
	if err != nil {
		t.Fatalf("ExpectedLoadedConns: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("ExpectedLoadedConns = %v, want 3 conns", loaded)
	}
	if lc := loaded["siteA"]; lc == nil || !reflect.DeepEqual(lc.Children, []string{"zzz-ts1"}) || !reflect.DeepEqual(lc.RemoteAddrs, []string{"10.200.0.3"}) {
		t.Fatalf("loaded siteA = %+v, want children [zzz-ts1] remote [10.200.0.3]", lc)
	}
	if lc := loaded["inline-siteA"]; lc == nil || !reflect.DeepEqual(lc.Children, []string{"w-ts1"}) || !reflect.DeepEqual(lc.RemoteAddrs, []string{"10.200.0.4"}) {
		t.Fatalf("loaded inline-siteA = %+v, want children [w-ts1] remote [10.200.0.4]", lc)
	}
	if lc := loaded[wantInlineKey]; lc == nil || !reflect.DeepEqual(lc.Children, []string{"siteA-ts1"}) || !reflect.DeepEqual(lc.RemoteAddrs, []string{"10.200.0.1"}) {
		t.Fatalf("loaded %s = %+v, want children [siteA-ts1] remote [10.200.0.1]", wantInlineKey, lc)
	}
	idx := BuildSANameIndex(cfg)
	if got := idx.VPNs("siteA"); !reflect.DeepEqual(got, []string{"zzz"}) {
		t.Errorf("index siteA = %v, want [zzz]", got)
	}
	if got := idx.VPNs("inline-siteA"); !reflect.DeepEqual(got, []string{"w"}) {
		t.Errorf("index inline-siteA = %v, want [w]", got)
	}
	if got := idx.VPNs(wantInlineKey); !reflect.DeepEqual(got, []string{"siteA"}) {
		t.Errorf("index %s = %v, want [siteA]", wantInlineKey, got)
	}
	if cols := idx.Collisions(); len(cols) != 0 {
		t.Errorf("index collisions = %v, want none after separation", cols)
	}
	secrets := doc.at(t, "secrets")
	wantSecrets := []string{"ike-" + wantInlineKey, "ike-inline-siteA", "ike-siteA"}
	if got := secrets.childNames(); !reflect.DeepEqual(got, wantSecrets) {
		t.Fatalf("secrets = %v, want %v\n%s", got, wantSecrets, text)
	}
	for _, peer := range []string{"10.200.0.1", "10.200.0.3", "10.200.0.4"} {
		if !strings.Contains(text, peer) {
			t.Fatalf("peer %s must appear in render:\n%s", peer, text)
		}
	}
}

// #17731 control: one named gateway + one referencing VPN renders
// byte-identically to the pristine origin/master output captured before
// the production change. This pins stable names for non-colliding configs.
func TestGatewaySingleGatewayRenderByteIdentical17731(t *testing.T) {
	cfg := gatewayGroupCfg15024()
	cfg.Gateways = map[string]*config.IPsecGateway{
		"siteA": {Name: "siteA", Address: "10.200.0.3", IKEPolicy: "ike-pol"},
	}
	cfg.VPNs = map[string]*config.IPsecVPN{
		"zzz": {PSK: config.NewSecret("zzz-secret"), Name: "zzz", Gateway: "siteA", IPsecPolicy: "ipsec-pol", BindInterface: "st0.0",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"ts1": {Name: "ts1", LocalIP: "10.1.0.0/24", RemoteIP: "10.9.1.0/24"},
			}},
	}
	text, rendered, err := (&Manager{}).renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if len(rendered) != 1 || !rendered["siteA"] {
		t.Fatalf("rendered = %v, want {siteA}\n%s", rendered, text)
	}
	const want = "# xpf managed config - do not edit\n\nconnections {\n  siteA {\n    remote_addrs = 10.200.0.3\n    local {\n      auth = psk\n    }\n    remote {\n      auth = psk\n      id = \"10.200.0.3\"\n    }\n    proposals = aes256-sha256-modp2048\n    children {\n      zzz-ts1 {\n        local_ts = 10.1.0.0/24\n        remote_ts = 10.9.1.0/24\n        esp_proposals = aes256-sha256\n        start_action = trap\n        if_id_in = 1\n        if_id_out = 1\n      }\n    }\n  }\n}\n\nsecrets {\n  ike-siteA {\n    secret = \"zzz-secret\"\n    id-1 = \"10.200.0.3\"\n  }\n}\n"
	if text != want {
		t.Fatalf("single-gateway render not byte-identical:\n got: %q\nwant: %q", text, want)
	}
}
