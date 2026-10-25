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
