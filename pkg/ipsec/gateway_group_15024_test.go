package ipsec

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15024: two VPNs sharing one IKE gateway must render as ONE swanctl
// connection (named by the gateway) carrying both VPNs' children, so a peer
// that runs them as children of one IKE SA can negotiate either child's
// traffic selectors. Pre-fix each VPN rendered its own connection copying
// the gateway parameters; the peer's single IKE SA could only carry the
// first VPN's TS and rejected the second with TS_UNACCEPTABLE.

func gatewayGroupCfg15024() *config.IPsecConfig {
	return &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "198.51.100.1", IKEPolicy: "ike-pol"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-p1"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {Name: "ike-p1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14, AuthMethod: "pre-shared-keys"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"vpn1": {PSK: "secret-one", Name: "vpn1", Gateway: "gw", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: "10.1.0.0/24", RemoteIP: "10.9.1.0/24"},
				}},
			"vpn2": {PSK: "secret-two", Name: "vpn2", Gateway: "gw", IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts2": {Name: "ts2", LocalIP: "10.2.0.0/24", RemoteIP: "10.9.2.0/24"},
				}},
		},
	}
}

func TestGatewayGroupRendersOneConnection15024(t *testing.T) {
	m := &Manager{}
	text, rendered, err := m.renderConfig(gatewayGroupCfg15024())
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if len(rendered) != 1 || !rendered["gw"] {
		t.Fatalf("rendered = %v, want exactly {gw} (one connection per gateway)\n%s", rendered, text)
	}
	doc := parseSwanctlDoc(t, text)
	conns := doc.at(t, "connections")
	if got := conns.childNames(); !reflect.DeepEqual(got, []string{"gw"}) {
		t.Fatalf("connections = %v, want [gw]\n%s", got, text)
	}
	conn := conns.at(t, "gw")
	conn.requireSetting(t, "remote_addrs", "198.51.100.1")
	kids := conn.at(t, "children").childNames()
	want := []string{"vpn1-ts1", "vpn2-ts2"}
	if !reflect.DeepEqual(kids, want) {
		t.Fatalf("children of gw = %v, want %v\n%s", kids, want, text)
	}
}

func TestGatewayGroupSecretsAndIndex15024(t *testing.T) {
	cfg := gatewayGroupCfg15024()
	m := &Manager{}
	text, _, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	// Both VPNs' PSKs are scoped under the single gateway connection's secret.
	secrets := parseSwanctlDoc(t, text).at(t, "secrets")
	if got := secrets.childNames(); !reflect.DeepEqual(got, []string{"ike-gw"}) {
		t.Fatalf("secrets = %v, want [ike-gw]\n%s", got, text)
	}
	if s := secrets.at(t, "ike-gw").setting(t, "secret"); s != `"secret-one,secret-two"` && s != `"secret-two,secret-one"` {
		t.Fatalf("ike-gw secret = %s, want both VPN PSKs\n%s", s, text)
	}

	idx := BuildSANameIndex(cfg)
	if got := idx.VPNs("gw"); !reflect.DeepEqual(got, []string{"vpn1", "vpn2"}) {
		t.Errorf("index gw = %v, want [vpn1 vpn2]", got)
	}
	if got := idx.VPNs("vpn1-ts1"); !reflect.DeepEqual(got, []string{"vpn1"}) {
		t.Errorf("index vpn1-ts1 = %v, want [vpn1]", got)
	}
	if got := idx.VPNs("vpn2-ts2"); !reflect.DeepEqual(got, []string{"vpn2"}) {
		t.Errorf("index vpn2-ts2 = %v, want [vpn2]", got)
	}

	loaded, err := ExpectedLoadedConns(&config.Config{Security: config.SecurityConfig{IPsec: *cfg}})
	if err != nil {
		t.Fatalf("ExpectedLoadedConns: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("ExpectedLoadedConns = %v, want one gw connection", loaded)
	}
	gwConn := loaded["gw"]
	if gwConn == nil || !reflect.DeepEqual(gwConn.Children, []string{"vpn1-ts1", "vpn2-ts2"}) {
		t.Fatalf("ExpectedLoadedConns gw = %+v, want children [vpn1-ts1 vpn2-ts2]", gwConn)
	}
	if got := RenderedVPNSet(&config.Config{Security: config.SecurityConfig{IPsec: *cfg}}); !got["vpn1"] || !got["vpn2"] {
		t.Errorf("RenderedVPNSet must fence both grouped VPNs by VPN name: %v", got)
	}
	if cm := ConnectionNamesForVPN(&config.Config{Security: config.SecurityConfig{IPsec: *cfg}}); cm["vpn1"] != "gw" || cm["vpn2"] != "gw" {
		t.Errorf("ConnectionNamesForVPN = %v, want both -> gw", cm)
	}
}

// Control: a single VPN on its own gateway keeps its gateway-named
// connection with its own child, and two VPNs on DIFFERENT gateways stay
// two connections.
func TestGatewayGroupDistinctGatewaysStaySeparate15024(t *testing.T) {
	cfg := gatewayGroupCfg15024()
	cfg.Gateways["gw2"] = &config.IPsecGateway{Name: "gw2", Address: "198.51.100.2", IKEPolicy: "ike-pol"}
	cfg.VPNs["vpn2"].Gateway = "gw2"
	text, rendered, err := (&Manager{}).renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if len(rendered) != 2 || !rendered["gw"] || !rendered["gw2"] {
		t.Fatalf("rendered = %v, want {gw gw2}\n%s", rendered, text)
	}
	conns := parseSwanctlDoc(t, text).at(t, "connections")
	if got := conns.at(t, "gw", "children").childNames(); !reflect.DeepEqual(got, []string{"vpn1-ts1"}) {
		t.Errorf("gw children = %v, want [vpn1-ts1]", got)
	}
	if got := conns.at(t, "gw2", "children").childNames(); !reflect.DeepEqual(got, []string{"vpn2-ts2"}) {
		t.Errorf("gw2 children = %v, want [vpn2-ts2]", got)
	}
}
