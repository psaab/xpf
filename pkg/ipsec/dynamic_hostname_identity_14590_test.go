package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14590: Junos `dynamic hostname <fqdn>` identifies a dynamic-IP peer by the
// IKE identity it presents; it is NOT a DNS endpoint to dial. The render must
// be responder-only: remote_addrs = %any, remote { id = "@<fqdn>" }, no
// start_action, responder DPD (clear), and the PSK scoped by that identity —
// not a secret selector of the bare hostname as a dial address and never
// `remote_addrs = <fqdn>` (strongSwan would DNS-resolve it and initiate).
func TestGenerateConfig_DynamicHostnameIdentity14590(t *testing.T) {
	for _, mode := range []string{"immediately", "on-traffic"} {
		t.Run(mode, func(t *testing.T) {
			m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
			cfg := &config.IPsecConfig{
				IKEPolicies: map[string]*config.IKEPolicy{
					"pol1": {Name: "pol1", Proposals: []string{"ike-p1"}},
				},
				IKEProposals: map[string]*config.IKEProposal{
					"ike-p1": {Name: "ike-p1", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
				},
				Gateways: map[string]*config.IPsecGateway{
					"dyn-gw": {
						Name:            "dyn-gw",
						DynamicHostname: "branch.example.net",
						ResponderOnly:   true,
						IKEPolicy:       "pol1",
						DPDEnable:       true,
						DeadPeerDetect:  "optimized",
					},
				},
				Proposals: map[string]*config.IPsecProposal{},
				VPNs: map[string]*config.IPsecVPN{
					"tun1": {
						Gateway:          "dyn-gw",
						BindInterface:    "st0.1",
						PSK:              "key456",
						EstablishTunnels: mode,
					},
				},
			}
			got := m.generateConfig(cfg)
			doc := parseSwanctlDoc(t, got)
			conn := doc.at(t, "connections", "tun1")
			conn.requireSetting(t, "remote_addrs", "%any")
			if v := conn.setting(t, "remote_addrs"); v == "branch.example.net" {
				t.Fatalf("dynamic hostname must not be rendered as a dial address:\n%s", got)
			}
			remote := conn.at(t, "remote")
			remote.requireSetting(t, "id", `"@branch.example.net"`)
			child := conn.at(t, "children", "tun1")
			child.hasNoSetting(t, "start_action")
			child.requireSetting(t, "dpd_action", "clear")

			blocks := parseSecretBlocks(t, got)
			blk, ok := blocks["ike-tun1"]
			if !ok {
				t.Fatalf("missing ike-tun1 secret block:\n%s", got)
			}
			if !containsStr(blk.ids, "@branch.example.net") {
				t.Errorf("PSK must be scoped by the dynamic identity @branch.example.net, got %v", blk.ids)
			}
		})
	}
}

// An explicit remote-identity still wins over the dynamic-hostname identity.
func TestGenerateConfig_DynamicHostnameExplicitRemoteIDWins14590(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol1": {Name: "pol1", Proposals: []string{"ike-p1"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {Name: "ike-p1", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		Gateways: map[string]*config.IPsecGateway{
			"dyn-gw": {
				Name:            "dyn-gw",
				DynamicHostname: "branch.example.net",
				ResponderOnly:   true,
				IKEPolicy:       "pol1",
				RemoteIDType:    "hostname",
				RemoteIDValue:   "other.example.net",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {Gateway: "dyn-gw", BindInterface: "st0.1", PSK: "key456"},
		},
	}
	got := m.generateConfig(cfg)
	conn := parseSwanctlDoc(t, got).at(t, "connections", "tun1")
	conn.requireSetting(t, "remote_addrs", "%any")
	conn.at(t, "remote").requireSetting(t, "id", `"@other.example.net"`)
}

// A defined gateway address still dials; only dynamic-hostname gateways
// become responder-only identities.
func TestGenerateConfig_AddressGatewayStillDials14590(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1"},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs:      map[string]*config.IPsecVPN{"tun": {Gateway: "gw", PSK: "key"}},
	}
	conn := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "tun")
	conn.requireSetting(t, "remote_addrs", "203.0.113.1")
	conn.at(t, "remote").hasNoSetting(t, "id")
}
