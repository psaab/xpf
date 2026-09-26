package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRenderTrafficSelectorSanitizesInjection is the #4098/#10884 render
// regression. A `traffic-selector local-ip / remote-ip` whose value carries a
// materialized newline (the Junos lexer turns a quoted `\n` into a real
// newline) is not a valid traffic-selector shape. The renderer must omit it
// rather than sanitize it into a different, still-invalid selector that makes
// charon discard the whole connection.
//
// Reverting the shared IsTrafficSelectorShape check in policy.go makes this
// test find the malformed VPN rendered again.
func TestRenderTrafficSelectorRejectsInjectionShape10884(t *testing.T) {
	const injectedLocal = "10.0.0.0/24\n        updown = /tmp/pwn.sh"
	const injectedRemote = "10.0.1.0/24\n        esp_proposals = null-null"

	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: injectedLocal, RemoteIP: injectedRemote},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
	}

	got := m.generateConfig(cfg)

	// A malformed selector cannot create directives or a broken child. The
	// whole VPN is omitted because it has no other renderable child.
	doc := parseSwanctlDoc(t, got)
	doc.hasNoSettingAnywhere(t, "updown")
	doc.hasNoSettingValuePrefixAnywhere(t, "esp_proposals", "null-null")
	doc.at(t, "connections").hasNoChild(t, "tun1")
}

// TestRenderTrafficSelectorNormalUnchanged is the over-reject negative control:
// a well-formed CIDR selector renders byte-for-byte as before (the sanitize
// belt is a no-op on a clean value).
func TestRenderTrafficSelectorNormalUnchanged(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: "10.0.0.0/24", RemoteIP: "10.0.1.0/24"},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
	}
	// #6824: the old needles carried a trailing "\n" purely to approximate
	// "the value ends here" -- an equality assertion at a known path states
	// that outright, and additionally pins WHICH child section carries it.
	child := parseSwanctlDoc(t, m.generateConfig(cfg)).
		at(t, "connections", "tun1", "children", "tun1-ts1")
	child.requireSetting(t, "local_ts", "10.0.0.0/24")
	child.requireSetting(t, "remote_ts", "10.0.1.0/24")
}
