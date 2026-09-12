package ipsec

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func vpnCfg9495(names ...string) *config.IPsecConfig {
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol": {Name: "pol", Proposals: []string{"prop"}, PSK: "secret-9495"},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"prop": {Name: "prop", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "192.0.2.1", IKEPolicy: "pol"},
		},
		VPNs: map[string]*config.IPsecVPN{},
	}
	for _, n := range names {
		cfg.VPNs[n] = &config.IPsecVPN{Name: n, Gateway: "gw"}
	}
	return cfg
}

// TestSectionBreakingNameIsSkippedAndTheFileStillLoads9495 is the render belt. A persisted or
// peer-synced VPN whose name breaks its section is skipped along with its secret, and the healthy
// tunnel beside it renders into a document that parses, with exactly that connection and that
// secret. Without the belt strongSwan discards EVERY tunnel in the file. Assertions go through
// the parsed document, not substrings of the render (#6824).
func TestSectionBreakingNameIsSkippedAndTheFileStillLoads9495(t *testing.T) {
	for _, hostile := range []string{"evil } # {", "a.b", `a"b`, "a:b", "x { children { p { mode = transport } } } y"} {
		doc := parseSwanctlDoc(t, New().generateConfig(vpnCfg9495("plain", hostile)))
		if got := doc.at(t, "connections").childNames(); !reflect.DeepEqual(got, []string{"plain"}) {
			t.Errorf("hostile name %q: connections = %v, want only [plain]", hostile, got)
		}
		if got := doc.at(t, "secrets").childNames(); !reflect.DeepEqual(got, []string{"ike-plain"}) {
			t.Errorf("hostile name %q: secrets = %v, want only [ike-plain]", hostile, got)
		}
		doc.hasNoValueSubstringAnywhere(t, "transport")
	}
}

// TestLoadsTodayNameStillRenders9495: the belt is narrower than the commit allowlist. A name that
// loaded verbatim in the measurement ('/' here) is refused at commit, but still renders when
// persisted, so an upgrade does not take down a working tunnel.
func TestLoadsTodayNameStillRenders9495(t *testing.T) {
	doc := parseSwanctlDoc(t, New().generateConfig(vpnCfg9495("a/b")))
	doc.at(t, "connections", "a/b")
	doc.at(t, "secrets", "ike-a/b")
}
