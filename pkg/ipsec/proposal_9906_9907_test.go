package ipsec

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func proposalRenderConfig9906(slot, value string) *config.IPsecConfig {
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "192.0.2.1"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw", IPsecPolicy: "esp-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp": {Name: "esp", Protocol: "esp", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
	}
	if slot == "ike" {
		cfg.Gateways["gw"].IKEPolicy = "ike-pol"
		cfg.IKEPolicies = map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike"}},
		}
		cfg.IKEProposals = map[string]*config.IKEProposal{
			"ike": {Name: "ike", EncryptionAlg: value, AuthAlg: "hmac-sha-256-128", DHGroup: 14},
		}
	} else {
		cfg.Proposals["esp"].EncryptionAlg = value
	}
	return cfg
}

// TestRenderRejectsProposalMetacharacters_9906 is the render-side belt for
// every metacharacter in each unquoted swanctl proposal slot. Without the
// resolver skip or output check, one cell would emit the attacker-controlled
// byte and this table goes RED.
func TestRenderRejectsProposalMetacharacters_9906(t *testing.T) {
	for _, slot := range []string{"ike", "esp"} {
		for _, metachar := range []string{"#", "{", "}", "="} {
			t.Run(slot+"/"+metachar, func(t *testing.T) {
				value := "aes256" + metachar + "x"
				text, rendered, err := (&Manager{}).renderConfig(proposalRenderConfig9906(slot, value))
				if err != nil {
					t.Fatalf("render returned error instead of tolerant skip: %v", err)
				}
				if rendered["tun"] {
					t.Fatalf("unsafe %s proposal was reported rendered", slot)
				}
				if strings.Contains(text, value) {
					t.Fatalf("unsafe proposal value reached output: %q", value)
				}
			})
		}
	}
}

func TestRenderRejectsBareNonAEADESP_9907(t *testing.T) {
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "192.0.2.1", IPsecPolicy: "esp-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"bare"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"bare": {Name: "bare", Protocol: "esp", EncryptionAlg: "aes-256-cbc"},
		},
	}
	text, rendered, err := (&Manager{}).renderConfig(cfg)
	if err != nil {
		t.Fatalf("render returned error instead of tolerant skip: %v", err)
	}
	if rendered["tun"] {
		t.Fatal("bare non-AEAD ESP VPN was reported rendered")
	}
	if strings.Contains(text, "esp_proposals") || strings.Contains(text, "aes256") {
		t.Fatalf("bare non-AEAD ESP reached output:\n%s", text)
	}
	if _, _, err := resolveESPSettings(cfg, cfg.VPNs["tun"]); err == nil || !strings.Contains(err.Error(), "authentication-algorithm") {
		t.Fatalf("resolver must reject bare non-AEAD ESP with named integrity error, got %v", err)
	}
}

func TestRenderAllowsAEADESPWithoutSeparateIntegrity_9907(t *testing.T) {
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "192.0.2.1", IPsecPolicy: "esp-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"gcm"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"gcm": {Name: "gcm", Protocol: "esp", EncryptionAlg: "aes-256-gcm"},
		},
	}
	text, rendered, err := (&Manager{}).renderConfig(cfg)
	if err != nil {
		t.Fatalf("render rejected AEAD without separate integrity: %v", err)
	}
	if !rendered["tun"] {
		t.Fatalf("AEAD ESP should render without auth, rendered=%v:\n%s", rendered, text)
	}
	childSA_3904(t, text, "tun").requireSetting(t, "esp_proposals", "aes256gcm16")
}

func TestRenderPreservesSafeProposalLists_9906(t *testing.T) {
	cfg := proposalRenderConfig9906("esp", "aes-256-cbc")
	cfg.Proposals["esp2"] = &config.IPsecProposal{
		Name: "esp2", Protocol: "esp", EncryptionAlg: "aes-128-cbc", AuthAlg: "hmac-sha-1-96",
	}
	cfg.Policies["esp-pol"].Proposals = []string{"esp", "esp2"}
	text, rendered, err := (&Manager{}).renderConfig(cfg)
	if err != nil || !rendered["tun"] {
		t.Fatalf("safe ESP proposal list failed to render: rendered=%v err=%v\n%s", rendered, err, text)
	}
	childSA_3904(t, text, "tun").requireSetting(t, "esp_proposals", "aes256-sha256,aes128-sha1")

	cfg.Gateways["gw"].IKEPolicy = "ike-pol"
	cfg.IKEPolicies = map[string]*config.IKEPolicy{
		"ike-pol": {Name: "ike-pol", Proposals: []string{"ike", "ike2"}},
	}
	cfg.IKEProposals = map[string]*config.IKEProposal{
		"ike":  {Name: "ike", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
		"ike2": {Name: "ike2", EncryptionAlg: "aes-128-cbc", AuthAlg: "hmac-sha-1-96", DHGroup: 14},
	}
	text, rendered, err = (&Manager{}).renderConfig(cfg)
	if err != nil || !rendered["tun"] {
		t.Fatalf("safe IKE proposal list failed to render: rendered=%v err=%v\n%s", rendered, err, text)
	}
	parseSwanctlDoc(t, text).at(t, "connections", "tun").
		requireSetting(t, "proposals", "aes256-sha256-modp2048,aes128-sha1-modp2048")
}

func TestProposalRenderErrorNamesUnsafeInput_9906(t *testing.T) {
	value := "aes256#injected"
	_, _, err := resolveESPSettings(proposalRenderConfig9906("esp", value), &config.IPsecVPN{IPsecPolicy: "esp-pol"})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%q", value)) {
		t.Fatalf("unsafe resolver error must name value %q, got %v", value, err)
	}
}
func TestLegacyDirectESPBadDHSentinel_9919(t *testing.T) {
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{
			"legacy": {
				Name:          "legacy",
				Protocol:      "esp",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "hmac-sha-256-128",
				DHGroup:       99,
			},
		},
	}
	_, _, err := resolveESPSettings(cfg, &config.IPsecVPN{IPsecPolicy: "legacy"})
	if !errors.Is(err, errDHGroupUnresolved) {
		t.Fatalf("legacy direct ESP bad DH must return errDHGroupUnresolved, got %v", err)
	}
}
