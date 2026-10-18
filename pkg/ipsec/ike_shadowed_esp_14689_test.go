package ipsec

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14689 (D10-04): when an ike-policy was authored, Phase-1 must never be
// rendered from the ESP proposal table (cfg.Proposals) under the same name,
// even when no IKE proposal in the authored policy resolves. The legacy
// direct-proposal fallback is only for a gateway whose ike-policy value names
// no authored ike-policy at all.

func shadowedESPConfig14689(proposals []string) *config.IPsecConfig {
	return &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: proposals},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"prop-psk": {
				Name: "prop-psk", AuthMethod: "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 3600,
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			// ESP proposal shadowing the ike-policy name; distinct cipher
			// so a Phase-1 render from it is recognisable (aes128).
			"ike-pol": {
				Name: "ike-pol", Protocol: "esp", EncryptionAlg: "aes-128-cbc",
				AuthAlg: "hmac-sha-256-128", DHGroup: 14, LifetimeSeconds: 3600,
			},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"},
		},
	}
}

func TestResolveIKESettingsNeverRendersESPWhenIKEPolicyAuthored14689(t *testing.T) {
	t.Run("no IKE proposal resolves", func(t *testing.T) {
		cfg := shadowedESPConfig14689([]string{"does-not-exist"})
		gw := cfg.Gateways["gw1"]
		_, proposals, _, _, err := resolveIKESettings(cfg, gw)
		if err == nil {
			t.Fatalf("resolveIKESettings rendered Phase-1 from ESP fallback for authored ike-policy: proposals=%q", proposals)
		}
		if !errors.Is(err, errIKEChainUnresolved) {
			t.Fatalf("error = %v, want errIKEChainUnresolved", err)
		}
		if proposals != "" {
			t.Fatalf("proposals = %q, want empty on unresolved authored chain", proposals)
		}
	})

	t.Run("empty proposals list", func(t *testing.T) {
		cfg := shadowedESPConfig14689(nil)
		gw := cfg.Gateways["gw1"]
		_, proposals, _, _, err := resolveIKESettings(cfg, gw)
		if err == nil {
			t.Fatalf("resolveIKESettings rendered Phase-1 from ESP fallback for authored ike-policy with no proposals: proposals=%q", proposals)
		}
		if !errors.Is(err, errIKEChainUnresolved) {
			t.Fatalf("error = %v, want errIKEChainUnresolved", err)
		}
	})

	t.Run("partially dangling list renders only the resolved IKE proposal", func(t *testing.T) {
		cfg := shadowedESPConfig14689([]string{"dangling", "prop-psk"})
		gw := cfg.Gateways["gw1"]
		_, proposals, _, _, err := resolveIKESettings(cfg, gw)
		if err != nil {
			t.Fatalf("partially-dangling list with a resolvable IKE proposal must render that proposal: %v", err)
		}
		if !strings.Contains(proposals, "aes256") {
			t.Fatalf("proposals = %q, want the resolved IKE proposal (aes256), not the ESP shadow (aes128)", proposals)
		}
		if strings.Contains(proposals, "aes128") {
			t.Fatalf("proposals = %q rendered the ESP shadow as Phase-1", proposals)
		}
	})
}

func TestResolveIKESettingsLegacyFallbackOnlyWhenNoIKEPolicyAuthored14689(t *testing.T) {
	cfg := shadowedESPConfig14689(nil)
	delete(cfg.IKEPolicies, "ike-pol")
	gw := cfg.Gateways["gw1"]
	_, proposals, _, _, err := resolveIKESettings(cfg, gw)
	if err != nil {
		t.Fatalf("legacy direct-proposal fallback must still render when no ike-policy was authored: %v", err)
	}
	if !strings.Contains(proposals, "aes128") {
		t.Fatalf("proposals = %q, want legacy ESP-as-IKE render (aes128)", proposals)
	}
}
