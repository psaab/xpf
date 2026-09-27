package ipsec

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestResolveIKESettingsRejectsMixedConnectionSettings_10879(t *testing.T) {
	for _, tc := range []struct {
		name       string
		first      string
		second     string
		firstAuth  string
		secondAuth string
		firstLife  int
		secondLife int
		want       string
	}{
		{
			name:       "mixed auth first",
			first:      "ike-psk",
			second:     "ike-ecdsa",
			firstAuth:  "pre-shared-keys",
			secondAuth: "ecdsa-signatures",
			firstLife:  3600,
			secondLife: 3600,
			want:       "authentication methods",
		},
		{
			name:       "mixed auth reversed",
			first:      "ike-ecdsa",
			second:     "ike-psk",
			firstAuth:  "ecdsa-signatures",
			secondAuth: "pre-shared-keys",
			firstLife:  3600,
			secondLife: 3600,
			want:       "authentication methods",
		},
		{
			name:       "mixed lifetime first",
			first:      "ike-short",
			second:     "ike-long",
			firstAuth:  "pre-shared-keys",
			secondAuth: "pre-shared-keys",
			firstLife:  3600,
			secondLife: 28800,
			want:       "lifetime-seconds",
		},
		{
			name:       "mixed lifetime reversed",
			first:      "ike-long",
			second:     "ike-short",
			firstAuth:  "pre-shared-keys",
			secondAuth: "pre-shared-keys",
			firstLife:  28800,
			secondLife: 3600,
			want:       "lifetime-seconds",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.IPsecConfig{
				IKEProposals: map[string]*config.IKEProposal{
					tc.first: {
						Name:            tc.first,
						AuthMethod:      tc.firstAuth,
						EncryptionAlg:   "aes-256-cbc",
						AuthAlg:         "sha-256",
						DHGroup:         14,
						LifetimeSeconds: tc.firstLife,
					},
					tc.second: {
						Name:            tc.second,
						AuthMethod:      tc.secondAuth,
						EncryptionAlg:   "aes-128-cbc",
						AuthAlg:         "sha-256",
						DHGroup:         14,
						LifetimeSeconds: tc.secondLife,
					},
				},
				IKEPolicies: map[string]*config.IKEPolicy{
					"ike-pol": {Name: "ike-pol", Proposals: []string{tc.first, tc.second}},
				},
			}
			gw := &config.IPsecGateway{IKEPolicy: "ike-pol"}
			_, _, _, _, err := resolveIKESettings(cfg, gw)
			if !errors.Is(err, errProposalUnresolved) {
				t.Fatalf("resolveIKESettings error = %v, want errProposalUnresolved", err)
			}
			for _, want := range []string{tc.first, tc.second, tc.want} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestRenderConfigSkipsMixedIKEAuthenticationWithoutSuppressingHealthyVPN_10879(t *testing.T) {
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1":     {Name: "tun1", Gateway: "gw1", IPsecPolicy: "esp-pol"},
			"tun-good": {Name: "tun-good", Gateway: "gw-good", IPsecPolicy: "esp-pol"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1":     {Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"},
			"gw-good": {Name: "gw-good", Address: "192.0.2.2", IKEPolicy: "ike-good"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol":  {Name: "ike-pol", Proposals: []string{"ike-psk", "ike-ecdsa"}, PSK: config.Secret("bad-shared-key")},
			"ike-good": {Name: "ike-good", Proposals: []string{"ike-good-a", "ike-good-b"}, PSK: config.Secret("good-shared-key")},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-psk": {
				Name: "ike-psk", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc",
				AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 3600,
			},
			"ike-ecdsa": {
				Name: "ike-ecdsa", AuthMethod: "ecdsa-signatures", EncryptionAlg: "aes-128-cbc",
				AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 3600,
			},
			"ike-good-a": {
				Name: "ike-good-a", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc",
				AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 3600,
			},
			"ike-good-b": {
				Name: "ike-good-b", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-128-cbc",
				AuthAlg: "sha-256", DHGroup: 5, LifetimeSeconds: 3600,
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp-a"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: 14},
		},
	}

	text, rendered, err := New().renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig returned an error instead of skipping only the conflicting VPN: %v", err)
	}
	if rendered["tun1"] || !rendered["tun-good"] || len(rendered) != 1 {
		t.Fatalf("rendered VPNs = %v, want only healthy tun-good", rendered)
	}
	doc := parseSwanctlDoc(t, text)
	connections := doc.at(t, "connections")
	connections.hasNoChild(t, "tun1")
	connections.at(t, "tun-good").requireSetting(t, "proposals", "aes256-sha256-modp2048,aes128-sha256-modp1536")
	secrets := doc.at(t, "secrets")
	secrets.hasNoChild(t, "ike-tun1")
	secrets.at(t, "ike-tun-good")
}
