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

func TestRenderConfigSkipsMixedIKEAuthentication_10879(t *testing.T) {
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {Name: "tun1", Gateway: "gw1", IPsecPolicy: "esp-pol"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-psk", "ike-ecdsa"}, PSK: config.Secret("shared-key")},
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
		t.Fatalf("renderConfig returned an error instead of skipping the conflicting VPN: %v", err)
	}
	if rendered["tun1"] {
		t.Fatal("renderConfig emitted a tunnel with mixed IKE authentication methods")
	}
	doc := parseSwanctlDoc(t, text)
	doc.at(t, "connections").hasNoChild(t, "tun1")
	doc.at(t, "secrets").hasNoChild(t, "ike-tun1")
}
