package config

import (
	"strings"
	"testing"
)

func TestIKEPolicyRejectsMixedConnectionSettings_10879(t *testing.T) {
	for _, tc := range []struct {
		name       string
		first      string
		second     string
		firstAuth  string
		secondAuth string
		firstLife  string
		secondLife string
		want       string
	}{
		{
			name:       "mixed auth first",
			first:      "ike-psk",
			second:     "ike-ecdsa",
			firstAuth:  "pre-shared-keys",
			secondAuth: "ecdsa-signatures",
			firstLife:  "3600",
			secondLife: "3600",
			want:       "authentication-method",
		},
		{
			name:       "mixed auth reversed",
			first:      "ike-ecdsa",
			second:     "ike-psk",
			firstAuth:  "ecdsa-signatures",
			secondAuth: "pre-shared-keys",
			firstLife:  "3600",
			secondLife: "3600",
			want:       "authentication-method",
		},
		{
			name:       "mixed lifetime first",
			first:      "ike-short",
			second:     "ike-long",
			firstAuth:  "pre-shared-keys",
			secondAuth: "pre-shared-keys",
			firstLife:  "3600",
			secondLife: "28800",
			want:       "lifetime-seconds",
		},
		{
			name:       "mixed lifetime reversed",
			first:      "ike-long",
			second:     "ike-short",
			firstAuth:  "pre-shared-keys",
			secondAuth: "pre-shared-keys",
			firstLife:  "28800",
			secondLife: "3600",
			want:       "lifetime-seconds",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := ikePolicyAgreementTree10879(t, tc.first, tc.second, tc.firstAuth, tc.secondAuth, tc.firstLife, tc.secondLife)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatal("CompileConfig accepted incompatible IKE proposal connection settings")
			}
			for _, want := range []string{tc.first, tc.second, tc.want} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestIKEPolicyMixedConnectionSettingsWarnsOnLenientCompile_10879(t *testing.T) {
	tree := ikePolicyAgreementTree10879(
		t, "ike-psk", "ike-ecdsa", "pre-shared-keys", "ecdsa-signatures", "3600", "3600")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient CompileConfig rejected mixed IKE settings: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "ike-policy chain reference/settings consistency") &&
			strings.Contains(warning, "ike-psk") && strings.Contains(warning, "ike-ecdsa") {
			return
		}
	}
	t.Fatalf("lenient compile warning did not name both conflicting proposals: %v", cfg.Warnings)
}

func ikePolicyAgreementTree10879(t *testing.T, first, second, firstAuth, secondAuth, firstLife, secondLife string) *ConfigTree {
	t.Helper()
	return buildTreeFromSet(t, []string{
		"set security ike proposal " + first + " authentication-method " + firstAuth,
		"set security ike proposal " + first + " encryption-algorithm aes-256-cbc",
		"set security ike proposal " + first + " authentication-algorithm sha-256",
		"set security ike proposal " + first + " dh-group group14",
		"set security ike proposal " + first + " lifetime-seconds " + firstLife,
		"set security ike proposal " + second + " authentication-method " + secondAuth,
		"set security ike proposal " + second + " encryption-algorithm aes-128-cbc",
		"set security ike proposal " + second + " authentication-algorithm sha-256",
		"set security ike proposal " + second + " dh-group group14",
		"set security ike proposal " + second + " lifetime-seconds " + secondLife,
		"set security ike policy ike-pol proposals [ " + first + " " + second + " ]",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
}
