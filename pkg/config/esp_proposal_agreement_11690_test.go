package config

import (
	"strings"
	"testing"
)

// #11690: the IKE side (#10879) rejects multi-proposal lifetime divergence at
// commit; the ESP side must reject the same shape instead of silently
// first-winning at render.
func TestIPsecPolicyRejectsDivergentESPLifetimes_11690(t *testing.T) {
	for _, tc := range []struct {
		name       string
		first      string
		second     string
		firstLife  string
		secondLife string
	}{
		{
			name:       "divergent lifetime first",
			first:      "esp-short",
			second:     "esp-long",
			firstLife:  "3600",
			secondLife: "28800",
		},
		{
			name:       "divergent lifetime reversed",
			first:      "esp-long",
			second:     "esp-short",
			firstLife:  "28800",
			secondLife: "3600",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := espPolicyAgreementTree11690(t, tc.first, tc.second, tc.firstLife, tc.secondLife)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatal("CompileConfig accepted divergent ESP proposal lifetimes")
			}
			for _, want := range []string{tc.first, tc.second, "lifetime-seconds"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestIPsecPolicyDivergentESPLifetimesWarnsOnLenientCompile_11690(t *testing.T) {
	tree := espPolicyAgreementTree11690(t, "esp-short", "esp-long", "3600", "28800")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient CompileConfig rejected divergent ESP lifetimes: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "ipsec policy proposal reference") &&
			strings.Contains(warning, "esp-short") && strings.Contains(warning, "esp-long") {
			return
		}
	}
	t.Fatalf("lenient compile warning did not name both conflicting proposals: %v", cfg.Warnings)
}

func espPolicyAgreementTree11690(t *testing.T, first, second, firstLife, secondLife string) *ConfigTree {
	t.Helper()
	return buildTreeFromSet(t, []string{
		"set security ipsec proposal " + first + " protocol esp",
		"set security ipsec proposal " + first + " encryption-algorithm aes-256-cbc",
		"set security ipsec proposal " + first + " authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal " + first + " dh-group group14",
		"set security ipsec proposal " + first + " lifetime-seconds " + firstLife,
		"set security ipsec proposal " + second + " protocol esp",
		"set security ipsec proposal " + second + " encryption-algorithm aes-128-cbc",
		"set security ipsec proposal " + second + " authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal " + second + " dh-group group14",
		"set security ipsec proposal " + second + " lifetime-seconds " + secondLife,
		"set security ipsec policy esp-pol proposals [ " + first + " " + second + " ]",
		"set security ike proposal ike-a authentication-method pre-shared-keys",
		"set security ike proposal ike-a encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-a authentication-algorithm sha-256",
		"set security ike proposal ike-a dh-group group14",
		"set security ike policy ike-pol proposals ike-a",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 ike ipsec-policy esp-pol",
		"set security ipsec vpn tun1 bind-interface st0",
	})
}
