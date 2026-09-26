package config

import (
	"strings"
	"testing"
)

func TestIPsecAlgorithmDomainRejectsNullAndUnknownTokens_10880(t *testing.T) {
	cases := []struct {
		name string
		sets []string
		bad  string
	}{
		{
			name: "IKE null encryption",
			sets: []string{
				"set security ike proposal p encryption-algorithm null",
				"set security ike proposal p authentication-algorithm sha-256",
			},
			bad: "null",
		},
		{
			name: "ESP null encryption",
			sets: []string{
				"set security ipsec proposal p protocol esp",
				"set security ipsec proposal p encryption-algorithm null",
				"set security ipsec proposal p authentication-algorithm hmac-sha-256-128",
			},
			bad: "null",
		},
		{
			name: "unsupported encryption",
			sets: []string{
				"set security ipsec proposal p protocol esp",
				"set security ipsec proposal p encryption-algorithm aes-512-cbc",
				"set security ipsec proposal p authentication-algorithm hmac-sha-256-128",
			},
			bad: "aes-512-cbc",
		},
		{
			name: "unsupported integrity",
			sets: []string{
				"set security ike proposal p encryption-algorithm aes-256-cbc",
				"set security ike proposal p authentication-algorithm sha-777",
			},
			bad: "sha-777",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.sets)
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), tc.bad) {
				t.Fatalf("strict compile error = %v, want unsupported algorithm %q", err, tc.bad)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected persisted proposal: %v", err)
			}
			if !warningsContain(cfg.Warnings, "proposal algorithms") || !warningsContain(cfg.Warnings, tc.bad) {
				t.Fatalf("lenient compile warnings = %v, want proposal algorithm warning naming %q", cfg.Warnings, tc.bad)
			}
		})
	}
}

func TestIKEProposalRequiresIntegrityUnlessAEAD_10880(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ike proposal cbc encryption-algorithm aes-256-cbc",
	})
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "cbc") || !strings.Contains(err.Error(), "authentication-algorithm") {
		t.Fatalf("strict compile error = %v, want missing IKE integrity diagnostic", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected persisted proposal: %v", err)
	}
	if !warningsContain(cfg.Warnings, "cbc") || !warningsContain(cfg.Warnings, "authentication-algorithm") {
		t.Fatalf("lenient compile warnings = %v, want missing IKE integrity warning", cfg.Warnings)
	}
}

func TestIPsecAlgorithmDomainAcceptsLegacyJunosCiphers_10880(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ike proposal ike-des encryption-algorithm des-cbc",
		"set security ike proposal ike-des authentication-algorithm sha1",
		"set security ike proposal ike-3des encryption-algorithm 3des-cbc",
		"set security ike proposal ike-3des authentication-algorithm md5",
		"set security ipsec proposal esp-des protocol esp",
		"set security ipsec proposal esp-des encryption-algorithm des-cbc",
		"set security ipsec proposal esp-des authentication-algorithm hmac-md5-96",
		"set security ipsec proposal esp-3des protocol esp",
		"set security ipsec proposal esp-3des encryption-algorithm 3des-cbc",
		"set security ipsec proposal esp-3des authentication-algorithm hmac-sha1-96",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("weak but valid Junos legacy proposal algorithms must remain accepted: %v", err)
	}
}

func TestIPsecAlgorithmDomainTreatsUppercaseGCMAsAEAD_10880(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ike proposal ike encryption-algorithm AES-256-GCM",
		"set security ipsec proposal esp protocol esp",
		"set security ipsec proposal esp encryption-algorithm AES-256-GCM",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("case-insensitive GCM proposals without separate integrity must compile: %v", err)
	}
}
