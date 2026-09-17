package config

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestIPsecProposalAlgorithmGate_9906 is a fail-on-revert guard for every
// swanctl-significant metacharacter in both proposal families and both
// algorithm leaves. The 16 printable metacharacter cases are rejected by
// validateIPsecProposalAlgorithmsStrict; the four newline cases are rejected
// earlier by the existing control-character prewalk. All 20 tolerant cases
// must still produce the new proposal-algorithm warning.
func TestIPsecProposalAlgorithmGate_9906(t *testing.T) {
	metachars := []string{"#", "{", "}", "=", "\n"}
	fields := []struct {
		name string
		path string
		base string
	}{
		{name: "ike encryption", path: "security ike proposal p encryption-algorithm", base: "aes256"},
		{name: "ike authentication", path: "security ike proposal p authentication-algorithm", base: "sha256"},
		{name: "esp encryption", path: "security ipsec proposal p encryption-algorithm", base: "aes256"},
		{name: "esp authentication", path: "security ipsec proposal p authentication-algorithm", base: "sha256"},
	}
	for _, field := range fields {
		for _, metachar := range metachars {
			t.Run(field.name+"/"+metachar, func(t *testing.T) {
				value := field.base + metachar + "x"
				lines := []string{fmt.Sprintf("set %s %s", field.path, strconv.Quote(value))}
				if strings.HasPrefix(field.name, "esp ") {
					lines = append(lines, "set security ipsec proposal p protocol esp")
					if strings.HasPrefix(field.name, "esp encryption") {
						lines = append(lines, "set security ipsec proposal p authentication-algorithm sha-256")
					} else {
						lines = append(lines, "set security ipsec proposal p encryption-algorithm aes-256-cbc")
					}
				}
				tree := buildTree(t, lines)
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("strict compile accepted %s value %q", field.name, value)
				}
				if strings.Contains(metachar, "\n") {
					if !strings.Contains(err.Error(), "control characters") {
						t.Fatalf("strict error must reject control-character value %q, got %v", value, err)
					}
				} else if !strings.Contains(err.Error(), value) || !strings.Contains(err.Error(), "proposal") {
					t.Fatalf("strict error must name proposal and value %q, got %v", value, err)
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("lenient compile rejected persisted %s value: %v", field.name, err)
				}
				if !warningsContain(cfg.Warnings, "proposal algorithms") {
					t.Fatalf("lenient compile must warn for %s value %q, warnings: %v", field.name, value, cfg.Warnings)
				}
				if !strings.Contains(metachar, "\n") && !warningsContain(cfg.Warnings, value) {
					t.Fatalf("lenient warning must name value %q, warnings: %v", value, cfg.Warnings)
				}
			})
		}
	}
}

func TestIPsecNonAEADIntegrityRequired_9907(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ipsec proposal cbc protocol esp",
		"set security ipsec proposal cbc encryption-algorithm aes-256-cbc",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted non-AEAD ESP proposal without authentication-algorithm")
	}
	if !strings.Contains(err.Error(), "cbc") || !strings.Contains(err.Error(), "authentication-algorithm") {
		t.Fatalf("strict error must name proposal and missing integrity leaf, got %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected persisted bare-cipher proposal: %v", err)
	}
	if !warningsContain(cfg.Warnings, "cbc") || !warningsContain(cfg.Warnings, "authentication-algorithm") {
		t.Fatalf("lenient compile must warn about missing integrity, warnings: %v", cfg.Warnings)
	}
}

func TestIPsecProposalAlgorithmAllowlistAcceptsNormalValues_9906(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ike proposal ike encryption-algorithm aes-256-cbc",
		"set security ike proposal ike authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal esp protocol esp",
		"set security ipsec proposal esp encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp authentication-algorithm hmac-sha-256-128",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("normal hyphen-joined algorithm values must commit: %v", err)
	}
}

func TestIPsecAEADESPMayOmitSeparateIntegrity_9907(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ipsec proposal gcm protocol esp",
		"set security ipsec proposal gcm encryption-algorithm aes-256-gcm",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("AEAD ESP may omit authentication-algorithm: %v", err)
	}
}
