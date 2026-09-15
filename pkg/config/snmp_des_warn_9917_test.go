package config

import (
	"strings"
	"testing"
)

// TestSNMPv3DESPrivacyWarns9917 is the F-136 RED cell: a USM user configured
// with privacy-des must produce a commit-visible deprecation warning steering
// to AES. RED on base (no signal for DES anywhere); GREEN once the
// ValidateConfig helper lands (commit surfaces it via the runTailGates fold
// into cfg.Warnings, alarms via recompute).
func TestSNMPv3DESPrivacyWarns9917(t *testing.T) {
	tree := buildTree(t, []string{
		"set snmp v3 usm local-engine user ops authentication-sha256 authentication-password s3cretpass",
		"set snmp v3 usm local-engine user ops privacy-des privacy-password d3spassw0rd",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// Operator-visible contract: the commit path prints compiled.Warnings.
	foundCommit := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "privacy-des") && strings.Contains(w, "ops") {
			foundCommit = true
			if !strings.Contains(w, "aes128") {
				t.Errorf("DES warning does not steer to AES: %q", w)
			}
			break
		}
	}
	if !foundCommit {
		t.Errorf("F-136: DES user committed with no privacy-des warning; cfg.Warnings=%v", cfg.Warnings)
	}
	// Validator surface: alarms recompute ValidateConfig over the active config.
	foundValid := false
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "privacy-des") && strings.Contains(w, "ops") {
			foundValid = true
			break
		}
	}
	if !foundValid {
		t.Errorf("F-136: ValidateConfig names no privacy-des warning; warnings=%v", ValidateConfig(cfg))
	}
}

// TestSNMPv3AES128PrivacySilent9917 is the F-136 negative control: the
// recommended cipher must not warn. GREEN on base and after.
func TestSNMPv3AES128PrivacySilent9917(t *testing.T) {
	tree := buildTree(t, []string{
		"set snmp v3 usm local-engine user ops authentication-sha256 authentication-password s3cretpass",
		"set snmp v3 usm local-engine user ops privacy-aes128 privacy-password a3spassw0rd",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "privacy-des") {
			t.Fatalf("aes128 user drew a DES warning: %q (warnings=%v)", w, cfg.Warnings)
		}
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "privacy-des") {
			t.Fatalf("aes128 user drew a DES validator warning: %q", w)
		}
	}
}
