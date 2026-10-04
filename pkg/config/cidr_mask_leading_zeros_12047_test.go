package config

import (
	"strings"
	"testing"
)

// TestCIDRMaskRedundantLeadingZerosRejectedAtCommit12047 pins the shared
// book-row and inline-literal strict gates for both address families.
func TestCIDRMaskRedundantLeadingZerosRejectedAtCommit12047(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{"ipv4-008", "10.0.0.0/008"},
		{"ipv4-08", "10.0.0.0/08"},
		{"ipv4-00", "10.0.0.0/00"},
		{"ipv6-0032", "2001:db8::/0032"},
		{"ipv6-032", "2001:db8::/032"},
		{"ipv6-064", "2001:db8::/064"},
	} {
		t.Run("book/"+tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security address-book global address padded " + tc.prefix,
			})
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "redundant leading-zero mask digits") {
				t.Fatalf("strict commit did not diagnose padded book mask %q: %v", tc.prefix, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant load must preserve the prior config: %v", err)
			}
			if !warningContains12047(cfg.Warnings) {
				t.Fatalf("tolerant load must warn about %q; warnings=%v", tc.prefix, cfg.Warnings)
			}
		})

		t.Run("policy-inline/"+tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p1 match source-address " + tc.prefix,
				"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p1 match application any",
				"set security policies from-zone trust to-zone untrust policy p1 then permit",
			})
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "redundant leading-zero") {
				t.Fatalf("strict commit did not diagnose inline padded mask %q: %v", tc.prefix, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant load must preserve the prior config: %v", err)
			}
			if !warningContains12047(cfg.Warnings) {
				t.Fatalf("tolerant load must warn about %q; warnings=%v", tc.prefix, cfg.Warnings)
			}
		})
	}
	for _, prefix := range []string{"10.0.0.0/008", "2001:db8::/0032"} {
		t.Run("zone-book/"+prefix, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security zones security-zone trust address-book address padded " + prefix,
			})
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "redundant leading-zero mask digits") {
				t.Fatalf("strict commit did not diagnose zone-local padded mask %q: %v", prefix, err)
			}
		})
	}
}

func TestCIDRMaskCanonicalPrefixesRemainAccepted12047(t *testing.T) {
	for _, prefix := range []string{
		"10.0.0.0/0", "10.0.0.0/8", "10.0.0.0/32",
		"2001:db8::/0", "2001:db8::/32", "2001:db8::/128",
	} {
		t.Run(prefix, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security address-book global address canonical " + prefix,
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict commit rejected canonical mask %q: %v", prefix, err)
			}
		})
	}
}

func warningContains12047(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "redundant leading-zero") {
			return true
		}
	}
	return false
}
