package config

import (
	"strings"
	"testing"
)

// TestCIDRMaskHelperUnsupportedPaddingRejected12047 pins the book-row and
// inline-literal strict gates to spellings the userspace helper cannot parse.
func TestCIDRMaskHelperUnsupportedPaddingRejected12047(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{"ipv4-008", "10.0.0.0/008"},
		{"ipv4-024", "10.0.0.0/024"},
		{"ipv4-000", "10.0.0.0/000"},
		{"ipv6-0032", "2001:db8::/0032"},
		{"ipv6-0064", "2001:db8::/0064"},
	} {
		t.Run("book/"+tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set security address-book global address padded " + tc.prefix,
			})
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "redundant leading-zero mask digits") {
				t.Fatalf("strict commit did not diagnose helper-refused book mask %q: %v", tc.prefix, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant load must preserve the prior config: %v", err)
			}
			if !warningContains12047(cfg.Warnings) {
				t.Fatalf("tolerant load must warn about helper-refused mask %q; warnings=%v", tc.prefix, cfg.Warnings)
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
				t.Fatalf("strict commit did not diagnose helper-refused inline mask %q: %v", tc.prefix, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant load must preserve the prior config: %v", err)
			}
			if !warningContains12047(cfg.Warnings) {
				t.Fatalf("tolerant load must warn about helper-refused mask %q; warnings=%v", tc.prefix, cfg.Warnings)
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
				t.Fatalf("strict commit did not diagnose helper-refused zone-local mask %q: %v", prefix, err)
			}
		})
	}
}

// TestCIDRMaskHelperAcceptedPaddingAllowed12178 covers masks ipnet accepts
// despite their leading zero: these must remain strict-commit compatible and
// must not trigger a tolerant-load warning.
func TestCIDRMaskHelperAcceptedPaddingAllowed12178(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{"ipv4-08", "10.0.0.0/08"},
		{"ipv4-00", "10.0.0.0/00"},
		{"ipv6-032", "2001:db8::/032"},
		{"ipv6-064", "2001:db8::/064"},
		{"ipv6-024", "2001:db8::/024"},
		{"ipv6-008", "2001:db8::/008"},
	} {
		for _, kind := range []string{"book", "policy-inline"} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				var lines []string
				if kind == "book" {
					lines = []string{
						"set security address-book global address padded " + tc.prefix,
					}
				} else {
					lines = []string{
						"set security zones security-zone trust",
						"set security zones security-zone untrust",
						"set security policies from-zone trust to-zone untrust policy p1 match source-address " + tc.prefix,
						"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
						"set security policies from-zone trust to-zone untrust policy p1 match application any",
						"set security policies from-zone trust to-zone untrust policy p1 then permit",
					}
				}
				tree := buildTree(t, lines)
				if CIDRMaskHasRedundantLeadingZero(tc.prefix) {
					t.Fatalf("helper-accepted mask %q was classified as helper-refused", tc.prefix)
				}
				if _, err := CompileConfig(tree); err != nil {
					t.Fatalf("strict commit rejected helper-accepted mask %q: %v", tc.prefix, err)
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("tolerant load rejected helper-accepted mask %q: %v", tc.prefix, err)
				}
				if warningContains12047(cfg.Warnings) {
					t.Fatalf("tolerant load warned about helper-accepted mask %q: %v", tc.prefix, cfg.Warnings)
				}
			})
		}
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
