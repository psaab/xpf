package config

import (
	"strings"
	"testing"
)

// #10688: the helper parses IPv4-mapped literals as IPv6, while the Go address-
// book builder folds them into prefixes_v4. Strict commit must reject the
// mismatch, and the tolerant boot/sync path must warn without bricking the
// already-persisted config.
//
// FAIL-ON-REVERT: removing validateAddressBookMappedPrefixesStrict from
// runEarlyStrictAndFolds makes every strict-reject row compile successfully.
func TestMappedAddressBookPrefixRejectedAtCommit10688(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name: "global",
			lines: []string{
				"set security address-book global address mapped-v4 ::ffff:10.0.0.0/104",
			},
			want: "security global address-book address \"mapped-v4\"",
		},
		{
			name: "zone-local",
			lines: []string{
				"set security zones security-zone trust address-book address mapped-v4 ::ffff:10.0.0.0/104",
			},
			want: "security zone \"trust\" address-book address \"mapped-v4\"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil || !strings.Contains(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "IPv4-mapped IPv6") ||
				!strings.Contains(err.Error(), "prefixes_v4") ||
				!strings.Contains(err.Error(), "entire policy snapshot") {
				t.Fatalf("strict commit must diagnose the address-book family mismatch, got %v", err)
			}

			cfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("tolerant load must keep the existing config bootable: %v", err)
			}
			var warned bool
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "IPv4-mapped IPv6") && strings.Contains(warning, "prefixes_v4") {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("tolerant load must warn about the wrong-family prefix; warnings=%v", cfg.Warnings)
			}
		})
	}
}

func TestMappedAddressBookPrefixGateLeavesOrdinaryFamiliesAlone10688(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set security address-book global address ordinary-v4 10.0.0.0/8",
		"set security address-book global address ordinary-v6 2001:db8::/32",
	}))
	if err != nil {
		t.Fatalf("strict commit rejected ordinary IPv4/IPv6 prefixes: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "IPv4-mapped IPv6") {
			t.Fatalf("ordinary address prefixes produced a mapped-prefix warning: %v", cfg.Warnings)
		}
	}
}
