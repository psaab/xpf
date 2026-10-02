package config

import (
	"strings"
	"testing"
)

// #4808: `system backup-router <next-hop> [destination <prefix>]` stored both
// values as raw strings without IP-format validation — only the family of an
// explicit destination and next-hop was checked (#2911). A malformed value
// could not be installed as a route in management table 999; strict commit must
// reject it, while tolerant loads warn and let the daemon omit the invalid
// route rather than preventing startup.

func hasBackupRouterFormatWarning(cfg *Config, substr string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// A malformed next-hop (trailing garbage byte, matching the issue's exact
// "192.168.1.x" typo reproducer) is rejected at commit.
func TestBackupRouterMalformedNextHopRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.168.1.x",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("malformed backup-router next-hop '192.168.1.x' compiled without error (#4808 regression)")
	}
	if !strings.Contains(err.Error(), "192.168.1.x") || !strings.Contains(err.Error(), "not a valid IP address") {
		t.Fatalf("error should name the malformed next-hop, got: %v", err)
	}
}

// A next-hop that is not an IP address at all is rejected at commit.
func TestBackupRouterNonAddressNextHopRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router notaddr",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("non-address backup-router next-hop 'notaddr' compiled without error (#4808 regression)")
	}
	if !strings.Contains(err.Error(), "notaddr") {
		t.Fatalf("error should name the malformed next-hop, got: %v", err)
	}
}

// A malformed EXPLICIT destination (bad mask) is rejected at commit even
// though its address portion alone would parse fine (natCIDRIPPart would
// otherwise mask this — net.ParseCIDR must validate the whole token).
func TestBackupRouterMalformedDestinationRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.168.50.1 destination 10.0.0.0/99",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("malformed backup-router destination '10.0.0.0/99' compiled without error (#4808 regression)")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/99") || !strings.Contains(err.Error(), "not a valid CIDR prefix") {
		t.Fatalf("error should name the malformed destination, got: %v", err)
	}
}

// A destination missing its mask entirely is also rejected.
func TestBackupRouterNonCIDRDestinationRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.168.50.1 destination notacidr",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("non-CIDR backup-router destination 'notacidr' compiled without error (#4808 regression)")
	}
	if !strings.Contains(err.Error(), "notacidr") {
		t.Fatalf("error should name the malformed destination, got: %v", err)
	}
}

// The lenient (tolerant load / peer-sync) path WARNS instead of rejecting a
// malformed next-hop, so an already-persisted bad config still boots (#1960
// fail-closed-on-load).
func TestBackupRouterMalformedNextHopLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.168.1.x",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a malformed backup-router next-hop must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasBackupRouterFormatWarning(cfg, "not a valid IP address") {
		t.Fatalf("lenient load must emit a malformed-next-hop warning, warnings=%v", cfg.Warnings)
	}
}

// The lenient path also warns (not rejects) a malformed destination.
func TestBackupRouterMalformedDestinationLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set system backup-router 192.168.50.1 destination 10.0.0.0/99",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a malformed backup-router destination must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasBackupRouterFormatWarning(cfg, "not a valid CIDR prefix") {
		t.Fatalf("lenient load must emit a malformed-destination warning, warnings=%v", cfg.Warnings)
	}
}

// A well-formed backup-router (bare next-hop, and next-hop + explicit
// matched-family destination) still compiles clean — the fix must not
// over-reject valid configs.
func TestBackupRouterValidFormatCommits(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"bare-v4-nh", "set system backup-router 192.168.50.1"},
		{"bare-v6-nh", "set system backup-router 2001:db8::1"},
		{"v4-nh-v4-dst", "set system backup-router 192.168.50.1 destination 10.0.0.0/8"},
		{"v6-nh-v6-dst", "set system backup-router 2001:db8::1 destination 2001:db8:1::/48"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("valid backup-router should compile, got: %v", err)
			}
			if hasBackupRouterFormatWarning(cfg, "not a valid") {
				t.Fatalf("valid backup-router must not warn, warnings=%v", cfg.Warnings)
			}
		})
	}
}
