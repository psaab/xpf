package config

import (
	"strings"
	"testing"
)

// #17779: the runtime capture plan keys queues by VPN name and marks every
// generation OwnerContested when two VPN names claim one if_id. Therefore
// shared st0.0 is rejected even when #11380 proves the rendered selectors
// disjoint; overlapping selectors remain unsafe for the separate XFRM-SA
// reason covered by the lenient #11380 warning below.
func TestSharedSt0BindWildcardSelectorsRejectedByCaptureOwner17779(t *testing.T) {
	tree := buildBindIfaceTree(t,
		"set security ike gateway gw-a address 198.51.100.1",
		"set security ike gateway gw-b address 198.51.100.2",
		"set security ipsec vpn site-a ike gateway gw-a",
		"set security ipsec vpn site-a bind-interface st0.0",
		"set security ipsec vpn site-b ike gateway gw-b",
		"set security ipsec vpn site-b bind-interface st0.0",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit accepted two VPNs sharing st0.0 with rendered wildcard selectors")
	}
	for _, want := range []string{"#17779", "OwnerContested", "st0.0", "site-a", "site-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("sharing error %q does not identify %q", err, want)
		}
	}
}

func sharedSt0BindTree11380(t *testing.T, extra ...string) *ConfigTree {
	t.Helper()
	lines := []string{
		"set security ike gateway gw-a address 198.51.100.1",
		"set security ike gateway gw-b address 198.51.100.2",
		"set security ipsec vpn site-a ike gateway gw-a",
		"set security ipsec vpn site-a bind-interface st0.0",
		"set security ipsec vpn site-b ike gateway gw-b",
		"set security ipsec vpn site-b bind-interface st0.0",
	}
	return buildBindIfaceTree(t, append(lines, extra...)...)
}

func selectorCommands11380(vpn, name, local, remote string) []string {
	lines := make([]string, 0, 2)
	if local != "" {
		lines = append(lines, "set security ipsec vpn "+vpn+" traffic-selector "+name+" local-ip "+local)
	}
	if remote != "" {
		lines = append(lines, "set security ipsec vpn "+vpn+" traffic-selector "+name+" remote-ip "+remote)
	}
	return lines
}

func TestSharedSt0BindRejectedRegardlessOfSelectors17779(t *testing.T) {
	cases := []struct {
		name                 string
		extra                []string
		wantSelectorOverlap  bool
	}{
		{
			name: "disjoint remote prefixes",
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.0/24", "198.51.100.0/24"),
				selectorCommands11380("site-b", "to-b", "10.0.0.0/24", "203.0.113.0/24")...,
			),
		},
		{
			name: "disjoint local prefixes",
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.0/24", "198.51.100.0/24"),
				selectorCommands11380("site-b", "to-b", "10.1.0.0/24", "198.51.100.0/24")...,
			),
		},
		{
			name:                "nested ranges overlap on both selector sides",
			wantSelectorOverlap: true,
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.0/24", "198.51.100.0/24"),
				selectorCommands11380("site-b", "to-b", "10.0.0.128/25", "198.51.100.128/25")...,
			),
		},
		{
			name:                "IPv6 overlap rejects despite disjoint IPv4 children",
			wantSelectorOverlap: true,
			extra: append(
				append(
					selectorCommands11380("site-a", "v4", "10.0.0.0/24", "192.0.2.0/24"),
					selectorCommands11380("site-a", "v6", "2001:db8:1::/48", "2001:db8:2::/48")...,
				),
				append(
					selectorCommands11380("site-b", "v4", "10.0.0.0/24", "198.51.100.0/24"),
					selectorCommands11380("site-b", "v6", "2001:db8:1::/48", "2001:db8:2:1::/64")...,
				)...,
			),
		},
		{
			name: "disjoint inclusive IP ranges",
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.1-10.0.0.10", "198.51.100.1-198.51.100.10"),
				selectorCommands11380("site-b", "to-b", "10.0.0.11-10.0.0.20", "198.51.100.1-198.51.100.10")...,
			),
		},
		{
			name:                "inclusive IP range endpoints overlap",
			wantSelectorOverlap: true,
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.1-10.0.0.10", "198.51.100.1-198.51.100.10"),
				selectorCommands11380("site-b", "to-b", "10.0.0.10-10.0.0.20", "198.51.100.10-198.51.100.20")...,
			),
		},
		{
			name:                "omitted selector side is not provably disjoint",
			wantSelectorOverlap: true,
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.0/24", ""),
				selectorCommands11380("site-b", "to-b", "10.0.0.0/24", "198.51.100.0/24")...,
			),
		},
		{
			name: "disjoint identity fallbacks with rendered wildcard sides",
			extra: []string{
				"set security ipsec vpn site-a local-identity 10.0.0.0/24",
				"set security ipsec vpn site-b local-identity 10.1.0.0/24",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(sharedSt0BindTree11380(t, tc.extra...))
			if err == nil || !strings.Contains(err.Error(), "#17779") ||
				!strings.Contains(err.Error(), "OwnerContested") {
				t.Fatalf("strict commit error = %v, want #17779 OwnerContested rejection", err)
			}

			cfg, err := CompileConfigLenient(sharedSt0BindTree11380(t, tc.extra...))
			if err != nil {
				t.Fatalf("lenient compile rejected shared-bind selector fixture: %v", err)
			}
			selectorErr := validateIPsecBindTrafficSelectorOverlapStrict(cfg)
			if tc.wantSelectorOverlap {
				if selectorErr == nil || !strings.Contains(selectorErr.Error(), "#11380") {
					t.Fatalf("selector validator error = %v, want independent #11380 overlap verdict", selectorErr)
				}
			} else if selectorErr != nil {
				t.Fatalf("selector validator rejected disjoint selectors: %v", selectorErr)
			}
		})
	}
}

func TestSharedSt0BindListsEveryCaptureOwner17779(t *testing.T) {
	extra := []string{
		"set security ike gateway gw-c address 198.51.100.3",
		"set security ipsec vpn site-c ike gateway gw-c",
		"set security ipsec vpn site-c bind-interface st0.0",
	}
	extra = append(extra,
		selectorCommands11380("site-a", "to-a", "10.0.0.0/24", "198.51.100.0/24")...)
	extra = append(extra,
		selectorCommands11380("site-b", "to-b", "10.0.0.0/24", "203.0.113.0/24")...)
	extra = append(extra,
		selectorCommands11380("site-c", "to-c", "10.0.0.0/24", "198.51.100.0/24")...)

	_, err := CompileConfig(sharedSt0BindTree11380(t, extra...))
	if err == nil || !strings.Contains(err.Error(), "#17779") ||
		!strings.Contains(err.Error(), "site-a") ||
		!strings.Contains(err.Error(), "site-b") ||
		!strings.Contains(err.Error(), "site-c") {
		t.Fatalf("strict commit error = %v, want capture-owner rejection listing site-a/b/c", err)
	}
}

func TestSharedSt0BindWildcardSelectorsWarnOnLenientLoad11380(t *testing.T) {
	cfg, err := CompileConfigLenient(sharedSt0BindTree11380(t))
	if err != nil {
		t.Fatalf("tolerant compile rejected existing shared-bind config: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "ipsec shared bind traffic-selector overlap") &&
			strings.Contains(warning, "#11380") &&
			strings.Contains(warning, "site-a") && strings.Contains(warning, "site-b") {
			return
		}
	}
	t.Fatalf("tolerant compile did not warn about shared wildcard selectors: %v", cfg.Warnings)
}
