package config

import (
	"strings"
	"testing"
)

// #11380: two route-based VPNs sharing st0.0 with no explicit selectors render
// the same 0.0.0.0/0,::/0 selector pair and if_id. XFRM cannot distinguish the
// SAs, so strict commit must reject this before either VPN can be misselected.
func TestSharedSt0BindWildcardSelectorsRejected11380(t *testing.T) {
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
	for _, want := range []string{"#11380", "st0.0", "site-a", "site-b"} {
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

func TestSharedSt0BindRequiresProvablyDisjointRenderedSelectors11380(t *testing.T) {
	cases := []struct {
		name   string
		extra  []string
		reject bool
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
			name: "nested ranges overlap on both selector sides",
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.0/24", "198.51.100.0/24"),
				selectorCommands11380("site-b", "to-b", "10.0.0.128/25", "198.51.100.128/25")...,
			),
			reject: true,
		},
		{
			name: "IPv6 overlap rejects despite disjoint IPv4 children",
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
			reject: true,
		},
		{
			name: "disjoint inclusive IP ranges",
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.1-10.0.0.10", "198.51.100.1-198.51.100.10"),
				selectorCommands11380("site-b", "to-b", "10.0.0.11-10.0.0.20", "198.51.100.1-198.51.100.10")...,
			),
		},
		{
			name: "inclusive IP range endpoints overlap",
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.1-10.0.0.10", "198.51.100.1-198.51.100.10"),
				selectorCommands11380("site-b", "to-b", "10.0.0.10-10.0.0.20", "198.51.100.10-198.51.100.20")...,
			),
			reject: true,
		},
		{
			name: "omitted selector side is not provably disjoint",
			extra: append(
				selectorCommands11380("site-a", "to-a", "10.0.0.0/24", ""),
				selectorCommands11380("site-b", "to-b", "10.0.0.0/24", "198.51.100.0/24")...,
			),
			reject: true,
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
			if tc.reject {
				if err == nil || !strings.Contains(err.Error(), "#11380") {
					t.Fatalf("strict commit error = %v, want #11380 selector-overlap rejection", err)
				}
			} else if err != nil {
				t.Fatalf("strict commit rejected provably disjoint selector unions: %v", err)
			}
		})
	}
}

func TestSharedSt0BindChecksEveryVPNPair11380(t *testing.T) {
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
	if err == nil || !strings.Contains(err.Error(), "#11380") ||
		!strings.Contains(err.Error(), "site-a") || !strings.Contains(err.Error(), "site-c") {
		t.Fatalf("strict commit error = %v, want overlap rejection for site-a and site-c", err)
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
