package config

import (
	"net/netip"
	"testing"
)

// #10856 phase 2: the delegated-prefix policy is global-unicast-only. Each
// refused class is pinned per-class, with the reason recorded for operators.
func TestDelegatedIPv6PrefixRefusalReason10856(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		want string
	}{
		{"fe80::/64", "link-local address space"},
		{"ff02::1/128", "multicast address space"},
		{"::1/128", "loopback address space"},
		{"::/128", "unspecified address space"},
		{"::c000:200/120", "IPv4-compatible address space"},
		{"::ffff:192.0.2.0/120", "IPv4-mapped address space"},
		{"fec0::/48", "site-local address space"},
		{"fd00::/48", "unique local address space (ULA)"},
		{"fc42::/48", "unique local address space (ULA)"},
		{"2001:db8:1::/48", "documentation address space (RFC 3849)"},
		{"3fff:1::/32", "documentation address space (RFC 9637)"},
		{"2000::/3", "documentation address space (RFC 3849)"},
		// SPANNING refused space is refused even though its first address
		// is global unicast.

	} {
		t.Run(tc.cidr, func(t *testing.T) {
			if got := DelegatedIPv6PrefixRefusalReason(netip.MustParsePrefix(tc.cidr)); got != tc.want {
				t.Fatalf("DelegatedIPv6PrefixRefusalReason(%s) = %q, want %q", tc.cidr, got, tc.want)
			}
		})
	}
	for _, cidr := range []string{
		"2606:4700:4700::/48",
		"2001:4860:4860::/48",
		"2002:0a00:0a00::/48",
	} {
		t.Run("accept "+cidr, func(t *testing.T) {
			if got := DelegatedIPv6PrefixRefusalReason(netip.MustParsePrefix(cidr)); got != "" {
				t.Fatalf("DelegatedIPv6PrefixRefusalReason(%s) = %q, want accepted", cidr, got)
			}
		})
	}
	// Not an IPv6 prefix at all.
	if got := DelegatedIPv6PrefixRefusalReason(netip.MustParsePrefix("192.0.2.0/24")); got != "not an IPv6 prefix" {
		t.Fatalf("v4 prefix reason = %q", got)
	}
	if got := DelegatedIPv6PrefixRefusalReason(netip.Prefix{}); got != "not an IPv6 prefix" {
		t.Fatalf("zero prefix reason = %q", got)
	}
}

// ConfiguredIPv6Prefixes must surface every configured source: interface
// unit addresses, static RA prefixes, RA NAT64 (PREF64), and NAT64
// rule-sets — and nothing dynamic.
func TestConfiguredIPv6Prefixes10856(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {Units: map[int]*InterfaceUnit{
					0: {Addresses: []string{"2606:4700:1111::1/64", "fe80::1/64", "192.0.2.1/24"}},
				}},
				"ge-0/0/1": {Units: map[int]*InterfaceUnit{
					0: {Addresses: []string{"2606:4700:2222::2"}}, // bare address → /128
				}},
			},
		},
		Protocols: ProtocolsConfig{
			RouterAdvertisement: []*RAInterfaceConfig{
				{Interface: "ge-0/0/2", Prefixes: []*RAPrefix{
					{Prefix: "2606:4700:3333::/64"},
					{Prefix: "not-a-prefix"}, // skipped, not fatal
				}, NAT64Prefix: "64:ff9b::/96"},
			},
		},
		Security: SecurityConfig{NAT: NATConfig{NAT64: []*NAT64RuleSet{
			{Name: "n64", Prefix: "64:ff9b:1::/96"},
			{Name: "empty"}, // nil-safe
		}}},
	}
	got := ConfiguredIPv6Prefixes(cfg)
	want := []netip.Prefix{
		netip.MustParsePrefix("2606:4700:1111::/64"),
		netip.MustParsePrefix("fe80::/64"),
		netip.MustParsePrefix("2606:4700:2222::2/128"),
		netip.MustParsePrefix("2606:4700:3333::/64"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/96"),
	}
	if len(got) != len(want) {
		t.Fatalf("ConfiguredIPv6Prefixes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}
	if ConfiguredIPv6Prefixes(nil) != nil {
		t.Fatal("nil config must yield nil")
	}
}
