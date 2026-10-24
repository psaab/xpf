package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPinnedDelegatedPrefixCovers12533(t *testing.T) {
	pin := netip.MustParsePrefix("fd00:1234::/48")
	for _, tc := range []struct {
		cidr string
		want bool
	}{
		{"fd00:1234::/48", true},
		{"fd00:1234:0:1::/64", true},
		{"fd00:1234:0:ffff::/64", true},
		{"fd00:1234::/47", false}, // wider than pin
		{"fd00:1235::/48", false},
		{"fd00::/48", false},
		{"2001:db8::/48", false},
	} {
		if got := PinnedDelegatedPrefixCovers(pin, netip.MustParsePrefix(tc.cidr)); got != tc.want {
			t.Errorf("covers(%s, %s)=%v want %v", pin, tc.cidr, got, tc.want)
		}
	}
	// Host bits masked.
	if !PinnedDelegatedPrefixCovers(netip.MustParsePrefix("fd00:1234::1/48"), netip.MustParsePrefix("fd00:1234:0:9::/64")) {
		t.Error("host-bit pin should mask and cover")
	}
	if PinnedDelegatedPrefixesCover(nil, netip.MustParsePrefix("fd00::/48")) {
		t.Error("nil pins must cover nothing")
	}
}

func TestPinnedPrefixSchema12533(t *testing.T) {
	base := "set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client prefix-delegating pinned-prefix "
	for _, bad := range []string{"10.0.0.0/8", "fd00::", "not-a-prefix", "::ffff:10.0.0.0/120"} {
		tree := flatTreeFromSets(t, base+bad)
		if err := SchemaValidate(tree); err == nil {
			t.Errorf("pinned-prefix %q accepted, want schema error", bad)
		}
	}
	for _, ok := range []string{"fd00:1234::/48", "2001:db8:1::/48", "2606:4700::/32"} {
		tree := flatTreeFromSets(t, base+ok)
		if err := SchemaValidate(tree); err != nil {
			t.Errorf("pinned-prefix %q rejected: %v", ok, err)
		}
	}
}

func TestPinnedPrefixCompile12533(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client prefix-delegating pinned-prefix fd00:1234::1/48",
		"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client prefix-delegating pinned-prefix fd00:aaaa::/48",
		"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client prefix-delegating pinned-prefix fd00:1234::/48",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dc := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].DHCPv6Client
	if dc == nil {
		t.Fatal("no DHCPv6Client")
	}
	want := []string{"fd00:1234::/48", "fd00:aaaa::/48"}
	if len(dc.PinnedPrefixes) != len(want) {
		t.Fatalf("PinnedPrefixes=%v want %v (masked/sorted/deduped)", dc.PinnedPrefixes, want)
	}
	for i := range want {
		if dc.PinnedPrefixes[i] != want[i] {
			t.Fatalf("PinnedPrefixes=%v want %v", dc.PinnedPrefixes, want)
		}
	}
	// Fingerprint stability: recompiling same config identical.
	cfg2, _ := CompileConfig(tree)
	if ConfigFingerprint(cfg) != ConfigFingerprint(cfg2) {
		t.Fatal("fingerprint not stable for pinned config")
	}
	if !strings.Contains(ConfigFingerprint(cfg), "fd00:1234::/48") {
		t.Fatal("fingerprint must include pins")
	}
	// No pins: nil, fingerprint differs.
	tree2 := flatTreeFromSets(t, "set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client prefix-delegating preferred-prefix-length 56")
	cfg3, _ := CompileConfig(tree2)
	if got := cfg3.Interfaces.Interfaces["ge-0/0/0"].Units[0].DHCPv6Client.PinnedPrefixes; got != nil {
		t.Fatalf("unpinned PinnedPrefixes=%v want nil", got)
	}
}
