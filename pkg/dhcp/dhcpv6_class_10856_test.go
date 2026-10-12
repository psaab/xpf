package dhcp

import (
	"net/netip"
	"testing"
	"time"
)

// Each blocked IAPREFIX is skipped independently; a valid sibling remains in
// the live set. The broad-prefix case pins whole-prefix overlap, not just the
// class of the prefix's first address.
func TestExtractDelegatedPrefixesRejectsBlocklistedClasses10856(t *testing.T) {
	bad := []struct {
		name string
		cidr string
	}{
		{"link-local", "fe80::/64"},
		{"multicast", "ff02::1/128"},
		{"loopback", "::1/128"},
		{"unspecified", "::/128"},
		{"ipv4-compatible", "::c000:200/120"},
		{"ipv4-mapped", "::ffff:192.0.2.0/120"},
		{"site-local", "fec0::/48"},
		{"prefix-overlaps-blocklist", "fe00::/8"},
	}
	good := netip.MustParsePrefix("2606:4700:4700::/48")
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			msg := iaPDReply(t,
				pdPrefixOpt(t, tc.cidr, time.Hour, 2*time.Hour),
				pdPrefixOpt(t, good.String(), time.Hour, 2*time.Hour),
			)
			live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now())
			if len(live) != 1 || live[0].Prefix != good {
				t.Errorf("live = %v, want only valid sibling %s (blocked %s must be skipped)", live, good, tc.cidr)
			}
			if len(withdrawn) != 0 {
				t.Errorf("withdrawn = %v, want empty", withdrawn)
			}
		})
	}
}

// Narrowed blocklist contract: valid GUA, ULA, and documentation prefixes are
// still accepted. These controls prevent an accidental GUA-envelope policy.
func TestExtractDelegatedPrefixesKeepsNonblockedClasses10856(t *testing.T) {
	for _, tc := range []struct {
		name string
		cidr string
	}{
		{"GUA", "2606:4700:4700::/48"},
		{"ULA", "fd00::/48"},
		{"documentation-RFC-3849", "2001:db8:1::/48"},
		{"documentation-RFC-9637", "3fff:1::/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := netip.MustParsePrefix(tc.cidr)
			msg := iaPDReply(t, pdPrefixOpt(t, tc.cidr, time.Hour, 2*time.Hour))
			live, withdrawn := extractDelegatedPrefixes(msg, "wan0", time.Now())
			if len(live) != 1 || live[0].Prefix != want {
				t.Fatalf("live = %v, want %s", live, want)
			}
			if len(withdrawn) != 0 {
				t.Fatalf("withdrawn = %v, want empty", withdrawn)
			}
		})
	}
}
