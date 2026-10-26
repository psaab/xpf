package dhcp

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17016: overlappingProtectedPrefixV4 must use
// config.IPv4PrefixesOverlap instead of carrying a private inline copy
// (#14728 added both in one commit; the exported helper was test-only).
// This table pins the production seam's boundary behaviour: equal,
// adjacent, containment both ways, /0, /32, host bits on either side,
// invalid, IPv6, and 4-in-6 inputs.
//
// Return contract: the first overlapping protected prefix, masked. The
// predicate must agree with config.IPv4PrefixesOverlap for every input pair.
func TestOverlappingProtectedPrefixV4Boundaries17016(t *testing.T) {
	pp := netip.MustParsePrefix
	cases := []struct {
		name      string
		installed netip.Prefix
		protected []netip.Prefix
		want      netip.Prefix
	}{
		{"equal", pp("10.0.1.0/24"), []netip.Prefix{pp("10.0.1.0/24")}, pp("10.0.1.0/24")},
		{"equal host bits both", pp("10.0.1.7/24"), []netip.Prefix{pp("10.0.1.9/24")}, pp("10.0.1.0/24")},
		{"installed inside protected", pp("10.0.1.128/25"), []netip.Prefix{pp("10.0.1.0/24")}, pp("10.0.1.0/24")},
		{"protected inside installed", pp("10.0.0.0/16"), []netip.Prefix{pp("10.0.1.0/24")}, pp("10.0.1.0/24")},
		{"protected host bits masked", pp("10.0.1.0/24"), []netip.Prefix{pp("10.0.1.10/24")}, pp("10.0.1.0/24")},
		{"adjacent disjoint", pp("10.0.1.0/25"), []netip.Prefix{pp("10.0.1.128/25")}, netip.Prefix{}},
		{"adjacent networks", pp("10.0.2.0/24"), []netip.Prefix{pp("10.0.1.0/24")}, netip.Prefix{}},
		{"disjoint", pp("10.0.2.0/24"), []netip.Prefix{pp("10.0.1.0/24")}, netip.Prefix{}},
		{"slash0 overlaps all", pp("192.0.2.0/24"), []netip.Prefix{pp("0.0.0.0/0")}, pp("0.0.0.0/0")},
		{"slash0 installed overlaps", pp("0.0.0.0/0"), []netip.Prefix{pp("10.0.1.0/24")}, pp("10.0.1.0/24")},
		{"slash32 equal", pp("192.0.2.1/32"), []netip.Prefix{pp("192.0.2.1/32")}, pp("192.0.2.1/32")},
		{"slash32 inside", pp("192.0.2.1/32"), []netip.Prefix{pp("192.0.2.0/24")}, pp("192.0.2.0/24")},
		{"slash32 disjoint", pp("192.0.2.2/32"), []netip.Prefix{pp("192.0.2.1/32")}, netip.Prefix{}},
		{"ipv6 protected skipped", pp("10.0.1.0/24"), []netip.Prefix{pp("2001:db8::/64")}, netip.Prefix{}},
		{"ipv6 installed", pp("2001:db8::/64"), []netip.Prefix{pp("10.0.1.0/24")}, netip.Prefix{}},
		{"4in6 protected skipped", pp("10.0.1.0/24"), []netip.Prefix{pp("::ffff:10.0.1.0/120")}, netip.Prefix{}},
		{"4in6 installed", pp("::ffff:10.0.1.0/120"), []netip.Prefix{pp("10.0.1.0/24")}, netip.Prefix{}},
		{"invalid installed", netip.Prefix{}, []netip.Prefix{pp("10.0.1.0/24")}, netip.Prefix{}},
		{"invalid protected skipped", pp("10.0.1.0/24"), []netip.Prefix{{}}, netip.Prefix{}},
		{"nil protected", pp("10.0.1.0/24"), nil, netip.Prefix{}},
		{"first match wins", pp("10.0.1.0/24"),
			[]netip.Prefix{pp("10.0.2.0/24"), pp("10.0.1.10/24"), pp("10.0.0.0/16")}, pp("10.0.1.0/24")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := overlappingProtectedPrefixV4(tc.installed, tc.protected)
			if got != tc.want {
				t.Errorf("overlappingProtectedPrefixV4(%v, %v) = %v, want %v",
					tc.installed, tc.protected, got, tc.want)
			}
			wantOverlap := false
			for _, p := range tc.protected {
				if config.IPv4PrefixesOverlap(tc.installed, p) {
					wantOverlap = true
					break
				}
			}
			if got.IsValid() != wantOverlap {
				t.Errorf("overlap result = %v, config.IPv4PrefixesOverlap says %v",
					got.IsValid(), wantOverlap)
			}
			if len(tc.protected) == 1 {
				reverse := overlappingProtectedPrefixV4(
					tc.protected[0], []netip.Prefix{tc.installed})
				reverseWant := config.IPv4PrefixesOverlap(tc.protected[0], tc.installed)
				if reverse.IsValid() != reverseWant || reverse.IsValid() != got.IsValid() {
					t.Errorf("overlap is not symmetric: forward=%v reverse=%v shared reverse=%v",
						got.IsValid(), reverse.IsValid(), reverseWant)
				}
			}
		})
	}
}
