package config

import (
	"testing"
)

// #12898: ZoneMemberDetailLines is the ONE shared renderer for the
// zones-detail per-member Address/DHCP block (local CLI since #5325, gRPC
// text since #12898). These table cases pin the display contract the two
// surfaces must keep agreeing on: unit isolation, bare-member all-units,
// malformed/trailing suffixes, unresolved bases, and the #5886/#5910
// nil-slot skips.
func TestZoneMemberDetailLines12898(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0:  {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			50: {Number: 50, Addresses: []string{"10.0.10.1/24"}, DHCPv6: true},
			7:  nil, // present-but-nil unit (#3494/#5068): skipped, not shown
		}},
	}}}
	cases := []struct {
		name   string
		member string
		want   []string
	}{
		{
			name:   "unit-qualified renders only that unit",
			member: "ge-0/0/0.0",
			want:   []string{"      Address: 10.0.0.1/24"},
		},
		{
			name:   "other unit qualified renders only that unit",
			member: "ge-0/0/0.50",
			want:   []string{"      Address: 10.0.10.1/24", "      DHCPv6: enabled"},
		},
		{
			name:   "bare member renders all units",
			member: "ge-0/0/0",
			want: []string{
				"      Address: 10.0.0.1/24",
				"      Address: 10.0.10.1/24",
				"      DHCPv6: enabled",
			},
		},
		{
			name:   "non-numeric suffix keeps no unit filter (CLI parity)",
			member: "ge-0/0/0.foo",
			want: []string{
				"      Address: 10.0.0.1/24",
				"      Address: 10.0.10.1/24",
				"      DHCPv6: enabled",
			},
		},
		{
			name:   "trailing dot keeps no unit filter (CLI parity)",
			member: "ge-0/0/0.",
			want: []string{
				"      Address: 10.0.0.1/24",
				"      Address: 10.0.10.1/24",
				"      DHCPv6: enabled",
			},
		},
		{
			name:   "unresolved base renders nothing",
			member: "ge-0/0/9.0",
			want:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Bare/all-units and malformed cases iterate a MAP, so compare
			// as sets when more than one unit can contribute lines.
			got := ZoneMemberDetailLines(cfg, tc.member)
			if len(got) != len(tc.want) || !sameLines12898(got, tc.want) {
				t.Fatalf("ZoneMemberDetailLines(%q) = %v, want %v", tc.member, got, tc.want)
			}
		})
	}
}

// sameLines12898 is order-insensitive line-set equality (map iteration order
// is unspecified; the renderers above it sort nothing either).
func sameLines12898(got, want []string) bool {
	seen := make(map[string]int, len(want))
	for _, w := range want {
		seen[w]++
	}
	for _, g := range got {
		if seen[g] == 0 {
			return false
		}
		seen[g]--
	}
	return true
}

// TestZoneMemberDetailLinesNilSafety12898: a present-but-nil stanza under the
// member's BASE key is a miss (LookupInterface doctrine #5886), never a
// deref; a nil cfg is a clean miss too.
func TestZoneMemberDetailLinesNilSafety12898(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/0": nil, // present-but-nil stanza (#3494/#5068)
	}}}
	if got := ZoneMemberDetailLines(cfg, "ge-0/0/0.0"); got != nil {
		t.Fatalf("nil stanza under base rendered %v; want nil", got)
	}
	if got := ZoneMemberDetailLines(nil, "ge-0/0/0.0"); got != nil {
		t.Fatalf("nil cfg rendered %v; want nil", got)
	}
	if got := ZoneMemberDetailLines(cfg, "ge-0/0/0"); got != nil {
		t.Fatalf("nil stanza bare lookup rendered %v; want nil", got)
	}
}
