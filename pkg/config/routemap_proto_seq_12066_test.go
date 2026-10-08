package config

import "testing"

// TestRouteMapSequenceCount_ProtoDimension_12066 pins the #12066 admission
// count: FromProtocols is an OR dimension in the pkg/frr renderer's Cartesian
// expansion (one sequence per source protocol), so the count must multiply by
// max(1,|from protocol|). Without the factor, a multi-protocol policy is
// admitted under the ceiling and renders past FRR's 65535 sequence limit.
func TestRouteMapSequenceCount_ProtoDimension_12066(t *testing.T) {
	cases := []struct {
		name string
		ps   *PolicyStatement
		want uint64
	}{
		{"nil-protocols-single", &PolicyStatement{Terms: []*PolicyTerm{{Name: "t"}}}, 1},
		{
			"single-protocol-single",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"bgp"}}}},
			1,
		},
		{
			"three-protocols",
			&PolicyStatement{Terms: []*PolicyTerm{{Name: "t", FromProtocols: []string{"bgp", "ospf", "direct"}}}},
			3,
		},
		{
			"proto-cross-product", // 2 pl x 2 proto x 2 comm = 8
			&PolicyStatement{Terms: []*PolicyTerm{{
				Name:          "t",
				PrefixList:    []string{"a", "b"},
				FromProtocols: []string{"bgp", "ospf"},
				FromCommunity: []string{"c1", "c2"},
			}}},
			8,
		},
		{
			"proto-family-split", // mixed v4+v6 route-filters x 2 proto = 4
			&PolicyStatement{Terms: []*PolicyTerm{{
				Name:          "t",
				FromProtocols: []string{"bgp", "ospf"},
				RouteFilters:  []*RouteFilter{{Prefix: "10.0.0.0/8"}, {Prefix: "2001:db8::/32"}},
			}}},
			4,
		},
		{
			"proto-sum-over-terms", // 2 + 3 = 5
			&PolicyStatement{Terms: []*PolicyTerm{
				{Name: "t1", FromProtocols: []string{"bgp", "ospf"}},
				{Name: "t2", FromProtocols: []string{"bgp", "ospf", "static"}},
			}},
			5,
		},
	}
	for _, c := range cases {
		if got := RouteMapSequenceCount(nil, c.ps); got != c.want {
			t.Errorf("%s: RouteMapSequenceCount = %d, want %d", c.name, got, c.want)
		}
	}
}
