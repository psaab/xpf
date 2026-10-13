package policymatch

import "testing"

// #3357/#4626/#12523: GlobalPolicyAppliesToZonePair governs which
// scoped/unscoped global policies a filtered policy view shows. For transit
// filters its semantics mirror the runtime globalScopeSetMatches: an empty or
// "any" match-scope axis spans every zone, and a multi-zone scope (#4626)
// applies when the filter names ANY member. A to-zone junos-host filter
// selects only globals scoped exactly to-zone junos-host (#12523).
func TestGlobalPolicyAppliesToZonePair(t *testing.T) {
	cases := []struct {
		name               string
		matchFrom, matchTo []string
		filtFrom, filtTo   string
		want               bool
	}{
		{"no filter, unscoped", nil, nil, "", "", true},
		{"no filter, scoped", []string{"trust"}, []string{"untrust"}, "", "", true},
		{"filter, unscoped global applies to transit pair", nil, nil, "trust", "untrust", true},
		{"filter, any-scope global applies to transit pair", []string{"any"}, []string{"any"}, "trust", "untrust", true},
		{"filter, scoped matches", []string{"trust"}, []string{"untrust"}, "trust", "untrust", true},
		{"filter, scoped from differs", []string{"dmz"}, []string{"untrust"}, "trust", "untrust", false},
		{"filter, scoped to differs", []string{"trust"}, []string{"dmz"}, "trust", "untrust", false},
		{"from-only filter, scoped to-only is all-from", nil, []string{"untrust"}, "trust", "", true},
		{"from-only filter, scoped from differs", []string{"dmz"}, nil, "trust", "", false},
		{"to-only filter, scoped from-only is all-to", []string{"trust"}, nil, "", "untrust", true},
		// #4626 M03: a multi-zone scope applies when the filter names any member.
		{"multi-zone from matches member", []string{"trust", "dmz"}, []string{"untrust"}, "dmz", "untrust", true},
		{"multi-zone from misses non-member", []string{"trust", "dmz"}, []string{"untrust"}, "wan", "untrust", false},
		// #12523: a junos-host filtered view must NOT present an unscoped or
		// any-scoped transit global as governing host-bound traffic — the host
		// gate (matchJunosHost) only consults globals with ToZones == [junos-host].
		{"junos-host filter, unscoped global excluded", nil, nil, "trust", "junos-host", false},
		{"junos-host filter, any-scope global excluded", []string{"any"}, []string{"any"}, "trust", "junos-host", false},
		{"junos-host filter, from-any unscoped-to global excluded", []string{"any"}, nil, "trust", "junos-host", false},
		{"junos-host filter, unscoped-from host-scoped included", nil, []string{"junos-host"}, "trust", "junos-host", true},
		{"junos-host filter, host-scoped included", []string{"trust"}, []string{"junos-host"}, "trust", "junos-host", true},
		{"junos-host filter, host-scoped other ingress excluded", []string{"dmz"}, []string{"junos-host"}, "trust", "junos-host", false},
		// #12523: the same exception holds for a to-zone-only host filter, and
		// the host gate requires the exact junos-host scope, not membership.
		{"to-only junos-host filter, unscoped global excluded", nil, nil, "", "junos-host", false},
		{"to-only junos-host filter, any-scope global excluded", []string{"any"}, []string{"any"}, "", "junos-host", false},
		{"to-only junos-host filter, host-scoped dmz-ingress global included", []string{"dmz"}, []string{"junos-host"}, "", "junos-host", true},
		{"junos-host filter, mixed host and transit to-scope excluded", nil, []string{"junos-host", "trust"}, "trust", "junos-host", false},
		{"transit filter, unscoped global still included", nil, nil, "trust", "untrust", true},
		{"transit filter, scoped host global excluded", []string{"trust"}, []string{"junos-host"}, "trust", "untrust", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GlobalPolicyAppliesToZonePair(tc.matchFrom, tc.matchTo, tc.filtFrom, tc.filtTo)
			if got != tc.want {
				t.Fatalf("GlobalPolicyAppliesToZonePair(%v,%v,%q,%q) = %v, want %v",
					tc.matchFrom, tc.matchTo, tc.filtFrom, tc.filtTo, got, tc.want)
			}
		})
	}
}
