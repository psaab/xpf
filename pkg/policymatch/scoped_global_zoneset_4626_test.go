package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4626 M03: a multi-zone scoped global matches iff the packet's from-zone is
// in the from-set AND its to-zone is in the to-set. This is the operator-side
// simulator mirror of the Rust runtime AND-of-set-membership.
func TestScopedGlobalMultiZoneMatch(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Zones:         zones("trust", "dmz", "untrust", "wan"),
		GlobalPolicies: []*config.Policy{
			deny("g-multi", config.PolicyMatch{
				FromZones: []string{"trust", "dmz"},
				ToZones:   []string{"untrust"},
			}),
		},
	}, config.ApplicationsConfig{})

	cases := []struct {
		name        string
		from, to    string
		wantMatched bool
	}{
		{"from in set (trust) -> to in set", "trust", "untrust", true},
		{"from in set (dmz) -> to in set", "dmz", "untrust", true},
		{"from NOT in set (wan) -> to in set", "wan", "untrust", false},
		{"from in set -> to NOT in set", "trust", "dmz", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, Query{FromZone: tc.from, ToZone: tc.to, Protocol: "tcp", DstPort: PortPtr(80)})
			gotDeny := res.Matched && res.Global && res.Action == config.PolicyDeny
			if gotDeny != tc.wantMatched {
				t.Fatalf("Match(%s->%s): matched-deny=%v, want %v (action=%v matched=%v global=%v)",
					tc.from, tc.to, gotDeny, tc.wantMatched, res.Action, res.Matched, res.Global)
			}
			// A multi-zone match reports the CONCRETE flow zone per column, not a
			// joined scope label (#4626 A10).
			if tc.wantMatched {
				if res.FromZone != tc.from || res.ToZone != tc.to {
					t.Errorf("reported scope = %s->%s, want the concrete flow zones %s->%s",
						res.FromZone, res.ToZone, tc.from, tc.to)
				}
			}
		})
	}
}
