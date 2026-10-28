package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// srcDstPortRangeAppCfg builds a trust->untrust permit policy whose application
// term is a custom TCP app constrained to a SOURCE-port RANGE (5000-6000) AND a
// DESTINATION-port RANGE (80-90). Both dimensions are ranges so this exercises
// the range branch of portMatches on each axis simultaneously — the case the
// single-axis #3330 (dest) / #3415 (source) suites do not cover.
func srcDstPortRangeAppCfg() *config.Config {
	sec := config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         zones("trust", "untrust"),
		Policies: []*config.ZonePairPolicies{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "range-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"dualrange"},
						},
					},
				},
			},
		},
	}
	apps := config.ApplicationsConfig{
		Applications: map[string]*config.Application{
			"dualrange": {
				Name:            "dualrange",
				Protocol:        "tcp",
				SourcePort:      "5000-6000",
				DestinationPort: "80-90",
			},
		},
	}
	return cfgWith(sec, apps)
}

// TestAppSrcAndDstPortRangesBothMustMatch is the #4413 (ps-review-007 dropped
// finding) coverage: an application constrained on BOTH a source-port range and
// a destination-port range matches ONLY when the query's source port AND
// destination port each fall inside their respective range (AND semantics),
// mirroring the runtime — appid.matchTuple / policy.rs CompiledApplications.matches
// gate a source-port-constrained app on source port AND a dest-port-constrained
// app on dest port, both against inclusive ranges. matchSingleApp checks
// app.SourcePort and app.DestinationPort independently and returns false if
// either fails, so a query in only one range must NOT match.
//
// RED-on-revert (source axis): dropping the `if app.SourcePort != "" { ... }`
// guard in matchSingleApp makes the "source-out, dest-in" subcase permit
// (Matched=true) instead of falling to the default deny — this test goes RED.
//
// RED-on-revert (destination axis): dropping the `if app.DestinationPort != ""
// { ... }` guard makes the "source-in, dest-out" subcase permit — RED.
//
// RED-on-revert (inclusive bounds): narrowing portMatches' range test to
// exclusive (`> l && < h`) flips the boundary permits (5000/6000, 80/90) to
// deny — RED.
func TestAppSrcAndDstPortRangesBothMustMatch(t *testing.T) {
	cfg := srcDstPortRangeAppCfg()

	cases := []struct {
		name        string
		srcPort     int
		dstPort     int
		wantMatched bool
	}{
		// Both in range -> permit (positive control, mid-range).
		{"both-mid-range", 5500, 85, true},
		// Inclusive lower and upper bounds on both axes still match.
		{"both-lower-bounds", 5000, 80, true},
		{"both-upper-bounds", 6000, 90, true},

		// Source in range, destination OUT of range -> deny (dest axis enforced).
		{"src-in-dst-above", 5500, 91, false},
		{"src-in-dst-below", 5500, 79, false},
		// Source OUT of range, destination in range -> deny (source axis enforced).
		{"src-above-dst-in", 6001, 85, false},
		{"src-below-dst-in", 4999, 85, false},
		// Both out of range -> deny.
		{"both-out", 4999, 91, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(cfg, Query{
				FromZone: "trust",
				ToZone:   "untrust",
				Protocol: "tcp",
				SrcPort:  PortPtr(uint16(tc.srcPort)),
				DstPort:  PortPtr(uint16(tc.dstPort)),
			})
			if res.Matched != tc.wantMatched {
				t.Fatalf("src=%d dst=%d: Matched = %v, want %v (res %+v)",
					tc.srcPort, tc.dstPort, res.Matched, tc.wantMatched, res)
			}
			if tc.wantMatched {
				if res.Action != config.PolicyPermit {
					t.Fatalf("src=%d dst=%d: Action = %v, want permit", tc.srcPort, tc.dstPort, res.Action)
				}
			} else {
				// A non-match falls through to the default deny — never a
				// fabricated permit for a tuple outside the app's ranges.
				if !res.DefaultUsed || res.Action != config.PolicyDeny {
					t.Fatalf("src=%d dst=%d: want default-policy deny, got %+v", tc.srcPort, tc.dstPort, res)
				}
			}
		})
	}
}
