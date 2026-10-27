package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestExcludedFlagsAndRuleIDOnMatch pins #3668 at the shared-matcher layer: a
// positive verdict against a source-address-excluded / destination-address-
// excluded policy must CONVEY the exclusion in Result.SourceAddressExcluded /
// DestinationAddressExcluded and carry the stable Result.RuleID that the
// inventory uses. Before #3668 Result had none of those fields, so a hit against
// a source OUTSIDE the excluded set reported the excluded list with no negation
// marker — reading as if the excluded address CAUSED the match.
//
// The matcher itself was already correct (matchAddr inverts for the excluded
// side); this pins that the RESULT reports the flags a renderer needs.
//
// RED-on-revert: dropping the SourceAddressExcluded/DestinationAddressExcluded/
// RuleID population in matchedResult (pkg/policymatch/policymatch.go) leaves them
// zero-value and every assertion below fails.
func TestExcludedFlagsAndRuleIDOnMatch(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name:   "exclude-permit",
							Action: config.PolicyPermit,
							Match: config.PolicyMatch{
								SourceAddresses:            []string{"10.0.99.0/24"},
								SourceAddressExcluded:      true,
								DestinationAddresses:       []string{"192.0.2.0/24"},
								DestinationAddressExcluded: true,
								Applications:               []string{"any"},
							},
						},
					},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	// Source OUTSIDE the excluded 10.0.99.0/24 and destination OUTSIDE the
	// excluded 192.0.2.0/24 => the excluded rule matches (matchAddr returns
	// !rawMatched for the excluded side).
	res := Match(cfg, Query{
		FromZone: "trust",
		ToZone:   "untrust",
		SrcIP:    net.ParseIP("10.0.5.7"),
		DstIP:    net.ParseIP("198.51.100.7"),
		Protocol: "tcp",
		DstPort:  PortPtr(80),
	})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("expected permit match for a source/dest outside the excluded sets; res = %+v", res)
	}
	if !res.SourceAddressExcluded {
		t.Errorf("SourceAddressExcluded = false, want true (matched rule is source-address-excluded)")
	}
	if !res.DestinationAddressExcluded {
		t.Errorf("DestinationAddressExcluded = false, want true (matched rule is destination-address-excluded)")
	}
	// RuleID must equal the inventory's stable identity for this zone-pair rule.
	want := dpuserspace.StablePolicyRuleID("trust", "untrust", "exclude-permit")
	if res.RuleID != want {
		t.Errorf("RuleID = %q, want %q", res.RuleID, want)
	}
}

// TestNonExcludedRuleReportsNoExclusion confirms the flags are false for a
// plain (non-excluded) matched rule, so an ordinary verdict never spuriously
// prints "(except)". RuleID is still populated.
func TestNonExcludedRuleReportsNoExclusion(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name:   "plain-permit",
							Action: config.PolicyPermit,
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"any"},
								DestinationAddresses: []string{"any"},
								Applications:         []string{"any"},
							},
						},
					},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.Matched {
		t.Fatalf("expected match; res = %+v", res)
	}
	if res.SourceAddressExcluded || res.DestinationAddressExcluded {
		t.Errorf("plain rule reported exclusion: src=%v dst=%v", res.SourceAddressExcluded, res.DestinationAddressExcluded)
	}
	if want := dpuserspace.StablePolicyRuleID("trust", "untrust", "plain-permit"); res.RuleID != want {
		t.Errorf("RuleID = %q, want %q", res.RuleID, want)
	}
}

// TestGlobalMatchRuleIDUsesJunosGlobal pins that a matched GLOBAL policy's RuleID
// uses the reserved "junos-global->junos-global/<name>" identity the inventory
// global rows use (pkg/api/security.go / pkg/grpcapi/server_show_zones.go), NOT
// the policy's optional match-SCOPE zones — so a simulator hit joins to the same
// inventory row. The exclusion flags also flow through the global branch.
//
// RED-on-revert: without the global -> junos-global RuleID remap in matchedResult
// the RuleID would carry the match-scope zone ("trust->junos-global/..." here),
// breaking the inventory join.
func TestGlobalMatchRuleIDUsesJunosGlobal(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			GlobalPolicies: []*config.Policy{
				{
					Name:   "g-exclude",
					Action: config.PolicyPermit,
					Match: config.PolicyMatch{
						SourceAddresses:       []string{"10.0.99.0/24"},
						SourceAddressExcluded: true,
						DestinationAddresses:  []string{"any"},
						Applications:          []string{"any"},
						FromZones:             []string{"trust"},
					},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	res := Match(cfg, Query{
		FromZone: "trust",
		ToZone:   "untrust",
		SrcIP:    net.ParseIP("10.0.5.7"), // outside the excluded set => matches
		Protocol: "tcp",
		DstPort:  PortPtr(80),
	})
	if !res.Matched || !res.Global {
		t.Fatalf("expected global match; res = %+v", res)
	}
	if !res.SourceAddressExcluded {
		t.Errorf("SourceAddressExcluded = false, want true on a global excluded rule")
	}
	want := dpuserspace.StablePolicyRuleID("junos-global", "junos-global", "g-exclude")
	if res.RuleID != want {
		t.Errorf("RuleID = %q, want %q (inventory global identity)", res.RuleID, want)
	}
}
