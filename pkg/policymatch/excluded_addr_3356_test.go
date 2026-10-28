package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// policyWithSourceExcluded builds a single trust->untrust permit policy whose
// source-address term carries the supplied tokens with source-address-excluded
// set. The destination/application are "any" so only the source side gates the
// verdict. Zones trust+untrust are defined so the #3355 defined-zone guard
// passes and this test isolates the matchAddr semantics.
func policyWithSourceExcluded(srcTokens []string) *config.Config {
	return &config.Config{
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
								SourceAddresses:       srcTokens,
								SourceAddressExcluded: true,
								DestinationAddresses:  []string{"any"},
								Applications:          []string{"any"},
							},
						},
					},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}
}

// TestExcludedEmptySetFailsClosed mirrors policy.rs try_match_rule's #2008
// fail-closed: an EMPTY but `*-address-excluded` set must NOT invert to
// match-all. Before #3356 matchAddr returned the len(addrs)==0 match-any
// short-circuit BEFORE consulting the exclusion flag, so the empty-excluded
// set failed OPEN and reported a permit no dataplane packet would receive.
//
// FAIL-ON-REVERT: restoring the early `if len(addrs)==0 { return true }` makes
// the query match (Matched=true), failing the want-default assertion.
func TestExcludedEmptySetFailsClosed(t *testing.T) {
	cfg := policyWithSourceExcluded(nil) // empty excluded set

	res := Match(cfg, Query{
		FromZone: "trust",
		ToZone:   "untrust",
		SrcIP:    net.ParseIP("10.0.5.7"),
		DstIP:    net.ParseIP("10.0.9.9"),
		Protocol: "tcp",
		DstPort:  PortPtr(80),
	})
	if res.Matched {
		t.Fatalf("empty-but-excluded source set matched (fail-open #2008/#3356); res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny, got %+v", res)
	}
}

// TestExcludedV6OnlyDoesNotOverBlockV4 mirrors the #3023 cross-family case
// preserved by policy.rs's `!(v4_empty && v6_empty)` gate: a v6-only exclusion
// set on a v4 packet leaves v4_empty=true but v6_empty=false, so the v4 address
// is trivially NOT in the excluded set and the side MATCHES. The old
// per-packet-family `contributesFamily` gate failed closed and over-blocked the
// v4 flow.
//
// FAIL-ON-REVERT: restoring the per-packet-family fail-closed (return false
// when the packet's family contributes nothing) makes the v4 query miss
// (Matched=false), failing the want-permit assertion.
func TestExcludedV6OnlyDoesNotOverBlockV4(t *testing.T) {
	cfg := policyWithSourceExcluded([]string{"2001:db8::/32"}) // v6-only exclusion

	res := Match(cfg, Query{
		FromZone: "trust",
		ToZone:   "untrust",
		SrcIP:    net.ParseIP("10.0.5.7"), // v4 source, not in the v6 excluded set
		DstIP:    net.ParseIP("10.0.9.9"),
		Protocol: "tcp",
		DstPort:  PortPtr(80),
	})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("v4 flow over-blocked by a v6-only exclusion (#3023/#3356); res = %+v", res)
	}
}

// TestExcludedV6OnlyStillExcludesV6Match confirms the exclusion is still live:
// a v6 source actually inside the excluded set does NOT match.
func TestExcludedV6OnlyStillExcludesV6Match(t *testing.T) {
	cfg := policyWithSourceExcluded([]string{"2001:db8::/32"})

	res := Match(cfg, Query{
		FromZone: "trust",
		ToZone:   "untrust",
		SrcIP:    net.ParseIP("2001:db8::1"), // inside the excluded set
		DstIP:    net.ParseIP("2001:db8::2"),
		Protocol: "tcp",
		DstPort:  PortPtr(80),
	})
	if res.Matched {
		t.Fatalf("v6 source inside the excluded set matched; exclusion not live; res = %+v", res)
	}
}
