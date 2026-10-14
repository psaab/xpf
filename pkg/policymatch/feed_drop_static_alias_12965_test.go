// feed_drop_static_alias_12965_test.go: #12965 (follow-up #12853).
//
// The simulator's expandBookNameWithMemo skipped a present-EMPTY overlay
// entry and appended the same-named static value, so `show security
// match-policies` (CLI / gRPC / REST MatchPolicies all ride this simulator)
// reported the static prefix as matching where the dataplane — since #12961
// — enforces match-none for a hold-dropped fail-mode drop binding. These
// pins fail on that divergence and pass once the simulator honors the same
// dropped-feed precedence, including for a drop+alias member nested inside
// an address-set.
package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dropAliasConfig12965 builds trust->untrust with a deny scoped to the
// drop+alias name (direct or nested in a set) followed by an explicit
// any-any permit, so a match-none deny visibly falls through to the permit.
func dropAliasConfig12965(addresses []string) *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyPermit,
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					"denylist": {Name: "denylist", Value: "10.0.0.0/8"},
				},
				AddressSets: map[string]*config.AddressSet{
					"denylist-set": {Name: "denylist-set", Addresses: []string{"denylist"}},
				},
			},
			DynamicAddress: config.DynamicAddressConfig{
				AddressBindings: map[string]*config.AddressBinding{
					"denylist": {Name: "denylist", FeedNames: []string{"threat"}, FailMode: "drop"},
				},
			},
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name: "deny-dropped-alias",
						Match: config.PolicyMatch{
							SourceAddresses:      addresses,
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
						Action: config.PolicyDeny,
					},
					{
						Name: "later-permit",
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
						Action: config.PolicyPermit,
					},
				},
			}},
		},
	}
}

func TestSimulatorDropHoldPrecedenceOverStaticAlias12965(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
	}{
		{name: "source direct", addresses: []string{"denylist"}},
		{name: "source nested", addresses: []string{"denylist-set"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dropAliasConfig12965(tc.addresses)
			overlay := map[string][]string{"denylist": {}}

			// The token expands to match-none, not to the static 10.0.0.0/8.
			v4, v6, anyV4, anyV6 := resolveToken(cfg, overlay, "denylist")
			if len(v4) != 0 || len(v6) != 0 || anyV4 || anyV6 {
				t.Fatalf("hold-dropped drop+alias must expand to no prefix, got v4=%v v6=%v any4=%v any6=%v", v4, v6, anyV4, anyV6)
			}

			// A source inside the static alias must therefore NOT hit the
			// deny: the explicit later permit wins.
			res := Match(cfg, Query{
				FromZone:    "trust",
				ToZone:      "untrust",
				SrcIP:       net.ParseIP("10.9.9.9"),
				DstIP:       net.ParseIP("192.0.2.80"),
				Protocol:    "tcp",
				DstPort:     80,
				FeedOverlay: overlay,
			})
			if !res.Matched || res.PolicyName != "later-permit" || res.Action != config.PolicyPermit {
				t.Fatalf("deny over a hold-dropped feed must be match-none, got Matched=%v Policy=%q Action=%v", res.Matched, res.PolicyName, res.Action)
			}

			// Control: a ready feed unions with the static alias, so the deny
			// matches traffic in the feed prefix.
			ready := map[string][]string{"denylist": {"203.0.113.0/24"}}
			res = Match(cfg, Query{
				FromZone:    "trust",
				ToZone:      "untrust",
				SrcIP:       net.ParseIP("203.0.113.7"),
				DstIP:       net.ParseIP("192.0.2.80"),
				Protocol:    "tcp",
				DstPort:     80,
				FeedOverlay: ready,
			})
			if !res.Matched || res.PolicyName != "deny-dropped-alias" || res.Action != config.PolicyDeny {
				t.Fatalf("ready feed must union with the static alias, got Matched=%v Policy=%q Action=%v", res.Matched, res.PolicyName, res.Action)
			}

			// Control: a DECLARED binding absent from the overlay is an
			// unready feed — the whole config fails closed (#12216/#5645
			// doctrine) and the simulator must not fabricate the static
			// alias as a verdict.
			res = Match(cfg, Query{
				FromZone: "trust",
				ToZone:   "untrust",
				SrcIP:    net.ParseIP("10.9.9.9"),
				DstIP:    net.ParseIP("192.0.2.80"),
				Protocol: "tcp",
				DstPort:  80,
			})
			assertContentRejected(t, res, "trust->untrust/deny-dropped-alias")

			// Control: without a declared binding the name is pure static and
			// the alias still matches — the fix must not over-drop statics.
			staticOnly := dropAliasConfig12965(tc.addresses)
			staticOnly.Security.DynamicAddress.AddressBindings = nil
			res = Match(staticOnly, Query{
				FromZone: "trust",
				ToZone:   "untrust",
				SrcIP:    net.ParseIP("10.9.9.9"),
				DstIP:    net.ParseIP("192.0.2.80"),
				Protocol: "tcp",
				DstPort:  80,
			})
			if !res.Matched || res.PolicyName != "deny-dropped-alias" || res.Action != config.PolicyDeny {
				t.Fatalf("pure static alias must keep matching, got Matched=%v Policy=%q Action=%v", res.Matched, res.PolicyName, res.Action)
			}
		})
	}
}

// The destination side rides the same expander; pin it directly so a future
// refactor of the source-side path cannot silently drop the doctrine.
func TestSimulatorDropHoldDestinationAliasMatchNone12965(t *testing.T) {
	cfg := dropAliasConfig12965([]string{"any"})
	cfg.Security.Policies[0].Policies[0].Match = config.PolicyMatch{
		SourceAddresses:      []string{"any"},
		DestinationAddresses: []string{"denylist"},
		Applications:         []string{"any"},
	}
	overlay := map[string][]string{"denylist": {}}

	res := Match(cfg, Query{
		FromZone:    "trust",
		ToZone:      "untrust",
		SrcIP:       net.ParseIP("203.0.113.7"),
		DstIP:       net.ParseIP("10.9.9.9"),
		Protocol:    "tcp",
		DstPort:     80,
		FeedOverlay: overlay,
	})
	if !res.Matched || res.PolicyName != "later-permit" || res.Action != config.PolicyPermit {
		t.Fatalf("destination drop+alias must be match-none, got Matched=%v Policy=%q Action=%v", res.Matched, res.PolicyName, res.Action)
	}
}
