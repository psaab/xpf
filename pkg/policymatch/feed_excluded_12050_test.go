package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func excludedDropFeedConfig12050(addresses []string, nested, destinationExcluded bool) *config.Config {
	addressBook := &config.AddressBook{}
	if nested {
		addressBook.AddressSets = map[string]*config.AddressSet{
			"partners-set": {Name: "partners-set", Addresses: []string{"partners"}},
		}
		addresses = []string{"partners-set"}
	}
	match := config.PolicyMatch{
		SourceAddresses:       addresses,
		SourceAddressExcluded: !destinationExcluded,
		DestinationAddresses:  []string{"any"},
		Applications:          []string{"any"},
	}
	if destinationExcluded {
		match.SourceAddresses = []string{"any"}
		match.SourceAddressExcluded = false
		match.DestinationAddresses = addresses
		match.DestinationAddressExcluded = true
	}
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyPermit,
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			AddressBook: addressBook,
			DynamicAddress: config.DynamicAddressConfig{
				AddressBindings: map[string]*config.AddressBinding{
					"partners": {Name: "partners", FeedNames: []string{"partner-feed"}, FailMode: "drop"},
				},
			},
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{
					{
						Name:   "deny-except-partners",
						Match:  match,
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

func TestExcludedDenyOverEmptyDropFeedFailsClosed12050(t *testing.T) {
	for _, tc := range []struct {
		name                string
		addresses           []string
		nested              bool
		destinationExcluded bool
	}{
		{name: "source direct", addresses: []string{"partners"}},
		{name: "source nested", nested: true},
		{name: "destination direct", addresses: []string{"partners"}, destinationExcluded: true},
		{name: "destination nested", nested: true, destinationExcluded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := excludedDropFeedConfig12050(tc.addresses, tc.nested, tc.destinationExcluded)
			res := Match(cfg, Query{
				FromZone:    "trust",
				ToZone:      "untrust",
				SrcIP:       net.ParseIP("203.0.113.7"),
				DstIP:       net.ParseIP("192.0.2.80"),
				Protocol:    "tcp",
				DstPort:     80,
				FeedOverlay: map[string][]string{"partners": {}},
			})
			// Before the content-rejection fix, the excluded DENY did not match
			// the empty set and the explicit later-permit rule won. The shared
			// assertion rejects both that fabricated verdict and default fallback.
			assertContentRejected(t, res, "trust->untrust/deny-except-partners")
			if !strings.Contains(strings.Join(res.ContentRejectionReasons, " | "), "partners") {
				t.Fatalf("rejection reason does not name the hold-dropped feed: %v", res.ContentRejectionReasons)
			}
		})
	}
}
