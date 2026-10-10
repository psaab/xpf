package userspace

import (
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPolicySnapshotHelperUnsupportedPaddedCIDRMasksRefused12047(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{"ipv4-book", "10.0.0.0/008"},
		{"ipv6-book", "2001:db8::/0032"},
		{"ipv4-inline", "10.0.0.0/008"},
		{"ipv6-inline", "2001:db8::/0032"},
		{"ipv4-over-padded-024", "10.0.0.0/024"},
		{"ipv6-over-padded-0064", "2001:db8::/0064"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inBook := strings.Contains(tc.name, "book")
			cfg := cidrMaskCfg12047(tc.prefix, inBook)
			books, nameToID, err := buildAddressBookTable(cfg)
			if err != nil {
				t.Fatalf("buildAddressBookTable: %v", err)
			}
			if inBook {
				var emitted []string
				for _, book := range books {
					emitted = append(emitted, book.PrefixesV4...)
					emitted = append(emitted, book.PrefixesV6...)
				}
				if !slices.Contains(emitted, tc.prefix) {
					t.Fatalf("precondition: address-book builder did not emit raw token %q: %v", tc.prefix, emitted)
				}
			} else {
				policies, err := buildPolicySnapshotsWithAddressBook(cfg, nil, nil, nameToID)
				if err != nil {
					t.Fatalf("buildPolicySnapshotsWithAddressBook: %v", err)
				}
				if len(policies) != 1 || !slices.Contains(policies[0].SourceLiterals, tc.prefix) {
					t.Fatalf("precondition: inline builder did not emit raw token %q: %+v", tc.prefix, policies)
				}
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if !has12047Reason(reasons) {
				t.Fatalf("mirror did not prevent publishing helper-refused padded token %q: %v", tc.prefix, reasons)
			}
		})
	}
}

func TestPolicySnapshotHelperAcceptedPaddedCIDRMasksAllowed12178(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{"ipv4-book-08", "10.0.0.0/08"},
		{"ipv6-book-032", "2001:db8::/032"},
		{"ipv6-inline-064", "2001:db8::/064"},
		{"ipv6-inline-024", "2001:db8::/024"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inBook := strings.Contains(tc.name, "book")
			cfg := cidrMaskCfg12047(tc.prefix, inBook)
			books, nameToID, err := buildAddressBookTable(cfg)
			if err != nil {
				t.Fatalf("buildAddressBookTable: %v", err)
			}
			if inBook {
				var emitted []string
				for _, book := range books {
					emitted = append(emitted, book.PrefixesV4...)
					emitted = append(emitted, book.PrefixesV6...)
				}
				if !slices.Contains(emitted, tc.prefix) {
					t.Fatalf("precondition: address-book builder did not emit raw token %q: %v", tc.prefix, emitted)
				}
			} else {
				policies, err := buildPolicySnapshotsWithAddressBook(cfg, nil, nil, nameToID)
				if err != nil {
					t.Fatalf("buildPolicySnapshotsWithAddressBook: %v", err)
				}
				if len(policies) != 1 || !slices.Contains(policies[0].SourceLiterals, tc.prefix) {
					t.Fatalf("precondition: inline builder did not emit raw token %q: %+v", tc.prefix, policies)
				}
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if has12047Reason(reasons) {
				t.Fatalf("mirror falsely refused helper-accepted padded token %q: %v", tc.prefix, reasons)
			}
		})
	}
}

func TestPolicySnapshotCanonicalCIDRMasksRemainAccepted12047(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
	}{
		{"ipv4-book", "10.0.0.0/8"},
		{"ipv6-book", "2001:db8::/32"},
		{"ipv4-inline", "10.0.0.0/0"},
		{"ipv6-inline", "2001:db8::/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inBook := strings.Contains(tc.name, "book")
			cfg := cidrMaskCfg12047(tc.prefix, inBook)
			if reasons := PolicyContentRejectionReasons(cfg, nil); has12047Reason(reasons) {
				t.Fatalf("mirror rejected canonical token %q: %v", tc.prefix, reasons)
			}
		})
	}
}

func cidrMaskCfg12047(prefix string, inBook bool) *config.Config {
	source := prefix
	book := &config.AddressBook{}
	if inBook {
		source = "padded"
		book.Addresses = map[string]*config.Address{
			"padded": {Name: "padded", Value: prefix},
		}
	}
	return &config.Config{Security: config.SecurityConfig{
		AddressBook: book,
		Zones: map[string]*config.ZoneConfig{
			"trust":   {Name: "trust"},
			"untrust": {Name: "untrust"},
		},
		Policies: []*config.ZonePairPolicies{{
			FromZone: "trust",
			ToZone:   "untrust",
			Policies: []*config.Policy{{
				Name: "p1",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{source},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
				Action: config.PolicyPermit,
			}},
		}},
	}}
}

func has12047Reason(reasons []string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, "#12047") {
			return true
		}
	}
	return false
}
