package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2416: a NAT rule scoped by `match source-address-name <book-entry>` is an
// address-book reference, not a literal prefix. The compiler parsed it into
// NATMatch.SourceAddressName but the snapshot builder never resolved it into
// the source list that the #2394 source-constraint enforcement reads, so a
// name-scoped DNAT/SNAT published an EMPTY source list = match-any source =
// fail-open. appendNATSourceAddressName resolves the name to its concrete
// prefixes (reusing the policy-path address-book expander) and appends them.
//
// These tests construct the config at the struct level so they exercise the
// snapshot builder directly. The compiler-side parse + commit-time reject are
// covered in pkg/config (compiler_nat_source_address_name_2416_test.go).

func addressBookForNAT() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"corp-a": {Name: "corp-a", Value: "198.51.100.0/24"},
			"corp-b": {Name: "corp-b", Value: "203.0.113.7/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"corp-net": {Name: "corp-net", Addresses: []string{"corp-a", "corp-b"}},
		},
	}
}

// TestBuildDestinationNATSnapshotsResolvesSourceAddressName is the core
// fail-on-revert pin: a DNAT rule with `match source-address-name corp-net`
// must publish the address-set's expanded prefixes in the snapshot source
// list. Reverting appendNATSourceAddressName leaves SourceAddresses empty
// (match-any = fail-open) and this test FAILS.
func TestBuildDestinationNATSnapshotsResolvesSourceAddressName(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = addressBookForNAT()
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "scoped", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name: "name-scoped",
					Match: config.NATMatch{
						SourceAddressName:  "corp-net",
						DestinationAddress: "203.0.113.20",
						Protocol:           "tcp",
						DestinationPort:    443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}

	snaps := buildDestinationNATSnapshots(cfg, nil)
	var got []string
	for _, s := range snaps {
		if s.Name == "name-scoped" {
			got = s.SourceAddresses
		}
	}
	// Address-set members expanded and sorted by the resolver.
	want := []string{"198.51.100.0/24", "203.0.113.7/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("name-scoped DNAT SourceAddresses = %+v, want resolved book prefixes %+v "+
			"(empty => source-address-name not resolved => fail-open #2416)", got, want)
	}
}

// TestBuildDestinationNATSnapshotsSourceAddressNameAndLiteralUnion: a rule can
// carry BOTH a literal `source-address` and a `source-address-name`; the
// snapshot must union them (literals first, then resolved book prefixes).
func TestBuildDestinationNATSnapshotsSourceAddressNameAndLiteralUnion(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = addressBookForNAT()
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "scoped", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name: "union",
					Match: config.NATMatch{
						SourceAddresses:    []string{"10.1.0.0/16"},
						SourceAddressName:  "corp-a",
						DestinationAddress: "203.0.113.21",
						Protocol:           "tcp",
						DestinationPort:    80,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}

	snaps := buildDestinationNATSnapshots(cfg, nil)
	var got []string
	for _, s := range snaps {
		if s.Name == "union" {
			got = s.SourceAddresses
		}
	}
	want := []string{"10.1.0.0/16", "198.51.100.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("union DNAT SourceAddresses = %+v, want literal+resolved %+v", got, want)
	}
}

// TestBuildDestinationNATSnapshotsUnknownSourceAddressNameFailsClosed: an
// unresolvable book name keeps the source list NON-EMPTY (carries the raw
// token), so source_constrained stays true on the Rust side and the rule
// matches NOTHING — never collapses back to match-any (fail-open).
func TestBuildDestinationNATSnapshotsUnknownSourceAddressNameFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = addressBookForNAT()
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "scoped", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name: "bad-name",
					Match: config.NATMatch{
						SourceAddressName:  "does-not-exist",
						DestinationAddress: "203.0.113.22",
						Protocol:           "tcp",
						DestinationPort:    8080,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}

	snaps := buildDestinationNATSnapshots(cfg, nil)
	var got []string
	for _, s := range snaps {
		if s.Name == "bad-name" {
			got = s.SourceAddresses
		}
	}
	if len(got) != 1 || got[0] != natUnresolvedAddressNamePrefix+"does-not-exist" {
		t.Fatalf("unknown source-address-name SourceAddresses = %+v, want prefixed unparseable fallback "+
			"(non-empty token => fail-closed match-nothing, NOT match-any)", got)
	}
}

// TestBuildSourceNATSnapshotsResolvesSourceAddressName: SNAT shares the same
// builder gap as DNAT. A source-NAT rule scoped by source-address-name must
// carry the resolved prefixes too.
func TestBuildSourceNATSnapshotsResolvesSourceAddressName(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = addressBookForNAT()
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "snat", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name: "name-scoped-snat",
				Match: config.NATMatch{
					SourceAddressName: "corp-net",
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}

	snaps := buildSourceNATSnapshots(cfg, nil)
	var got []string
	for _, s := range snaps {
		if s.Name == "name-scoped-snat" {
			got = s.SourceAddresses
		}
	}
	want := []string{"198.51.100.0/24", "203.0.113.7/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("name-scoped SNAT SourceAddresses = %+v, want resolved book prefixes %+v", got, want)
	}
}
