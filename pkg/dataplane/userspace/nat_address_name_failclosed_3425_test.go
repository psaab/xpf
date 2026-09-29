package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3425: on the tolerant load / peer-sync path a NAT rule may carry a
// defined-but-unresolvable `match {source,destination}-address-name` (the
// strict commit gate downgrades to a warning so the config still boots #1960).
// The snapshot builder must fail CLOSED for such a reference: it appends the
// raw, unparseable book-name token so the source/destination constraint stays
// NON-EMPTY (source_constrained / destination present) but matches NOTHING — it
// must NOT collapse to an empty (match-any) list that would broaden the rule.
//
// These tests pin that fail-closed contract directly at the builder, so a
// future change that "cleaned up" the raw-token append (turning the unresolved
// reference into a no-op = wildcard) would be caught here.

// emptySetCfgSNAT builds a config whose SNAT rule references a DEFINED but
// member-less address-set — resolveUserspaceAddressBookEntry returns ok=false,
// so the builder takes the raw-token fail-closed branch.
func emptySetCfgSNAT() *config.Config {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		AddressSets: map[string]*config.AddressSet{
			"EMPTY": {Name: "EMPTY"}, // defined, no members
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name:  "dead-scope",
				Match: config.NATMatch{SourceAddressName: "EMPTY"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	return cfg
}

// TestSNATEmptyAddressSetFailsClosed: the source list must carry the raw
// unmatchable token and must NOT be empty (which would match any source).
func TestSNATEmptyAddressSetFailsClosed(t *testing.T) {
	snaps := buildSourceNATSnapshots(emptySetCfgSNAT(), nil)
	if len(snaps) == 0 {
		t.Fatal("expected a source NAT snapshot")
	}
	src := snaps[0].SourceAddresses
	if len(src) == 0 {
		t.Fatal("source list collapsed to empty (match-any) — fail-OPEN; an " +
			"unresolvable source-address-name must stay non-empty + unmatchable (#3425)")
	}
	if !contains(src, "EMPTY") {
		t.Fatalf("source list must carry the raw unmatchable token to fail closed, got %v", src)
	}
}

// emptySetCfgDNAT is the destination twin.
func emptySetCfgDNAT() *config.Config {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		AddressSets: map[string]*config.AddressSet{
			"EMPTY": {Name: "EMPTY"},
		},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		RuleSets: []*config.NATRuleSet{
			{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "dead-scope",
					Match: config.NATMatch{DestinationAddressName: "EMPTY"},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
	}
	return cfg
}

// TestDNATEmptyAddressSetFailsClosed: the DNAT builder appends the raw
// unparseable token to the destination list, then dnatDestinationParts rejects
// it and emits NO snapshot entry — the rule matches NOTHING (fail-closed). It
// must NOT emit an unscoped entry that would DNAT every destination.
func TestDNATEmptyAddressSetFailsClosed(t *testing.T) {
	snaps := buildDestinationNATSnapshots(emptySetCfgDNAT(), nil)
	if len(snaps) != 0 {
		t.Fatalf("a DNAT rule whose only destination-address-name is "+
			"unresolvable must emit no snapshot entry (match-nothing), got %d "+
			"entries %+v — fail-OPEN if any entry DNATs an unscoped destination (#3425)",
			len(snaps), snaps)
	}
}
func mixedAddressBook3425() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"MIXED": {
				Name:               "MIXED",
				Value:              "10.0.0.0/8",
				UnimplementedForms: []string{"dns-name"},
			},
		},
	}
}

func TestSNATMixedAddressNameFailsClosed(t *testing.T) {
	cfg := emptySetCfgSNAT()
	cfg.Security.AddressBook = mixedAddressBook3425()
	cfg.Security.NAT.Source[0].Rules[0].Match.SourceAddressName = "MIXED"
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) == 0 {
		t.Fatal("expected the fail-closed source NAT snapshot")
	}
	src := snaps[0].SourceAddresses
	if !contains(src, "MIXED") {
		t.Fatalf("source constraint must retain the raw unmatchable name, got %v", src)
	}
	if contains(src, "10.0.0.0/8") {
		t.Fatalf("mixed address's otherwise-usable prefix leaked into NAT source constraint: %v", src)
	}
}

func TestDNATMixedAddressNameFailsClosed(t *testing.T) {
	cfg := emptySetCfgDNAT()
	cfg.Security.AddressBook = mixedAddressBook3425()
	cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match.DestinationAddressName = "MIXED"
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 0 {
		t.Fatalf("mixed address-name must not yield a DNAT destination prefix; got %+v", snaps)
	}
}
