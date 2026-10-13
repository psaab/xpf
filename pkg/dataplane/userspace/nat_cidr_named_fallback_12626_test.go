package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12626: address-book names containing '/' are legal (#4340), so an
// unresolvable set named like a CIDR ("10.99.0.0/16") must not come back
// from the raw-name fallback as a parseable prefix. Pre-fix the fallback
// appended the name verbatim: DNAT installed a longest-prefix row for
// 10.99.0.0/16 (unrelated to the set's members) and SNAT matched that
// literal. The fallback token is now unparseable by construction: a fixed
// prefix + the name, which no IP/CIDR parser (Go, config gate, or Rust)
// can accept for any legal name.

const cidrNamedSet12626 = "10.99.0.0/16"

// cidrNamedBook12626 builds a set NAMED like a CIDR whose closure is
// poisoned (one resolvable member plus a dangling "ghost"), so both NAT
// append helpers take the fallback branch. Its only real member is
// disjoint from the name literal, so any 10.99.0.0/16 in the output can
// only have come from parsing the name itself.
func cidrNamedBook12626() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"real-member": {Name: "real-member", Value: "192.0.2.0/24"},
		},
		AddressSets: map[string]*config.AddressSet{
			cidrNamedSet12626: {Name: cidrNamedSet12626, Addresses: []string{"real-member", "ghost"}},
		},
	}
}

// The fallback token must be unparseable by construction for every
// address-shaped legal name, on BOTH append helpers.
func TestNATFallbackTokenUnparseableForCIDRShapedNames12626(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = cidrNamedBook12626()

	names := []string{
		"10.99.0.0/16",     // CIDR-shaped set name (poisoned closure)
		"10.99.0.5",        // bare IPv4-shaped undefined name
		"10.99.0.5/32",     // host-CIDR-shaped undefined name
		"2001:db8:99::/48", // IPv6 CIDR-shaped undefined name
		"2001:db8::1",      // bare IPv6-shaped undefined name
		"10.99.0.0/+16",    // tolerated prefix-length spelling (#7481)
		"10.99.0.0/016",    // leading-zero prefix-length spelling (#7481)
	}
	for _, name := range names {
		want := "unresolved-address-name:" + name
		if got := appendNATSourceAddressName(cfg, nil, nil, name); len(got) != 1 || got[0] != want {
			t.Fatalf("SNAT source fallback for %q = %v, want [%q]", name, got, want)
		}
		if got := appendNATDestinationAddressName(cfg, nil, nil, name); len(got) != 1 || got[0] != want {
			t.Fatalf("DNAT destination fallback for %q = %v, want [%q]", name, got, want)
		}
		if config.NATMatchPrefixParses(want) {
			t.Fatalf("fallback token %q parses as an IP/CIDR under the shared gate predicate", want)
		}
		if _, _, ok := dnatDestinationParts(want); ok {
			t.Fatalf("fallback token %q parses as a DNAT destination", want)
		}
	}
}

// Probe G (SNAT): a CIDR-named poisoned set clears its entire selector side
// and sets the whole-rule drop marker. The name literal and surviving member
// subset must not publish as a partial match.
func TestSNATCIDRNamedSetDoesNotMatchNameLiteral12626(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = cidrNamedBook12626()
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name:  "cidr-named-src",
				Match: config.NATMatch{SourceAddressName: cidrNamedSet12626},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			},
			{
				Name:  "cidr-named-dst",
				Match: config.NATMatch{DestinationAddressName: cidrNamedSet12626},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	var sourceRule, destinationRule *SourceNATRuleSnapshot
	for i := range snaps {
		switch snaps[i].Name {
		case "cidr-named-src":
			sourceRule = &snaps[i]
		case "cidr-named-dst":
			destinationRule = &snaps[i]
		}
	}
	if sourceRule == nil || len(sourceRule.SourceAddresses) != 0 || !sourceRule.LenientMatchDropped {
		t.Fatalf("poisoned CIDR-named SNAT source must clear its side and drop: %+v", sourceRule)
	}
	if destinationRule == nil || len(destinationRule.DestinationAddresses) != 0 || !destinationRule.LenientMatchDropped {
		t.Fatalf("poisoned CIDR-named SNAT destination must clear its side and drop: %+v", destinationRule)
	}
}

// Probe G2 (DNAT): a CIDR-named, poisoned set referenced as a DNAT
// destination must install NO translation row. Pre-fix it installed a
// longest-prefix row for 10.99.0.0/16, widening inbound translation to
// the whole /16 regardless of the set's members.
func TestDNATCIDRNamedSetInstallsNoRow12626(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = cidrNamedBook12626()
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "192.0.2.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name: "cidr-named-dnat",
					Match: config.NATMatch{
						DestinationAddressName: cidrNamedSet12626,
						Protocol:               "tcp",
						DestinationPort:        443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	snap := natFeedSnapHelper(t, cfg, nil)
	for _, s := range snap.DestinationNAT {
		if s.Name == "cidr-named-dnat" {
			t.Fatalf("DNAT installed a translation row for the CIDR-shaped set name: %+v", s)
		}
	}
}
