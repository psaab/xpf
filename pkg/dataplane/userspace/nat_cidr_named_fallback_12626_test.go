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

// Probe G (SNAT): a CIDR-named, poisoned set referenced by a SNAT rule
// must publish only the unparseable fallback token — never the name
// literal (which the Rust matcher would parse as 10.99.0.0/16) and never
// the surviving member subset.
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
	snap := natFeedSnapHelper(t, cfg, nil)

	src := snatSourceAddrs(snap, "cidr-named-src")
	if len(src) == 0 {
		t.Fatal("SNAT source list collapsed to empty (match-any) — fail-OPEN")
	}
	if contains(src, cidrNamedSet12626) {
		t.Fatalf("SNAT source carries the parseable name literal %q: %v", cidrNamedSet12626, src)
	}
	if !contains(src, "unresolved-address-name:"+cidrNamedSet12626) {
		t.Fatalf("SNAT source must carry the unparseable fallback token, got %v", src)
	}
	if contains(src, "192.0.2.0/24") {
		t.Fatalf("SNAT source published the surviving member subset despite poisoned closure: %v", src)
	}
	for _, tok := range src {
		if config.NATMatchPrefixParses(tok) {
			t.Fatalf("SNAT source token %q parses as a prefix; rule would match it", tok)
		}
	}

	dst := snatDestAddrs(snap, "cidr-named-dst")
	if contains(dst, cidrNamedSet12626) || contains(dst, "192.0.2.0/24") {
		t.Fatalf("SNAT destination carries the name literal or member subset: %v", dst)
	}
	if len(dst) != 0 && !contains(dst, "unresolved-address-name:"+cidrNamedSet12626) {
		t.Fatalf("SNAT destination must carry only the unparseable fallback token, got %v", dst)
	}
	for _, tok := range dst {
		if config.NATMatchPrefixParses(tok) {
			t.Fatalf("SNAT destination token %q parses as a prefix; rule would match it", tok)
		}
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
