package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4925: a NAT `match {source,destination}-address-name` reference to an
// address-SET whose MEMBER is a dynamic-address feed must resolve the nested
// member's live feed overlay prefixes — closing the fail-closed parity gap with
// the security-policy path, which has been feed-aware for nested set members
// since #3294 (expandBookNameRecursive). Before #4925 the NAT resolver called
// the STATIC resolveUserspaceAddressBookEntry expander, which never consulted
// feedOverlay for nested members and (crucially) keyed the overlay by the direct
// feed name, not by the containing set — so a `match source-address-name
// bad-set` where bad-set contains feed member bad-feed resolved to NO feed
// prefixes and the rule silently matched nothing.
//
// These are the fail-on-revert pins. Reverting resolveNATAddressNamePrefixes to
// the static resolveUserspaceAddressBookEntry + direct feedOverlay[name] lookup
// makes every "must resolve feed prefixes" assertion below RED:
//   - the static expander poisons bad-set on the unresolvable feed member,
//   - feedOverlay["bad-set"] is empty (the overlay is keyed by "bad-feed"),
//   - so the SNAT source/dest constraint falls back to the raw "bad-set" token
//     (matches nothing) and the DNAT rule installs no table row.
//
// The fail-closed cases (a set whose only member is a genuinely unresolvable
// NON-feed token) must STILL yield no match — the fix must not turn a
// fail-closed miss into a fail-open match-anything.

// feedNestedSetAddressBook builds an address book with:
//   - "feed-only-set": an address-set whose ONLY member is the feed binding
//     "bad-feed" (no static content); the feed prefixes reach the set only via
//     the nested-member overlay merge.
//   - "mixed-set": an address-set with a static member ("static-a" =
//     10.20.0.0/16) AND the feed binding "bad-feed"; both must resolve.
//   - "dead-set": an address-set whose only member is "ghost", a name that is
//     neither a static address, nor a set, nor a feed — the fail-closed case.
func feedNestedSetAddressBook() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"static-a": {Name: "static-a", Value: "10.20.0.0/16"},
		},
		AddressSets: map[string]*config.AddressSet{
			"feed-only-set": {Name: "feed-only-set", Addresses: []string{"bad-feed"}},
			"mixed-set":     {Name: "mixed-set", Addresses: []string{"static-a", "bad-feed"}},
			"dead-set":      {Name: "dead-set", Addresses: []string{"ghost"}},
		},
	}
}

// nat_source_address_name_set_with_feed_member_resolved_4925 drives the full
// public snapshot path for BOTH a feed-only set and a mixed static+feed set,
// on SNAT and DNAT, matching source-address-name AND destination-address-name.
func Test_nat_source_address_name_set_with_feed_member_resolved_4925(t *testing.T) {
	overlay := map[string][]string{"bad-feed": {"198.51.100.0/24", "203.0.113.7/32"}}

	// --- SNAT source-address-name -> feed-only set ---
	t.Run("snat_source_feed_only_set", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = feedNestedSetAddressBook()
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "set-feed-src",
					Match: config.NATMatch{SourceAddressName: "feed-only-set"},
					Then:  config.NATThen{Type: config.NATSource, Interface: true},
				},
			}},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		got := snatSourceAddrs(snap, "set-feed-src")
		if !contains(got, "198.51.100.0/24") || !contains(got, "203.0.113.7/32") {
			t.Fatalf("SNAT source-address-name -> feed-only SET must resolve the nested "+
				"feed member's prefixes, got %v (missing => nested feed member not "+
				"resolved => #4925 regression)", got)
		}
		if contains(got, "feed-only-set") {
			t.Fatalf("SNAT source list must not carry the raw set-name token "+
				"(fail-closed fallback => nested feed member unresolved), got %v", got)
		}
	})

	// --- SNAT source-address-name -> mixed static+feed set ---
	t.Run("snat_source_mixed_set", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = feedNestedSetAddressBook()
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "set-mixed-src",
					Match: config.NATMatch{SourceAddressName: "mixed-set"},
					Then:  config.NATThen{Type: config.NATSource, Interface: true},
				},
			}},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		got := snatSourceAddrs(snap, "set-mixed-src")
		if !contains(got, "10.20.0.0/16") {
			t.Fatalf("mixed SET must keep the static member prefix, got %v", got)
		}
		if !contains(got, "198.51.100.0/24") || !contains(got, "203.0.113.7/32") {
			t.Fatalf("mixed SET must ALSO resolve the nested feed member's prefixes, "+
				"got %v (#4925)", got)
		}
		if contains(got, "mixed-set") || contains(got, "bad-feed") {
			t.Fatalf("mixed SET source list must not carry the raw set/feed name token, got %v", got)
		}
	})

	// --- SNAT destination-address-name -> feed-only set ---
	t.Run("snat_dest_feed_only_set", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = feedNestedSetAddressBook()
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "set-feed-dst",
					Match: config.NATMatch{DestinationAddressName: "feed-only-set"},
					Then:  config.NATThen{Type: config.NATSource, Interface: true},
				},
			}},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		got := snatDestAddrs(snap, "set-feed-dst")
		if !contains(got, "198.51.100.0/24") || !contains(got, "203.0.113.7/32") {
			t.Fatalf("SNAT destination-address-name -> feed-only SET must resolve the "+
				"nested feed member's prefixes, got %v (#4925)", got)
		}
		if contains(got, "feed-only-set") {
			t.Fatalf("SNAT destination list must not carry the raw set-name token, got %v", got)
		}
	})

	// --- DNAT source-address-name -> mixed static+feed set (the #2394 source
	// constraint on a destination-translation rule) ---
	t.Run("dnat_source_mixed_set", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = feedNestedSetAddressBook()
		cfg.Security.NAT.Destination = &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{
				{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
					{
						Name: "set-src-dnat",
						Match: config.NATMatch{
							SourceAddressName:  "mixed-set",
							DestinationAddress: "198.51.100.9",
							Protocol:           "tcp",
							DestinationPort:    443,
						},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
					},
				}},
			},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		var got []string
		for _, s := range snap.DestinationNAT {
			if s.Name == "set-src-dnat" {
				got = s.SourceAddresses
				break
			}
		}
		if !contains(got, "10.20.0.0/16") {
			t.Fatalf("DNAT source-address-name mixed SET must keep the static member, got %v", got)
		}
		if !contains(got, "198.51.100.0/24") || !contains(got, "203.0.113.7/32") {
			t.Fatalf("DNAT source-address-name mixed SET must resolve the nested feed "+
				"member's prefixes, got %v (#4925)", got)
		}
		if contains(got, "mixed-set") || contains(got, "bad-feed") {
			t.Fatalf("DNAT source list must not carry the raw set/feed token, got %v", got)
		}
	})
}

// nat_dest_address_name_set_with_feed_member_resolved_4925 pins the DNAT
// destination-translation path: a `match destination-address-name <set>` whose
// set contains a feed member must install one table row per feed host. This is
// the case that installed NO row at all before #4925 (the destination resolves
// to nothing -> the rule is continue-skipped).
func Test_nat_dest_address_name_set_with_feed_member_resolved_4925(t *testing.T) {
	overlay := map[string][]string{"bad-feed": {"198.51.100.42/32", "198.51.100.43/32"}}

	t.Run("dnat_dest_feed_only_set", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = feedNestedSetAddressBook()
		cfg.Security.NAT.Destination = &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{
				{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
					{
						Name: "set-dst-dnat",
						Match: config.NATMatch{
							DestinationAddressName: "feed-only-set",
							Protocol:               "tcp",
							DestinationPort:        443,
						},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
					},
				}},
			},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		var got []string
		for _, s := range snap.DestinationNAT {
			if s.Name == "set-dst-dnat" {
				got = append(got, s.DestinationAddress)
			}
		}
		if !contains(got, "198.51.100.42") || !contains(got, "198.51.100.43") {
			t.Fatalf("DNAT destination-address-name -> feed-only SET must install one "+
				"table entry per nested feed host, got %v (empty => nested feed member "+
				"unresolved => rule dropped => #4925 regression)", got)
		}
	})

	t.Run("dnat_dest_mixed_set", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = &config.AddressBook{
			Addresses: map[string]*config.Address{
				"host-a": {Name: "host-a", Value: "10.30.0.9/32"},
			},
			AddressSets: map[string]*config.AddressSet{
				"mixed-dst": {Name: "mixed-dst", Addresses: []string{"host-a", "bad-feed"}},
			},
		}
		cfg.Security.NAT.Destination = &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{
				{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
					{
						Name: "set-dst-mixed-dnat",
						Match: config.NATMatch{
							DestinationAddressName: "mixed-dst",
							Protocol:               "tcp",
							DestinationPort:        443,
						},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
					},
				}},
			},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		var got []string
		for _, s := range snap.DestinationNAT {
			if s.Name == "set-dst-mixed-dnat" {
				got = append(got, s.DestinationAddress)
			}
		}
		if !contains(got, "10.30.0.9") {
			t.Fatalf("DNAT destination mixed SET must install the static host row, got %v", got)
		}
		if !contains(got, "198.51.100.42") || !contains(got, "198.51.100.43") {
			t.Fatalf("DNAT destination mixed SET must ALSO install the nested feed host "+
				"rows, got %v (#4925)", got)
		}
	})
}

// Test_nat_address_name_set_unresolvable_nonfeed_member_fails_closed_4925 pins
// that the #4925 fix does NOT weaken fail-closed: a set whose ONLY member is a
// genuinely unresolvable NON-feed token ("ghost") yields no feed prefixes, so
// the SNAT constraint carries the raw set token (matches nothing) and the DNAT
// rule installs no row. It must NOT fail-open to match-anything.
func Test_nat_address_name_set_unresolvable_nonfeed_member_fails_closed_4925(t *testing.T) {
	// Non-empty overlay for a DIFFERENT feed, so the resolver's overlay path is
	// live but has nothing to contribute to "dead-set" (whose member "ghost" is
	// not a feed).
	overlay := map[string][]string{"bad-feed": {"198.51.100.0/24"}}

	t.Run("snat_source_dead_set_fails_closed", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = feedNestedSetAddressBook()
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "dead-scope",
					Match: config.NATMatch{SourceAddressName: "dead-set"},
					Then:  config.NATThen{Type: config.NATSource, Interface: true},
				},
			}},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		got := snatSourceAddrs(snap, "dead-scope")
		if len(got) == 0 {
			t.Fatal("source list collapsed to empty (match-any) — fail-OPEN; an " +
				"unresolvable non-feed set member must stay non-empty + unmatchable (#4925)")
		}
		if !contains(got, natUnresolvedAddressNamePrefix+"dead-set") {
			t.Fatalf("source list must carry the prefixed unmatchable set token to fail "+
				"closed, got %v", got)
		}
		// Must NOT have leaked any other feed's prefixes into this set.
		if contains(got, "198.51.100.0/24") {
			t.Fatalf("unrelated feed prefixes must not leak into an unrelated set, got %v", got)
		}
	})

	t.Run("dnat_dest_dead_set_fails_closed", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = feedNestedSetAddressBook()
		cfg.Security.NAT.Destination = &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{
				{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
					{
						Name: "dead-scope-dnat",
						Match: config.NATMatch{
							DestinationAddressName: "dead-set",
							Protocol:               "tcp",
							DestinationPort:        443,
						},
						Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
					},
				}},
			},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		for _, s := range snap.DestinationNAT {
			if s.Name == "dead-scope-dnat" {
				t.Fatalf("a DNAT rule whose only destination-address-name resolves to an "+
					"unresolvable non-feed set member must emit NO snapshot entry "+
					"(match-nothing), got %+v — fail-OPEN otherwise (#4925)", s)
			}
		}
	})
}
