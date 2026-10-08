package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6143's former partial-resolution expectation is superseded by #12216:
// a NAT reference to an address-set with any dangling member must refuse the
// whole set, just like the policy path. Publishing only the static member
// under-matches the operator's intended translation scope.
//
// These cells cover each NAT source/destination address-name consumer. A failed
// SNAT/DNAT constraint remains unmatchable; it never publishes the surviving
// static subset. The strict commit gate still reports the dangling reference.

// mixedStaticGhostAddressBook builds an address book with two sets, each mixing
// one resolvable static member with the unresolvable non-feed token "ghost":
//   - "mixed-static-ghost": { static-a = 10.20.0.0/16, ghost } — CIDR member for
//     the SNAT source/destination + DNAT source-constraint cases.
//   - "mixed-host-ghost":   { host-a  = 10.30.0.9/32,  ghost } — target for
//     the DNAT destination-address-name case.
//
// "ghost" is neither a static address, nor a set, nor a feed binding. The
// resolver now poisons the entire closure instead of silently dropping it.
func mixedStaticGhostAddressBook() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"static-a": {Name: "static-a", Value: "10.20.0.0/16"},
			"host-a":   {Name: "host-a", Value: "10.30.0.9/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"mixed-static-ghost": {Name: "mixed-static-ghost", Addresses: []string{"static-a", "ghost"}},
			"mixed-host-ghost":   {Name: "mixed-host-ghost", Addresses: []string{"host-a", "ghost"}},
		},
	}
}

func Test_nat_mixed_static_and_unresolvable_set_fails_closed_6143(t *testing.T) {
	// A live overlay for an UNRELATED feed, so the resolver's overlay path is
	// exercised but has nothing to contribute to either mixed set (neither
	// references "bad-feed"). Assertions below confirm the unrelated feed does
	// not leak into these sets.
	overlay := map[string][]string{"bad-feed": {"198.51.100.0/24"}}

	// --- SNAT source-address-name -> mixed static+ghost set ---
	t.Run("snat_source_mixed_static_ghost", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = mixedStaticGhostAddressBook()
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "mixed-src",
					Match: config.NATMatch{SourceAddressName: "mixed-static-ghost"},
					Then:  config.NATThen{Type: config.NATSource, Interface: true},
				},
			}},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		got := snatSourceAddrs(snap, "mixed-src")
		if !contains(got, "mixed-static-ghost") {
			t.Fatalf("SNAT source must retain the raw unmatchable set name after the "+
				"dangling member poisons the whole set, got %v", got)
		}
		if contains(got, "10.20.0.0/16") {
			t.Fatalf("SNAT source published a partial static subset despite dangling member: %v", got)
		}
		if contains(got, "0.0.0.0/0") || contains(got, "::/0") {
			t.Fatalf("failed NAT address reference widened to match-any, got %v", got)
		}
		if contains(got, "198.51.100.0/24") {
			t.Fatalf("unrelated feed prefixes leaked into this set: %v", got)
		}
	})

	// --- SNAT destination-address-name -> mixed static+ghost set ---
	t.Run("snat_dest_mixed_static_ghost", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = mixedStaticGhostAddressBook()
		cfg.Security.NAT.Source = []*config.NATRuleSet{
			{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "mixed-dst",
					Match: config.NATMatch{DestinationAddressName: "mixed-static-ghost"},
					Then:  config.NATThen{Type: config.NATSource, Interface: true},
				},
			}},
		}
		snap := natFeedSnapHelper(t, cfg, overlay)
		got := snatDestAddrs(snap, "mixed-dst")
		if !contains(got, "mixed-static-ghost") || contains(got, "10.20.0.0/16") {
			t.Fatalf("SNAT destination must poison the whole dangling set, got %v", got)
		}
	})

	// --- DNAT source-address-name (the #2394 source constraint on a
	// destination-translation rule) -> mixed static+ghost set ---
	t.Run("dnat_source_mixed_static_ghost", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = mixedStaticGhostAddressBook()
		cfg.Security.NAT.Destination = &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{
				{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
					{
						Name: "mixed-src-dnat",
						Match: config.NATMatch{
							SourceAddressName:  "mixed-static-ghost",
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
			if s.Name == "mixed-src-dnat" {
				got = s.SourceAddresses
				break
			}
		}
		if !contains(got, "mixed-static-ghost") || contains(got, "10.20.0.0/16") {
			t.Fatalf("DNAT source constraint must poison the whole dangling set, got %v", got)
		}
	})

	// --- DNAT destination-address-name -> mixed static+ghost set ---
	// The dangling member poisons the translation target, so the rule installs
	// no destination row rather than translating only the surviving host.
	t.Run("dnat_dest_mixed_static_ghost", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Security.AddressBook = mixedStaticGhostAddressBook()
		cfg.Security.NAT.Destination = &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{
				{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
					{
						Name: "mixed-dst-dnat",
						Match: config.NATMatch{
							DestinationAddressName: "mixed-host-ghost",
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
			if s.Name == "mixed-dst-dnat" {
				got = append(got, s.DestinationAddress)
			}
		}
		if len(got) != 0 {
			t.Fatalf("DNAT installed a partial destination row despite dangling member: %v", got)
		}
	})
}
