package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3303: NAT `match {source,destination}-address-name` references must resolve
// the dynamic-address feed overlay (#2049), exactly as the policy/address-book
// path does. Before the fix the snapshot builder threaded feedOverlay into the
// policy and address-book builders but called the NAT builders with NO overlay,
// so a NAT rule scoped to a feed-backed address-name resolved STATIC-ONLY and
// matched nothing on live feed content — contradicting docs/feature-gaps.md's
// claim that feeds are enforced via "policy/NAT address-name bindings".
//
// These are the fail-on-revert pins. They drive the FULL public snapshot path
// (buildSnapshotWithSchedulerState) with a feed overlay whose feed-backed name
// is ABSENT from the static address book — so the ONLY way the feed prefixes
// reach the NAT source/destination lists is the overlay threading. Reverting
// nat.go + builder.go to the pre-#3303 state makes every assertion below RED:
//   - SNAT source-address-name falls back to the raw "bad-feed" token
//     (fail-closed, no feed prefix),
//   - SNAT destination-address-name likewise,
//   - DNAT destination-address-name resolves nothing → the rule installs no
//     table row at all.

func natFeedSnapHelper(t *testing.T, cfg *config.Config, overlay map[string][]string) *ConfigSnapshot {
	t.Helper()
	snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, nil, nil, overlay)
	if err != nil {
		t.Fatalf("buildSnapshotWithSchedulerState: %v", err)
	}
	if snap == nil {
		t.Fatal("nil snapshot")
	}
	return snap
}

func snatSourceAddrs(snap *ConfigSnapshot, name string) []string {
	for _, s := range snap.SourceNAT {
		if s.Name == name {
			return s.SourceAddresses
		}
	}
	return nil
}

func snatDestAddrs(snap *ConfigSnapshot, name string) []string {
	for _, s := range snap.SourceNAT {
		if s.Name == name {
			return s.DestinationAddresses
		}
	}
	return nil
}

// TestSNATSourceAddressNameResolvesFeedOverlay: a source NAT rule scoped to a
// feed-backed `match source-address-name` must carry the live feed prefixes in
// its source constraint. The feed-backed name is NOT in any static book, so the
// raw-token fail-closed fallback is what a revert produces.
func TestSNATSourceAddressNameResolvesFeedOverlay(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name:  "feed-scoped",
				Match: config.NATMatch{SourceAddressName: "bad-feed"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	overlay := map[string][]string{"bad-feed": {"198.51.100.0/24", "203.0.113.7/32"}}

	snap := natFeedSnapHelper(t, cfg, overlay)
	got := snatSourceAddrs(snap, "feed-scoped")
	if !contains(got, "198.51.100.0/24") || !contains(got, "203.0.113.7/32") {
		t.Fatalf("SNAT source-address-name must resolve feed prefixes, got %v "+
			"(missing => feedOverlay not threaded into NAT builder #3303)", got)
	}
	if contains(got, "bad-feed") {
		t.Fatalf("SNAT source list must not carry the raw feed name token (fail-closed fallback => overlay not threaded), got %v", got)
	}
}

// TestSNATDestinationAddressNameResolvesFeedOverlay: the SNAT builder also
// carries the destination constraint; a feed-backed destination-address-name
// must resolve there too.
func TestSNATDestinationAddressNameResolvesFeedOverlay(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name:  "feed-dst",
				Match: config.NATMatch{DestinationAddressName: "bad-feed"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	overlay := map[string][]string{"bad-feed": {"198.51.100.0/24"}}

	snap := natFeedSnapHelper(t, cfg, overlay)
	got := snatDestAddrs(snap, "feed-dst")
	if !contains(got, "198.51.100.0/24") {
		t.Fatalf("SNAT destination-address-name must resolve feed prefixes, got %v #3303", got)
	}
	if contains(got, "bad-feed") {
		t.Fatalf("SNAT destination list must not carry the raw feed name token, got %v", got)
	}
}

// TestDNATDestinationAddressNameResolvesFeedOverlay: a DNAT rule scoped to a
// feed-backed destination-address-name must install one table entry per feed
// host. With the overlay un-threaded the name resolves to nothing → the rule is
// continue-skipped → NO snapshot row at all.
func TestDNATDestinationAddressNameResolvesFeedOverlay(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name: "feed-dnat",
					Match: config.NATMatch{
						DestinationAddressName: "bad-feed",
						Protocol:               "tcp",
						DestinationPort:        443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	overlay := map[string][]string{"bad-feed": {"198.51.100.42/32", "198.51.100.43/32"}}

	snap := natFeedSnapHelper(t, cfg, overlay)
	var got []string
	for _, s := range snap.DestinationNAT {
		if s.Name == "feed-dnat" {
			got = append(got, s.DestinationAddress)
		}
	}
	if !contains(got, "198.51.100.42") || !contains(got, "198.51.100.43") {
		t.Fatalf("DNAT destination-address-name must install one entry per feed host, got %v "+
			"(empty => feedOverlay not threaded => rule dropped #3303)", got)
	}
}

// TestDNATSourceAddressNameResolvesFeedOverlay: a DNAT rule scoped to a
// feed-backed `match source-address-name` carries the #2394 source constraint;
// the feed prefixes must resolve into the snapshot's SourceAddresses (otherwise
// the destination translation the operator scoped to a named feed set fires for
// every source = fail-open). This completes the source+dest feed coverage
// symmetry alongside TestDNATDestinationAddressNameResolvesFeedOverlay. With the
// overlay un-threaded the name resolves to the raw token (fail-closed) instead.
func TestDNATSourceAddressNameResolvesFeedOverlay(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name: "feed-src-dnat",
					Match: config.NATMatch{
						SourceAddressName:  "bad-feed",
						DestinationAddress: "198.51.100.9",
						Protocol:           "tcp",
						DestinationPort:    443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	overlay := map[string][]string{"bad-feed": {"203.0.113.0/24", "192.0.2.7/32"}}

	snap := natFeedSnapHelper(t, cfg, overlay)
	var got []string
	for _, s := range snap.DestinationNAT {
		if s.Name == "feed-src-dnat" {
			got = s.SourceAddresses
			break
		}
	}
	if !contains(got, "203.0.113.0/24") || !contains(got, "192.0.2.7/32") {
		t.Fatalf("DNAT source-address-name must resolve feed prefixes, got %v "+
			"(missing => feedOverlay not threaded into DNAT builder #3303)", got)
	}
	if contains(got, "bad-feed") {
		t.Fatalf("DNAT source list must not carry the raw feed name token (fail-closed fallback => overlay not threaded), got %v", got)
	}
}

// TestNATAddressNameUnionsStaticBookAndFeedOverlay: a usable static alias and
// direct feed binding publish both prefixes, matching the policy book row.
func TestNATAddressNameUnionsStaticBookAndFeedOverlay(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"mixed": {Name: "mixed", Value: "10.10.0.0/16"},
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name:  "union",
				Match: config.NATMatch{SourceAddressName: "mixed"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	overlay := map[string][]string{"mixed": {"198.51.100.0/24"}}

	snap := natFeedSnapHelper(t, cfg, overlay)
	got := snatSourceAddrs(snap, "union")
	if !contains(got, "10.10.0.0/16") {
		t.Fatalf("usable static alias must remain in the direct feed-bound match, got %v", got)
	}
	if !contains(got, "198.51.100.0/24") {
		t.Fatalf("direct feed-bound name must resolve its live feed prefix, got %v", got)
	}
}
