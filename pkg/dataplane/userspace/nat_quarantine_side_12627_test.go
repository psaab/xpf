package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12627 probes. SNAT uses whole-rule fail-closed taint on poisoned names;
// DNAT remains per-name because its snapshot has no poison field. Direct feed
// names keep policy parity: use the feed alone for a poisoned same-name static
// closure, otherwise preserve the usable static+feed union.

func natSideBook12627() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"good": {Name: "good", Value: "10.20.0.0/16"},
		},
		AddressSets: map[string]*config.AddressSet{
			"good-set":    {Name: "good-set", Addresses: []string{"good"}},
			"flawed-set":  {Name: "flawed-set", Addresses: []string{"good", "ghost"}},
			"fx":          {Name: "fx", Addresses: []string{"ghost"}},
			"empty-fx":    {Name: "empty-fx"},
			"unusable-fx": {Name: "unusable-fx", Addresses: []string{"dns"}},
		},
	}
}


// Probe F: a poisoned name taints the WHOLE SNAT selector side — bracket lists
// and literal companions are cleared rather than publishing a surviving subset.
func TestNATPoisonedNameTaintsWholeSide12627(t *testing.T) {
	// SNAT source bracket list [good-set flawed-set] plus a literal.
	cfg := &config.Config{}
	cfg.Security.AddressBook = natSideBook12627()
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "snat", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name: "mixed",
				Match: config.NATMatch{
					SourceAddresses:  []string{"192.0.2.0/24"},
					SourceAddressNames: []string{"good-set", "flawed-set"},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	for _, s := range buildSourceNATSnapshots(cfg, nil) {
		if s.Name != "mixed" {
			continue
		}
		if len(s.SourceAddresses) != 0 {
			t.Fatalf("poisoned SNAT source side published a surviving subset: %v", s.SourceAddresses)
		}
		if !s.LenientMatchDropped {
			t.Fatalf("poisoned SNAT rule lacks whole-rule drop marker: %+v", s)
		}
		return
	}
	t.Fatal("mixed SNAT rule produced no snapshot")
}

func TestNATPoisonedDestinationNameTaintsWholeSide12627(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = natSideBook12627()
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "snat", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name: "mixed-destination",
				Match: config.NATMatch{
					DestinationAddresses:    []string{"192.0.2.0/24"},
					DestinationAddressNames: []string{"good-set", "flawed-set"},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	for _, s := range buildSourceNATSnapshots(cfg, nil) {
		if s.Name != "mixed-destination" {
			continue
		}
		if len(s.DestinationAddresses) != 0 || !s.LenientMatchDropped {
			t.Fatalf("poisoned SNAT destination side must be cleared and rule dropped: %+v", s)
		}
		return
	}
	t.Fatal("mixed SNAT destination rule produced no snapshot")
}

// DNAT intentionally retains per-name filtering because its snapshot has no
// whole-rule poison/tombstone field. See docs/log/12627.md.

// Probe F': a poisoned `off` exemption must not fall through. SNAT can carry
// the existing whole-rule LenientMatchDropped poison, so the exemption stops
// (drops) instead of allowing later translation.
func TestNATPoisonedOffExemptionStops12627(t *testing.T) {
	// SNAT: off rule scoped to [good-set flawed-set], then a translating rule.
	cfg := &config.Config{}
	cfg.Security.AddressBook = natSideBook12627()
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "snat", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name:  "exempt",
				Match: config.NATMatch{SourceAddressNames: []string{"good-set", "flawed-set"}},
				Then:  config.NATThen{Type: config.NATSource, Off: true},
			},
			{
				Name:  "translate",
				Match: config.NATMatch{SourceAddresses: []string{"10.0.0.0/8"}},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	var exempt, translate *SourceNATRuleSnapshot
	for i := range snaps {
		switch snaps[i].Name {
		case "exempt":
			exempt = &snaps[i]
		case "translate":
			translate = &snaps[i]
		}
	}
	if translate == nil || translate.LenientMatchDropped {
		t.Fatalf("healthy translating rule must survive untouched: %+v", snaps)
	}
	if exempt == nil {
		t.Fatal("poisoned SNAT off rule produced no snapshot — exempted traffic would fall through to the translating rule")
	}
	if !exempt.LenientMatchDropped {
		t.Fatalf("poisoned SNAT off rule shipped an unmarked exemption (would exempt/flow-through): %+v", exempt)
	}
	if len(exempt.SourceAddresses) != 0 {
		t.Fatalf("poisoned SNAT off side published a subset instead of clearing the selector: %v", exempt.SourceAddresses)
	}
}

// DNAT off rules remain per-name because the DNAT snapshot has no whole-rule
// poison/tombstone field; the shape constraint is recorded in docs/log/12627.md.

// Probe I (positive): a feed-bound name 'fx' that is also a same-named static
// set with a dangling member resolves its feed prefixes (policy parity) —
// NAT must not be stricter than policy. Also pins: a present-empty feed
// resolves empty (match-none), and an unusable static alias beside a ready
// feed still resolves the feed.
func TestNATFeedBoundNameParityWithPolicy12627(t *testing.T) {
	book := natSideBook12627()
	book.Addresses["dns"] = &config.Address{Name: "dns", Value: "10.30.0.0/16", UnimplementedForms: []string{"dns-name"}}
	cfg := &config.Config{}
	cfg.Security.AddressBook = book
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"fx":          {Name: "fx", FeedNames: []string{"threat"}},
		"empty-fx":    {Name: "empty-fx", FeedNames: []string{"threat"}},
		"unusable-fx": {Name: "unusable-fx", FeedNames: []string{"threat"}},
	}

	overlay := map[string][]string{"fx": {"198.51.100.0/24"}}
	if got := resolveNATAddressNamePrefixes(cfg, overlay, "fx"); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("feed-bound fx with dangling same-name set = %v, want [198.51.100.0/24] (policy accepts the direct feed reference)", got)
	}
	if !nameRepresentable(book, overlay, cfg.Security.DynamicAddress.AddressBindings, "fx", map[string]bool{}) {
		t.Fatal("policy-path control rejected the same feed-bound fx reference")
	}

	empty := map[string][]string{"empty-fx": {}}
	if got := resolveNATAddressNamePrefixes(cfg, empty, "empty-fx"); len(got) != 0 {
		t.Fatalf("present-empty feed-bound empty-fx = %v, want empty (match-none, policy parity)", got)
	}

	// A present-empty direct feed remains match-none even when its name parses
	// as a CIDR; do not fall back to that name as a literal prefix.
	cidrFeed := "192.0.2.7/32"
	got, poisoned := appendNATAddressNames(cfg, map[string][]string{cidrFeed: {}}, nil, []string{cidrFeed})
	if poisoned || len(got) != 1 || got[0] != natUnresolvedAddressNamePrefix+cidrFeed {
		t.Fatalf("present-empty CIDR-shaped feed name = %v, poisoned=%v, want the unparseable match-none fallback", got, poisoned)
	}

	// DNAT snapshot level: a destination-address-name fx must translate the
	// feed prefix exactly like the policy path enforces it.
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "dnat", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "feed-dst",
					Match: config.NATMatch{DestinationAddressName: "fx", Protocol: "tcp"},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	found := false
	for _, s := range buildDestinationNATSnapshotsWithFeeds(cfg, nil, overlay) {
		if s.Name == "feed-dst" && s.DestinationPrefix == "198.51.100.0/24" {
			found = true
		}
	}
	if !found {
		t.Fatal("DNAT destination-address-name fx did not install the feed prefix row (NAT stricter than policy)")
	}
}

// Probe I (negative): a feed-bound name with NO live overlay entry keeps
// poisoning (declared-but-unready stays fail-closed), including when it
// names a static set with usable members.
func TestNATFeedBoundUnreadyStillPoisoned12627(t *testing.T) {
	book := natSideBook12627()
	cfg := &config.Config{}
	cfg.Security.AddressBook = book
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"fx": {Name: "fx", FeedNames: []string{"threat"}},
	}
	if got := resolveNATAddressNamePrefixes(cfg, nil, "fx"); len(got) != 0 {
		t.Fatalf("declared-but-unready fx = %v, want poisoned (nil/empty)", got)
	}
}
