package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14947: poison empty or unresolved NAT address names so DNAT and SNAT
// `off` exemptions fail closed (D7-04). A poisoned closure or an unready
// (present-but-empty, non-drop) dynamic feed must mark the whole rule so
// the dataplane drops claimed flows instead of exempting/translating a
// surviving subset or falling through to a later translate rule.

func poisonBook14947() *config.AddressBook {
	return &config.AddressBook{
		Addresses: map[string]*config.Address{
			"good": {Name: "good", Value: "10.20.0.0/16"},
		},
		AddressSets: map[string]*config.AddressSet{
			"good-set":   {Name: "good-set", Addresses: []string{"good"}},
			"flawed-set": {Name: "flawed-set", Addresses: []string{"good", "ghost"}},
			"empty-set":  {Name: "empty-set"},
		},
	}
}

func TestDNATPoisonedOffExemptionMarked14947(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = poisonBook14947()
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "dnat", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "exempt",
					Match: config.NATMatch{DestinationAddress: "203.0.113.10", SourceAddressNames: []string{"good-set", "flawed-set"}},
					Then:  config.NATThen{Type: config.NATDestination, Off: true},
				},
				{
					Name:  "translate",
					Match: config.NATMatch{DestinationAddress: "203.0.113.10"},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	var exempt, translate *DestinationNATRuleSnapshot
	for i := range snaps {
		switch snaps[i].Name {
		case "exempt":
			exempt = &snaps[i]
		case "translate":
			translate = &snaps[i]
		}
	}
	if exempt == nil {
		t.Fatal("poisoned DNAT off rule produced no snapshot — exempted traffic would fall through")
	}
	if !exempt.LenientMatchDropped || !exempt.Off {
		t.Fatalf("poisoned DNAT off rule must carry LenientMatchDropped: %+v", exempt)
	}
	if translate == nil || translate.LenientMatchDropped {
		t.Fatalf("healthy DNAT translate rule must stay unmarked: %+v", snaps)
	}
}

func TestDNATPoisonedDestinationNameMarked14947(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = poisonBook14947()
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "dnat", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "mixed",
					Match: config.NATMatch{DestinationAddressNames: []string{"good-set", "flawed-set"}},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) == 0 {
		t.Fatal("poisoned DNAT translate rule produced no snapshot — it must ship marked so claimed flows drop")
	}
	for _, s := range snaps {
		if !s.LenientMatchDropped {
			t.Fatalf("poisoned DNAT entry must be marked: %+v", s)
		}
	}
}

func TestDNATEmptyFeedPoisonsOff14947(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = poisonBook14947()
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"feed-set": {Name: "feed-set", FeedNames: []string{"threat"}},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "dnat", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "exempt",
					Match: config.NATMatch{DestinationAddress: "203.0.113.10", SourceAddressName: "feed-set"},
					Then:  config.NATThen{Type: config.NATDestination, Off: true},
				},
			}},
		},
	}
	overlay := map[string][]string{"feed-set": {}}
	snaps := buildDestinationNATSnapshotsWithFeeds(cfg, nil, overlay)
	if len(snaps) == 0 {
		t.Fatal("empty-feed DNAT off rule produced no snapshot")
	}
	if !snaps[0].LenientMatchDropped {
		t.Fatalf("empty-feed DNAT off exemption must be poisoned: %+v", snaps[0])
	}
	// Control: fail-mode drop present-empty is intentional match-none.
	cfg.Security.DynamicAddress.AddressBindings["feed-set"].FailMode = "drop"
	snaps = buildDestinationNATSnapshotsWithFeeds(cfg, nil, overlay)
	if len(snaps) == 0 || snaps[0].LenientMatchDropped {
		t.Fatalf("fail-mode-drop empty feed must stay unmarked match-none: %+v", snaps)
	}
	// Defined-but-empty static set: its closure is poisoned (no members to
	// resolve), so it poisons like SNAT (#3425) — not a legitimate empty.
	cfg2 := &config.Config{}
	cfg2.Security.AddressBook = poisonBook14947()
	cfg2.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "dnat", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "exempt",
					Match: config.NATMatch{DestinationAddress: "203.0.113.10", SourceAddressName: "empty-set"},
					Then:  config.NATThen{Type: config.NATDestination, Off: true},
				},
			}},
		},
	}
	snaps = buildDestinationNATSnapshots(cfg2, nil)
	if len(snaps) == 0 || !snaps[0].LenientMatchDropped {
		t.Fatalf("defined-but-empty set must poison: %+v", snaps)
	}
}

func TestSNATEmptyFeedPoisonsOff14947(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = poisonBook14947()
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"feed-set": {Name: "feed-set", FeedNames: []string{"threat"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "snat", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{
			{
				Name:  "exempt",
				Match: config.NATMatch{SourceAddressName: "feed-set"},
				Then:  config.NATThen{Type: config.NATSource, Off: true},
			},
			{
				Name:  "translate",
				Match: config.NATMatch{SourceAddresses: []string{"10.0.0.0/8"}},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			},
		}},
	}
	overlay := map[string][]string{"feed-set": {}}
	snaps := buildSourceNATSnapshotsWithFeeds(cfg, nil, overlay)
	var exempt, translate *SourceNATRuleSnapshot
	for i := range snaps {
		switch snaps[i].Name {
		case "exempt":
			exempt = &snaps[i]
		case "translate":
			translate = &snaps[i]
		}
	}
	if exempt == nil || !exempt.LenientMatchDropped {
		t.Fatalf("empty-feed SNAT off exemption must be poisoned: %+v", snaps)
	}
	if translate == nil || translate.LenientMatchDropped {
		t.Fatalf("healthy SNAT translate must stay unmarked: %+v", snaps)
	}
	// Control: fail-mode drop stays unmarked.
	cfg.Security.DynamicAddress.AddressBindings["feed-set"].FailMode = "drop"
	snaps = buildSourceNATSnapshotsWithFeeds(cfg, nil, overlay)
	for i := range snaps {
		if snaps[i].Name == "exempt" && snaps[i].LenientMatchDropped {
			t.Fatalf("fail-mode-drop SNAT off must stay unmarked: %+v", snaps[i])
		}
	}
	// Control: empty-feed translate rule stays unmarked (already match-none).
	cfg.Security.DynamicAddress.AddressBindings["feed-set"].FailMode = ""
	cfg.Security.NAT.Source[0].Rules[0].Then = config.NATThen{Type: config.NATSource, Interface: true}
	snaps = buildSourceNATSnapshotsWithFeeds(cfg, nil, overlay)
	for i := range snaps {
		if snaps[i].Name == "exempt" && snaps[i].LenientMatchDropped {
			t.Fatalf("empty-feed SNAT translate must stay unmarked: %+v", snaps[i])
		}
	}
}

func TestDNATHealthyNamesUnmarked14947(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = poisonBook14947()
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "dnat", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name:  "web",
					Match: config.NATMatch{DestinationAddressName: "good-set", SourceAddressName: "good-set"},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) == 0 {
		t.Fatal("healthy DNAT rule produced no snapshot")
	}
	for _, s := range snaps {
		if s.LenientMatchDropped {
			t.Fatalf("healthy DNAT entry must be unmarked: %+v", s)
		}
	}
}
