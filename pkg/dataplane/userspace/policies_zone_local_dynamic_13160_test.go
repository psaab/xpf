package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13160 (D4-01): a zone-local address-book name that also names a
// dynamic-address binding must honor the feed contract exactly like the
// global name: unready feeds poison the policy, ready feeds merge their
// prefixes into the zone-local row, and a hold-dropped fail-mode drop feed
// suppresses the static fallback instead of resurrecting it.

func zoneLocalDynamicCfg13160() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			AddressBook: &config.AddressBook{
				Addresses: map[string]*config.Address{
					"zone-local/trust/feed-obj": {Name: "zone-local/trust/feed-obj", Value: "192.0.2.1/32"},
					"feed-obj":                  {Name: "feed-obj", Value: "192.0.2.1/32"},
				},
			},
			DynamicAddress: config.DynamicAddressConfig{
				AddressBindings: map[string]*config.AddressBinding{
					"feed-obj": {Name: "feed-obj", FailMode: "drop"},
				},
			},
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{
						{
							Name:   "deny-zone-local",
							Action: config.PolicyDeny,
							Match: config.PolicyMatch{
								SourceAddresses:      []string{"zone-local/trust/feed-obj"},
								DestinationAddresses: []string{"any"},
								Applications:         []string{"any"},
							},
						},
					},
				},
			},
		},
	}
}

func bookPrefixes13160(t *testing.T, snap *ConfigSnapshot, id uint32) []string {
	t.Helper()
	for _, entry := range snap.AddressBooks {
		if entry.ID == id {
			return entry.PrefixesV4
		}
	}
	t.Fatalf("address book ID %d not found in snapshot; rows=%+v", id, snap.AddressBooks)
	return nil
}

func TestZoneLocalDynamicAddressFeedContract13160(t *testing.T) {
	// (a) Unready feed (nil overlay) must poison the deny policy the same
	// way the global feed-obj reference does, not fall back to static.
	snap, err := buildSnapshotWithSchedulerState(zoneLocalDynamicCfg13160(), config.UserspaceConfig{}, 1, 1, nil, nil, nil)
	if err != nil {
		t.Fatalf("buildSnapshot unready: %v", err)
	}
	reasons := collectPolicyContentRejections(snap.Policies)
	if len(reasons) == 0 {
		t.Fatalf("zone-local unready feed: expected policy content rejection, got none (srcBookIDs=%v)", snap.Policies[0].SourceBookIDs)
	}

	// (b) Ready feed prefixes must merge into the zone-local book row.
	overlayReady := map[string][]string{"feed-obj": {"203.0.113.0/24"}}
	snapReady, err := buildSnapshotWithSchedulerState(zoneLocalDynamicCfg13160(), config.UserspaceConfig{}, 1, 1, nil, nil, overlayReady)
	if err != nil {
		t.Fatalf("buildSnapshot ready: %v", err)
	}
	zoneLocal := bookPrefixes13160(t, snapReady, snapReady.Policies[0].SourceBookIDs[0])
	foundStatic, foundFeed := false, false
	for _, p := range zoneLocal {
		if p == "192.0.2.1/32" {
			foundStatic = true
		}
		if p == "203.0.113.0/24" {
			foundFeed = true
		}
	}
	if !foundStatic || !foundFeed {
		t.Fatalf("zone-local ready feed: expected static 192.0.2.1/32 and feed 203.0.113.0/24 merged, got %v", zoneLocal)
	}
	if reasons := collectPolicyContentRejections(snapReady.Policies); len(reasons) != 0 {
		t.Fatalf("zone-local ready feed: unexpected rejection %v", reasons)
	}

	// (c) Hold-dropped fail-mode drop feed on an excluded rule must reject
	// and must not resurrect the static prefix in the zone-local row.
	cfgExcluded := zoneLocalDynamicCfg13160()
	cfgExcluded.Security.Policies[0].Policies[0].Action = config.PolicyPermit
	cfgExcluded.Security.Policies[0].Policies[0].Match.SourceAddressExcluded = true
	overlayDropped := map[string][]string{"feed-obj": {}}
	snapDropped, err := buildSnapshotWithSchedulerState(cfgExcluded, config.UserspaceConfig{}, 1, 1, nil, nil, overlayDropped)
	if err != nil {
		t.Fatalf("buildSnapshot dropped: %v", err)
	}
	reasons = collectPolicyContentRejections(snapDropped.Policies)
	if len(reasons) == 0 {
		t.Fatalf("zone-local hold-dropped feed on excluded rule: expected rejection, got none")
	}
	for _, entry := range snapDropped.AddressBooks {
		for _, prefix := range entry.PrefixesV4 {
			if prefix == "192.0.2.1/32" {
				t.Fatalf("zone-local hold-dropped feed: static prefix resurrected, row=%+v", entry)
			}
		}
	}
}
