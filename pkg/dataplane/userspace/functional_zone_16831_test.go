package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16831: the functional (host-only) mark must reach the wire ZoneSnapshot
// for a zone compiled from `security zones functional-zone management`,
// and must NOT appear for the `security-zone management` twin. The Rust
// PolicyState reads this field to deny functional transit and exclude
// the zone from global/default matching.
//
// RED-on-revert: dropping the Functional carry in buildZoneSnapshots (or
// the ZoneConfig.Functional stamp) makes the functional row decode
// identical to the twin and this test fails.

func functionalSnapCfg16831(functional bool) *config.Config {
	mgmt := &config.ZoneConfig{
		Name:       "management",
		Interfaces: []string{"ge-0/0/1.0"},
		Functional: functional,
		HostInboundTraffic: &config.HostInboundTraffic{
			SystemServices: []string{"ssh"},
		},
	}
	return &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{
			"management": mgmt,
			"trust":      {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
		},
		GlobalPolicies: []*config.Policy{{
			Name:   "g1",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}},
	}}
}

func TestFunctionalZoneSnapshotWire16831(t *testing.T) {
	snaps := buildZoneSnapshots(functionalSnapCfg16831(true))
	var mgmt *ZoneSnapshot
	for i := range snaps {
		if snaps[i].Name == "management" {
			mgmt = &snaps[i]
		}
		if snaps[i].Name == "trust" && snaps[i].Functional {
			t.Fatal("ordinary trust zone marked Functional")
		}
	}
	if mgmt == nil {
		t.Fatal("management zone snapshot missing")
	}
	if !mgmt.Functional {
		t.Fatal("functional management zone snapshot Functional = false, want true (#16831)")
	}
	// Host-inbound still rides the snapshot: ssh to the interface address
	// remains admissible at the host-inbound layer.
	if !mgmt.HostInboundConfigured || len(mgmt.HostInboundSystemServices) != 1 || mgmt.HostInboundSystemServices[0] != "ssh" {
		t.Fatalf("management host-inbound = configured %v services %v, want [ssh]", mgmt.HostInboundConfigured, mgmt.HostInboundSystemServices)
	}
	// Control: the security-zone twin is an ordinary transit zone.
	twin := buildZoneSnapshots(functionalSnapCfg16831(false))
	for i := range twin {
		if twin[i].Name == "management" && twin[i].Functional {
			t.Fatal("security-zone management twin marked Functional; want ordinary transit zone")
		}
	}
	// The unscoped global permit still publishes (the Rust side excludes
	// the functional zone from its scope at evaluation time).
	rules, err := buildPolicySnapshots(functionalSnapCfg16831(true))
	if err != nil {
		t.Fatalf("buildPolicySnapshots: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.Name == "g1" && r.FromZone == "junos-global" && r.ToZone == "junos-global" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unscoped global permit not published: %+v", rules)
	}
}
