package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15678: buildNAT64Snapshots carries the rule-set's ingress scoping onto
// the wire and resolves `match source-address-name` to prefixes.
// Fail-on-revert: dropping the scope stamp leaves FromZone empty.
func TestBuildNAT64SnapshotsCarriesScope15678(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"clients-v6": {Name: "clients-v6", Value: "2001:db8:1::/48"},
		},
		AddressSets: map[string]*config.AddressSet{},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.1/32"}},
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name:               "rs1",
		Prefix:             "64:ff9b::/96",
		SourcePool:         "p64",
		FromZone:           "trust",
		SourceAddresses:    []string{"2001:db8:2::/48"},
		SourceAddressNames: []string{"clients-v6"},
	}}
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.FromZone != "trust" {
		t.Fatalf("FromZone = %q, want trust", s.FromZone)
	}
	found := map[string]bool{}
	for _, a := range s.SourceAddresses {
		found[a] = true
	}
	if !found["2001:db8:2::/48"] || !found["2001:db8:1::/48"] {
		t.Fatalf("SourceAddresses = %v, want authored + resolved name prefixes", s.SourceAddresses)
	}
}

// #15932: the snapshot builder folds a hand-built rule-set's FromZones
// list (plus its singular FromZone) into the plural wire field so the
// dataplane unions every authored zone.
func TestBuildNAT64SnapshotsCarriesZoneList15932(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.1/32"}},
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name: "rs1", Prefix: "64:ff9b::/96", SourcePool: "p64",
		FromZone: "trust", FromZones: []string{"trust", "untrust"},
	}}
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].FromZones) != 2 {
		t.Fatalf("FromZones = %v, want [trust untrust]", snaps)
	}
	if snaps[0].FromZones[0] != "trust" || snaps[0].FromZones[1] != "untrust" {
		t.Fatalf("FromZones = %v, want [trust untrust]", snaps[0].FromZones)
	}
}

// #16049: the snapshot builder folds a hand-built rule-set's
// FromRoutingInstances list (plus its singular) into the plural wire
// field so the dataplane unions every authored routing-instance.
func TestBuildNAT64SnapshotsCarriesRIList16049(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.1/32"}},
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name: "rs1", Prefix: "64:ff9b::/96", SourcePool: "p64",
		FromRoutingInstance: "blue", FromRoutingInstances: []string{"blue", "red"},
	}}
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].FromRoutingInstances) != 2 {
		t.Fatalf("FromRoutingInstances = %v, want [blue red]", snaps)
	}
	if snaps[0].FromRoutingInstances[0] != "blue" || snaps[0].FromRoutingInstances[1] != "red" {
		t.Fatalf("FromRoutingInstances = %v, want [blue red]", snaps[0].FromRoutingInstances)
	}
	if snaps[0].FromRoutingInstance != "blue" {
		t.Fatalf("FromRoutingInstance = %q, want blue (singular mirror)", snaps[0].FromRoutingInstance)
	}
}
