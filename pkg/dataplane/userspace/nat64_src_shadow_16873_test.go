package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16873 review fold (F1/F2): the snapshot shapes the static shadow proof
// must mirror. A wildcard beside a poisoned name, and a name whose
// closure contains an empty nested set, both lower to the never-match
// sentinel (constrained, no parseable prefix) — never to match-any.
// The valid-wildcard control lowers to unconstrained ::/0. These pin
// the builder behaviour nat64EffectiveSourcePrefixes now defers to:
// poison is checked for every name before any wildcard is believed.

func nat64TwoSnap16873(t *testing.T, a *config.NAT64RuleSet, book *config.AddressBook) NAT64RuleSnapshot {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.AddressBook = book
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.1/32"}},
	}
	a.Prefix = "64:ff9b::/96"
	a.SourcePool = "p64"
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{a}
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	return snaps[0]
}

func TestNAT64WildcardPoisonSnapshotShape16873(t *testing.T) {
	book := &config.AddressBook{Addresses: map[string]*config.Address{
		"dns-clients": {Name: "dns-clients", DNSName: "clients.example.net"},
	}}
	s := nat64TwoSnap16873(t, &config.NAT64RuleSet{
		Name: "a", SourceAddresses: []string{"any"}, SourceAddressNames: []string{"dns-clients"},
	}, book)
	if !neverMatch15930(s) {
		t.Fatalf("wildcard+poisoned name must lower to never-match, got constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
	// Control: wildcard + valid name lowers to match-any.
	book2 := &config.AddressBook{Addresses: map[string]*config.Address{
		"clients-v6": {Name: "clients-v6", Value: "2001:db8:1::/48"},
	}}
	s = nat64TwoSnap16873(t, &config.NAT64RuleSet{
		Name: "a", SourceAddresses: []string{"any"}, SourceAddressNames: []string{"clients-v6"},
	}, book2)
	if !matchAny15930(s) {
		t.Fatalf("wildcard+valid name must lower to match-any, got constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
}

func TestNAT64NestedEmptySetSnapshotShape16873(t *testing.T) {
	book := &config.AddressBook{
		Addresses: map[string]*config.Address{
			"wide": {Name: "wide", Value: "2001:db8::/48"},
		},
		AddressSets: map[string]*config.AddressSet{
			"empty":   {Name: "empty"},
			"parents": {Name: "parents", Addresses: []string{"wide"}, AddressSets: []string{"empty"}},
		},
	}
	s := nat64TwoSnap16873(t, &config.NAT64RuleSet{
		Name: "a", SourceAddressNames: []string{"parents"},
	}, book)
	if !neverMatch15930(s) {
		t.Fatalf("empty nested set must poison the closure to never-match, got constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
	// Control: without the empty member the wide prefix ships.
	book.AddressSets["parents"] = &config.AddressSet{Name: "parents", Addresses: []string{"wide"}}
	s = nat64TwoSnap16873(t, &config.NAT64RuleSet{
		Name: "a", SourceAddressNames: []string{"parents"},
	}, book)
	if !s.SourceConstrained || len(s.SourceAddresses) != 1 || s.SourceAddresses[0] != "2001:db8::/48" {
		t.Fatalf("control closure must ship 2001:db8::/48, got constrained=%v addrs=%v", s.SourceConstrained, s.SourceAddresses)
	}
}
