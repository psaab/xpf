package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15673: range/wildcard/dns address-book entries must publish ALL their
// usable prefixes in the wire book row, not just the first.

func TestAddressFormsPublishAllPrefixes15673(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"rng":    {Name: "rng", ExpandedPrefixes: []string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"}},
			"dnsent": {Name: "dnsent", DNSName: "api.example.com", DNSAddresses: []string{"203.0.113.10/32", "2001:db8::10/128"}},
		},
		AddressSets: map[string]*config.AddressSet{},
	}
	books, nameToID, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = nameToID
	var rngRow *AddressBookSnapshot
	for i := range books {
		if books[i].Name == "rng" {
			rngRow = &books[i]
		}
	}
	// Names sharing content buckets may merge; fall back to prefix search.
	if rngRow == nil {
		for i := range books {
			if len(books[i].PrefixesV4) == 3 {
				rngRow = &books[i]
			}
		}
	}
	if rngRow == nil || len(rngRow.PrefixesV4) != 3 {
		t.Fatalf("range entry must publish 3 prefixes, got %+v", books)
	}
	foundV4, foundV6 := false, false
	for _, b := range books {
		for _, p := range b.PrefixesV4 {
			if p == "203.0.113.10/32" {
				foundV4 = true
			}
		}
		for _, p := range b.PrefixesV6 {
			if p == "2001:db8::10/128" {
				foundV6 = true
			}
		}
	}
	if !foundV4 || !foundV6 {
		t.Fatalf("dns entry prefixes not published: v4=%v v6=%v books=%+v", foundV4, foundV6, books)
	}
	// resolveUserspaceAddressBookEntry (capabilities path) returns all.
	vals, ok := resolveUserspaceAddressBookEntry(cfg, "rng")
	if !ok || len(vals) != 3 {
		t.Fatalf("resolve rng = %v ok=%v, want 3 prefixes", vals, ok)
	}
	// expandBookNameRecursive (NAT path) returns all.
	natVals, unknown := expandBookNameRecursive(cfg.Security.AddressBook, nil, nil, "dnsent", map[string]bool{}, 0)
	if unknown || len(natVals) != 2 {
		t.Fatalf("NAT expand dnsent = %v unknown=%v, want 2", natVals, unknown)
	}
}
