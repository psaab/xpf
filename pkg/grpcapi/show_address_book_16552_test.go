package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16552: gRPC showAddressBook must render #15673 forms via the shared
// renderer, byte-equal to config.RenderAddressBook.

func TestShowAddressBookForms16552(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"h1":   {Name: "h1", Value: "10.0.0.1/32"},
			"rng":  {Name: "rng", RangeSpec: "192.0.2.1 to 192.0.2.3", ExpandedPrefixes: []string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"}},
			"wc":   {Name: "wc", WildcardSpec: "10.1.2.3/255.255.255.0", ExpandedPrefixes: []string{"10.1.2.0/24"}},
			"up":   {Name: "up", DNSName: "up.example.com", DNSFamily: "ipv4-only", DNSAddresses: []string{"198.51.100.10/32"}},
			"down": {Name: "down", DNSName: "down.example.com"},
			"bad":  nil,
		},
		AddressSets: map[string]*config.AddressSet{
			"s1": {Name: "s1", Addresses: []string{"up", "down"}},
		},
	}
	var buf strings.Builder
	(&Server{}).showAddressBook(cfg, &buf)
	out := buf.String()
	for _, want := range []string{
		"10.0.0.1/32",
		"range-address 192.0.2.1 to 192.0.2.3", "192.0.2.3/32",
		"wildcard-address 10.1.2.3/255.255.255.0", "10.1.2.0/24",
		"dns-name up.example.com", "198.51.100.10/32",
		"dns-name down.example.com", "unresolved", "matches nothing",
		"members: up, down",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gRPC address-book missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "bad") {
		t.Errorf("nil slot rendered:\n%s", out)
	}
	var sb strings.Builder
	config.RenderAddressBook(&sb, cfg.Security.AddressBook)
	if sb.String() != out {
		t.Errorf("gRPC not byte-equal to shared renderer:\n%s\n---\n%s", out, sb.String())
	}
}
