package config

import (
	"net/netip"
	"testing"
)

// #14728: ConfiguredIPv4Prefixes collects static v4 interface prefixes
// (sorted/deduped, v6 filtered, bare addr -> /32, bad skipped).
func TestConfiguredIPv4Prefixes14728(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {Units: map[int]*InterfaceUnit{
					0: {Addresses: []string{"10.0.1.1/24", "2606:4700:1111::1/64", "192.0.2.1"}},
				}},
				"ge-0/0/1": {Units: map[int]*InterfaceUnit{
					0: {Addresses: []string{"10.0.1.99/24", "not-a-prefix"}},
				}},
			},
		},
	}
	got := ConfiguredIPv4Prefixes(cfg)
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("192.0.2.1/32"),
	}
	if len(got) != len(want) {
		t.Fatalf("ConfiguredIPv4Prefixes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ConfiguredIPv4Prefixes = %v, want %v", got, want)
		}
	}
	if ConfiguredIPv4Prefixes(nil) != nil {
		t.Fatal("nil config must yield nil")
	}
	// Deterministic across rebuilds (#14153 discipline).
	for i := range 10 {
		again := ConfiguredIPv4Prefixes(cfg)
		if len(again) != len(got) || again[0] != got[0] || again[1] != got[1] {
			t.Fatalf("run %d: %v, want deterministic %v", i, again, got)
		}
	}
	// Overlap helper: masked either-contains.
	if !IPv4PrefixesOverlap(netip.MustParsePrefix("10.0.1.2/25"), netip.MustParsePrefix("10.0.1.0/24")) {
		t.Error("contained must overlap")
	}
	if IPv4PrefixesOverlap(netip.MustParsePrefix("10.0.2.0/24"), netip.MustParsePrefix("10.0.1.0/24")) {
		t.Error("disjoint must not overlap")
	}
	if IPv4PrefixesOverlap(netip.MustParsePrefix("2001:db8::/64"), netip.MustParsePrefix("10.0.1.0/24")) {
		t.Error("v6/v4 must not overlap")
	}
}
