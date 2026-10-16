package userspace

import (
	"testing"
)

// #13929: the same local address in two routing domains must produce two
// classifier entries, otherwise the address-only key admits foreign-domain
// local delivery on the default ingress.
func TestBuildLocalAddressEntriesRemainDistinctAcrossRoutingDomains13929(t *testing.T) {
	snapshot := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name:          "reth0.0",
				RoutingDomain: 100042,
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.0.1/24"},
					{Family: "inet6", Address: "2001:db8::1/64"},
				},
			},
			{
				Name: "reth1.0",
				Addresses: []InterfaceAddressSnapshot{
					{Family: "inet", Address: "10.0.0.1/24"},
					{Family: "inet6", Address: "2001:db8::1/64"},
				},
			},
		},
	}
	got := buildLocalAddressEntries(snapshot)
	if len(got) != 4 {
		t.Fatalf("len(local address entries) = %d, want 4 (same IPv4/IPv6 address in two routing domains)", len(got))
	}
}
