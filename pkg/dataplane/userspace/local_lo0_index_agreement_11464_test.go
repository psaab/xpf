package userspace

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestUnresolvedLo0AddressesAreNotShimLocal11464(t *testing.T) {
	addresses := []InterfaceAddressSnapshot{
		{Family: "inet", Address: "10.255.0.1/32"},
		{Family: "inet6", Address: "2001:db8::1/128"},
	}
	snapshot := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{{
		Name:      "lo0.0",
		LinuxName: "lo0",
		Ifindex:   0,
		Addresses: addresses,
	}}}
	if got := buildLocalAddressEntries(snapshot); len(got) != 0 {
		t.Fatalf("unresolved lo0 addresses must not be classified local by the shim, got %#v", got)
	}

	// A real device named lo0 (including an actual tunnel netdev) has a
	// positive ifindex and retains its local-address entries.
	snapshot.Interfaces[0].Ifindex = 17
	got := buildLocalAddressEntries(snapshot)
	seen := make(map[string]bool, len(got))
	for _, entry := range got {
		if entry.v4 {
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], entry.v4Key)
			seen[net.IP(bytes[:]).String()] = true
			continue
		}
		seen[net.IP(entry.v6Key.Addr[:]).String()] = true
	}
	for _, want := range []string{"10.255.0.1", "2001:db8::1"} {
		if !seen[want] {
			t.Errorf("resolved lo0 address %s must remain shim-local, got %v", want, seen)
		}
	}
}
