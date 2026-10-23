package cluster

import (
	"errors"
	"net"
	"testing"
)

// #15944 H23-02: the duplicate-identity watcher passed the authored
// Junos control-interface name ("ge-0/0/0.0") verbatim to
// net.InterfaceByName, which expects the kernel name ("ge-0-0-0"), so
// the lookup failed and the beacon silently never started on
// slashed/unit-suffixed control interfaces. The watcher now translates
// the authored ref to the kernel device (unit suffix stripped to the
// physical parent, where the control address lives) before lookup.
//
// FAIL-ON-REVERT: passing the authored name through makes the stub
// record "ge-0/0/0.0", the lookup miss, and the broadcast derivation
// fail below.

func TestDuplicateIdentityBroadcastAddrResolvesKernelName15944(t *testing.T) {
	var seen []string
	prev := duplicateIdentityInterfaceByName
	t.Cleanup(func() { duplicateIdentityInterfaceByName = prev })
	duplicateIdentityInterfaceByName = func(kernelName string) ([]net.Addr, error) {
		seen = append(seen, kernelName)
		if kernelName != "ge-0-0-0" {
			return nil, errors.New("no such device")
		}
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}}, nil
	}

	for _, authored := range []string{"ge-0/0/0.0", "ge-0/0/0", "ge-0-0-0"} {
		seen = nil
		bcast, err := duplicateIdentityBroadcastAddr(authored, net.ParseIP("10.0.0.1"))
		if err != nil {
			t.Fatalf("authored %q: %v", authored, err)
		}
		if bcast == nil || bcast.IP.String() != "10.0.0.255" {
			t.Fatalf("authored %q: broadcast = %v, want 10.0.0.255", authored, bcast)
		}
		if len(seen) != 1 || seen[0] != "ge-0-0-0" {
			t.Fatalf("authored %q: kernel lookups = %v, want [ge-0-0-0]", authored, seen)
		}
	}

	// Unit-suffixed VLAN spelling: the control address lives on the
	// parent device, so the unit netdev suffix is stripped.
	if got := duplicateIdentityKernelName("ge-0/0/1.100"); got != "ge-0-0-1" {
		t.Fatalf("duplicateIdentityKernelName(ge-0/0/1.100) = %q, want ge-0-0-1", got)
	}
	// Non-numeric dotted names are not unit refs and pass through.
	if got := duplicateIdentityKernelName("vrf-mgmt"); got != "vrf-mgmt" {
		t.Fatalf("duplicateIdentityKernelName(vrf-mgmt) = %q, want vrf-mgmt", got)
	}
}
