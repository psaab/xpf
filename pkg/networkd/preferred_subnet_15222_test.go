// #15222 A37-03: the Junos `preferred` leaf must select the source address
// for locally originated traffic on its subnet. On Linux that is per-subnet
// first-in-list ordering, not PreferredLifetime=forever on a [Address]
// section (an IPv6 valid/preferred lifetime knob that does not choose the
// IPv4 source and does not order same-subnet IPv6 either).
//
// These tests pin the networkd render: within each subnet the preferred
// address is FIRST among that subnet's addresses, other subnets keep their
// relative order, and no address gains PreferredLifetime. Controls pin the
// neighbouring legitimate behaviour: primary-first is preserved, a lone
// address is untouched, and a preferred address suppressed by its family
// DHCP gate does not resurrect.
package networkd

import (
	"strings"
	"testing"
)

func renderAddrs15222(t *testing.T, ifc InterfaceConfig) []string {
	t.Helper()
	got := New().generateNetwork(ifc)
	var out []string
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "Address=") {
			out = append(out, strings.TrimPrefix(line, "Address="))
		}
		if strings.Contains(line, "PreferredLifetime") {
			t.Errorf("preferred must not emit PreferredLifetime (inert for source selection):\n%s", got)
		}
	}
	return out
}

func equalAddrs15222(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Same-subnet IPv4: peer subnet first in config, preferred is the second
// address of the 10.0.1.0/24 subnet. RED on master: order is config order
// (10.0.1.10 first) plus a PreferredLifetime section.
func TestPreferredFirstPerSubnet15222(t *testing.T) {
	got := renderAddrs15222(t, InterfaceConfig{
		Name: "trust0",
		Addresses: []string{
			"192.0.2.10/24",
			"10.0.1.10/24", "10.0.1.20/24",
		},
		PreferredAddress: "10.0.1.20/24",
	})
	want := []string{"192.0.2.10/24", "10.0.1.20/24", "10.0.1.10/24"}
	if !equalAddrs15222(got, want) {
		t.Errorf("preferred not first in its subnet:\n got %v\nwant %v", got, want)
	}
}

// Per-subnet, not global: a preferred in the second subnet must not jump
// ahead of the first subnet (that would change the other subnet's source).
func TestPreferredDoesNotCrossSubnet15222(t *testing.T) {
	got := renderAddrs15222(t, InterfaceConfig{
		Name: "trust0",
		Addresses: []string{
			"10.0.1.10/24", "10.0.1.20/24",
			"192.0.2.10/24", "192.0.2.20/24",
		},
		PreferredAddress: "192.0.2.20/24",
	})
	want := []string{"10.0.1.10/24", "10.0.1.20/24", "192.0.2.20/24", "192.0.2.10/24"}
	if !equalAddrs15222(got, want) {
		t.Errorf("preferred crossed subnet boundary:\n got %v\nwant %v", got, want)
	}
}

// Same-subnet IPv6 preferred also orders first in its subnet.
func TestPreferredIPv6FirstPerSubnet15222(t *testing.T) {
	got := renderAddrs15222(t, InterfaceConfig{
		Name: "trust0",
		Addresses: []string{
			"2001:db8:1::10/64", "2001:db8:1::20/64",
			"2001:db8:2::10/64",
		},
		PreferredAddress: "2001:db8:1::20/64",
	})
	want := []string{"2001:db8:1::20/64", "2001:db8:1::10/64", "2001:db8:2::10/64"}
	if !equalAddrs15222(got, want) {
		t.Errorf("IPv6 preferred not first in its subnet:\n got %v\nwant %v", got, want)
	}
}

// Two subnets sharing one network number are distinct kernel subnets:
// /25 halves must not be merged.
func TestPreferredRespectsPrefixBoundary15222(t *testing.T) {
	got := renderAddrs15222(t, InterfaceConfig{
		Name: "trust0",
		Addresses: []string{
			"10.0.1.10/25", "10.0.1.200/25", "10.0.1.20/25",
		},
		PreferredAddress: "10.0.1.20/25",
	})
	want := []string{"10.0.1.20/25", "10.0.1.10/25", "10.0.1.200/25"}
	if !equalAddrs15222(got, want) {
		t.Errorf("preferred ordering merged distinct /25 subnets:\n got %v\nwant %v", got, want)
	}
}

// Controls: no preferred keeps config order; primary still first overall;
// primary+same preferred stays first; preferred already first is a no-op.
func TestPreferredControls15222(t *testing.T) {
	cases := []struct {
		name string
		ifc  InterfaceConfig
		want []string
	}{
		{"no-preferred", InterfaceConfig{Name: "t", Addresses: []string{"10.0.1.10/24", "10.0.1.20/24"}},
			[]string{"10.0.1.10/24", "10.0.1.20/24"}},
		{"primary-only", InterfaceConfig{Name: "t", Addresses: []string{"10.0.1.10/24", "10.0.1.20/24"}, PrimaryAddress: "10.0.1.20/24"},
			[]string{"10.0.1.20/24", "10.0.1.10/24"}},
		{"primary-eq-preferred", InterfaceConfig{Name: "t", Addresses: []string{"10.0.1.10/24", "10.0.1.20/24"}, PrimaryAddress: "10.0.1.20/24", PreferredAddress: "10.0.1.20/24"},
			[]string{"10.0.1.20/24", "10.0.1.10/24"}},
		{"preferred-already-first", InterfaceConfig{Name: "t", Addresses: []string{"10.0.1.20/24", "10.0.1.10/24"}, PreferredAddress: "10.0.1.20/24"},
			[]string{"10.0.1.20/24", "10.0.1.10/24"}},
		{"preferred-absent", InterfaceConfig{Name: "t", Addresses: []string{"10.0.1.10/24"}, PreferredAddress: "10.0.1.99/24"},
			[]string{"10.0.1.10/24"}},
	}
	for _, tc := range cases {
		if got := renderAddrs15222(t, tc.ifc); !equalAddrs15222(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// Control: a preferred suppressed by its family DHCP gate stays suppressed.
func TestPreferredDHCPGateControl15222(t *testing.T) {
	got := renderAddrs15222(t, InterfaceConfig{
		Name:             "trust0",
		Addresses:        []string{"10.0.1.10/24", "10.0.1.20/24", "2001:db8::10/64"},
		PreferredAddress: "10.0.1.20/24",
		DHCPv4:           true,
	})
	want := []string{"2001:db8::10/64"}
	if !equalAddrs15222(got, want) {
		t.Errorf("DHCP-gated preferred resurrected: got %v want %v", got, want)
	}
}
