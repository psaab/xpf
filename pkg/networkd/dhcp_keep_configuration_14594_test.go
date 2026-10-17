package networkd

import (
	"strings"
	"testing"
)

// #14594: daemon DHCP lease addresses are foreign to systemd-networkd
// (pkg/dhcp applyAddress uses AddrReplace with no lifetimes and no
// Address= in the generated .network). Before the fix, a DHCP row carried
// no keep directive, so an ordinary `networkctl reconfigure` of every
// managed interface stripped the lease until at least T1.
//
// FAIL-ON-REVERT: revert generateNetwork to emit KeepConfiguration only
// for KeepAddresses (RETH/VRRP) and these cells go RED for DHCPv4,
// stateful/address-bearing DHCPv6, and mixed DHCP+static rows. The
// stateless / PD-only / static-only controls must stay without a keep
// directive: they own no address on this interface, so widening keep to
// them would preserve unrelated foreign addresses for no reason.
func TestGenerateNetwork_DHCPLeaseKeepConfiguration14594(t *testing.T) {
	m := New()
	cases := []struct {
		name string
		ifc  InterfaceConfig
		want string
	}{
		{
			name: "DHCPv4 only",
			ifc:  InterfaceConfig{Name: "wan0", DHCPv4: true},
			want: "KeepConfiguration=dhcp\n",
		},
		{
			name: "DHCPv6 stateful default",
			ifc:  InterfaceConfig{Name: "wan0", DHCPv6: true},
			want: "KeepConfiguration=dhcp\n",
		},
		{
			name: "DHCPv6 with IA-NA",
			ifc: InterfaceConfig{Name: "wan0", DHCPv6: true,
				DHCPv6IATypes: []string{"ia-na"}},
			want: "KeepConfiguration=dhcp\n",
		},
		{
			name: "DHCPv6 with IA-NA and IA-PD",
			ifc: InterfaceConfig{Name: "wan0", DHCPv6: true,
				DHCPv6IATypes: []string{"ia-na", "ia-pd"}},
			want: "KeepConfiguration=dhcp\n",
		},
		{
			name: "dual DHCP",
			ifc:  InterfaceConfig{Name: "wan0", DHCPv4: true, DHCPv6: true},
			want: "KeepConfiguration=dhcp\n",
		},
		{
			name: "DHCPv4 plus static IPv6",
			// Static v6 renders but KeepAddresses is false: the file
			// configures it, so only the dynamic class is foreign.
			ifc: InterfaceConfig{Name: "wan0", DHCPv4: true,
				Addresses: []string{"2001:db8:2::10/64"}},
			want: "KeepConfiguration=dhcp\n",
		},
		{
			name: "DHCPv6 plus static IPv4",
			ifc: InterfaceConfig{Name: "wan0", DHCPv6: true,
				Addresses: []string{"192.0.2.10/24"}},
			want: "KeepConfiguration=dhcp\n",
		},
		{
			name: "DHCPv6 stateless owns no address",
			ifc: InterfaceConfig{Name: "wan0", DHCPv6: true,
				DHCPv6Stateless: true},
			want: "",
		},
		{
			name: "DHCPv6 PD-only owns no address on this interface",
			ifc: InterfaceConfig{Name: "wan0", DHCPv6: true,
				DHCPv6IATypes: []string{"ia-pd"}},
			want: "",
		},
		{
			name: "static only",
			ifc: InterfaceConfig{Name: "wan0",
				Addresses: []string{"192.0.2.10/24"}},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.generateNetwork(tc.ifc)
			// Exactly zero or one KeepConfiguration line, with the
			// exact value the contract requires.
			count := strings.Count(got, "KeepConfiguration=")
			if tc.want == "" {
				if count != 0 {
					t.Errorf("generated .network carries a keep directive, want none:\n%s", got)
				}
				return
			}
			if count != 1 {
				t.Errorf("generated .network has %d KeepConfiguration lines, want exactly 1 (%q):\n%s", count, tc.want, got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("generated .network missing %q:\n%s", tc.want, got)
			}
		})
	}
}

// #14594: KeepAddresses (VRRP VIP preservation) must compose with the
// DHCP lease keep. A RETH that is also a DHCP client owns both foreign
// address classes; neither keep may drop the other.
func TestGenerateNetwork_KeepAddressesWithDHCP14594(t *testing.T) {
	m := New()
	cases := []struct {
		name string
		ifc  InterfaceConfig
		want string
	}{
		{
			name: "RETH static plus DHCPv6",
			// v4 link-local base renders (DHCPv6 does not suppress it)
			// and the v6 lease is dynamic: both classes -> yes.
			ifc: InterfaceConfig{Name: "ge-0-0-0", KeepAddresses: true, DHCPv6: true,
				Addresses: []string{"169.254.1.1/32"}},
			want: "KeepConfiguration=yes\n",
		},
		{
			name: "RETH static only unchanged",
			ifc: InterfaceConfig{Name: "ge-0-0-0", KeepAddresses: true,
				Addresses: []string{"169.254.1.1/32"}},
			want: "KeepConfiguration=static\n",
		},
		{
			name: "RETH DHCP only",
			ifc:  InterfaceConfig{Name: "ge-0-0-0", KeepAddresses: true, DHCPv4: true},
			// KeepAddresses without any surviving static Address= owns
			// no static address (the RETH link-local is DHCP-
			// suppressed); only the dynamic class needs keeping.
			want: "KeepConfiguration=dhcp\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.generateNetwork(tc.ifc)
			if strings.Count(got, "KeepConfiguration=") != 1 {
				t.Errorf("generated .network must carry exactly one KeepConfiguration line:\n%s", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("generated .network missing %q:\n%s", tc.want, got)
			}
		})
	}
}
