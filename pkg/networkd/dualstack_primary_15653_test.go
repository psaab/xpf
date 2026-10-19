package networkd

import "testing"

// #15653: dual-stack networkd render must order each family's primary
// first within its subnet. RED pre-fix: PrimaryAddressV6 did not exist
// and the single PrimaryAddress (IPv4) was moved globally first, leaving
// the IPv6 primary second in its subnet (IFA_F_SECONDARY on install).
func TestDualStackPrimaryOrdering15653(t *testing.T) {
	got := renderAddrs15222(t, InterfaceConfig{
		Name:             "ge-0-0-0",
		Addresses:        []string{"10.0.0.1/24", "10.0.0.2/24", "2001:db8::1/64", "2001:db8::2/64"},
		PrimaryAddress:   "10.0.0.2/24",
		PrimaryAddressV6: "2001:db8::2/64",
	})
	want := []string{"10.0.0.2/24", "10.0.0.1/24", "2001:db8::2/64", "2001:db8::1/64"}
	if !equalAddrs15222(got, want) {
		t.Errorf("dual-stack primaries not first per subnet:\n got %v\nwant %v", got, want)
	}
}
