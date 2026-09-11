package networkd

import (
	"strings"
	"testing"
)

// #9721: a VLAN parent renders the addresses it carries ITSELF
// (VLANParentAddresses) and still ignores Addresses, which belong to its
// sub-interfaces. TestGenerateNetwork_VLANParent pins the ignored half on its
// own; this cell pins both halves together, on the model the dataplane builds
// for a VRRP-backed RETH parent.
//
// FAIL-ON-REVERT: drop the VLANParentAddresses block in generateNetwork and the
// advert source disappears from the parent's .network; render Addresses for a
// VLAN parent and the unit address leaks onto it.
func TestGenerateNetwork_VLANParentOwnAddresses_9721(t *testing.T) {
	m := New()
	got := m.generateNetwork(InterfaceConfig{
		Name:                "ge-0-0-2",
		IsVLANParent:        true,
		Addresses:           []string{"172.16.50.8/24"}, // a unit's VIP: must stay ignored
		VLANParentAddresses: []string{"169.254.1.1/32"},
		KeepAddresses:       true,
	})
	if !strings.Contains(got, "Address=169.254.1.1/32\n") {
		t.Errorf("VLAN parent dropped its own address 169.254.1.1/32:\n%s", got)
	}
	if strings.Contains(got, "172.16.50.8") {
		t.Errorf("VLAN parent rendered a unit address it must ignore:\n%s", got)
	}
	for _, want := range []string{"DHCP=no\n", "RequiredForOnline=no\n", "KeepConfiguration=static\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("VLAN parent .network is missing %q:\n%s", want, got)
		}
	}
}

// The field is VLAN-parent only. A non-VLAN interface renders from Addresses,
// and a stray VLANParentAddresses must not add an address nobody asked for.
func TestGenerateNetwork_VLANParentAddressesIgnoredOffAVLANParent_9721(t *testing.T) {
	m := New()
	got := m.generateNetwork(InterfaceConfig{
		Name:                "ge-0-0-1",
		Addresses:           []string{"169.254.2.1/32"},
		VLANParentAddresses: []string{"169.254.9.9/32"},
	})
	if !strings.Contains(got, "Address=169.254.2.1/32\n") {
		t.Errorf("non-VLAN interface lost its address:\n%s", got)
	}
	if strings.Contains(got, "169.254.9.9") {
		t.Errorf("non-VLAN interface rendered VLANParentAddresses:\n%s", got)
	}
}
