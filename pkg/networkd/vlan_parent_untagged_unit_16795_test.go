package networkd

import (
	"strings"
	"testing"
)

// #16795: the rendered half of the untagged-unit-on-tagged-parent fix.
// pkg/dataplane now puts the untagged unit's real address into
// VLANParentAddresses on a non-RETH parent (and sets KeepAddresses); this
// cell pins that the production generateNetwork renders it as an Address=
// line together with KeepConfiguration=static, so the address survives
// systemd-networkd's reload + reconfigure instead of being stripped as
// foreign.
//
// FAIL-ON-REVERT: drop the VLANParentAddresses render block (or the
// dataplane producer) and the Address=/KeepConfiguration assertions go RED.
func TestGenerateNetwork_VLANParentUntaggedUnitAddress_16795(t *testing.T) {
	m := New()
	got := m.generateNetwork(InterfaceConfig{
		Name:                "ge-0-0-1",
		IsVLANParent:        true,
		Addresses:           []string{"10.0.50.1/24"}, // tagged unit's: must stay ignored
		VLANParentAddresses: []string{"10.0.0.1/24"},
		KeepAddresses:       true,
	})
	if !strings.Contains(got, "Address=10.0.0.1/24\n") {
		t.Errorf("VLAN parent dropped its untagged unit's address 10.0.0.1/24:\n%s", got)
	}
	if !strings.Contains(got, "KeepConfiguration=static\n") {
		t.Errorf("VLAN parent carrying an untagged unit's address lacks KeepConfiguration=static:\n%s", got)
	}
	if strings.Contains(got, "10.0.50.1") {
		t.Errorf("VLAN parent rendered a tagged unit's address it must ignore:\n%s", got)
	}

	// Control: a tagged-only parent renders exactly as before — no address,
	// no keep.
	got = m.generateNetwork(InterfaceConfig{Name: "ge-0-0-2", IsVLANParent: true})
	if strings.Contains(got, "Address=") || strings.Contains(got, "KeepConfiguration=") {
		t.Errorf("tagged-only VLAN parent changed; want no Address=/KeepConfiguration:\n%s", got)
	}
}
