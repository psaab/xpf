package networkd

import (
	"strings"
	"testing"
)

// #10435: a VLAN child (e.g. ge-0-0-1.50) with a configured MTU gets only a
// .network file — no MAC-backed .link or .netdev to carry MTUBytes — so
// generateNetwork must emit MTUBytes in the [Link] section. Without it the
// subinterface stays at the kernel default 1500 while the configuration
// shows 9000.
//
// FAIL-ON-REVERT: drop the MTUBytes block in generateNetwork and this cell
// reddens.
func TestGenerateNetwork_VLANChildMTU_10435(t *testing.T) {
	m := New()
	got := m.generateNetwork(InterfaceConfig{
		Name:      "ge-0-0-1.50",
		Addresses: []string{"10.0.50.2/24"},
		MTU:       9000,
	})
	if !strings.Contains(got, "MTUBytes=9000\n") {
		t.Errorf("VLAN child .network omits MTUBytes=9000:\n%s", got)
	}
	link := strings.Index(got, "[Link]\n")
	mtu := strings.Index(got, "MTUBytes=9000\n")
	network := strings.Index(got, "[Network]\n")
	if link < 0 || mtu < 0 || network < 0 || !(link < mtu && mtu < network) {
		t.Errorf("MTUBytes=9000 is not inside the [Link] section:\n%s", got)
	}
}

// Unset-MTU control: a VLAN child with MTU 0 renders exactly as before — no
// MTUBytes line and no [Link] section at all.
func TestGenerateNetwork_VLANChildNoMTU_10435(t *testing.T) {
	m := New()
	got := m.generateNetwork(InterfaceConfig{
		Name:      "ge-0-0-1.50",
		Addresses: []string{"10.0.50.2/24"},
	})
	if strings.Contains(got, "MTUBytes") {
		t.Errorf("MTU=0 VLAN child must not emit MTUBytes:\n%s", got)
	}
	if strings.Contains(got, "[Link]") {
		t.Errorf("MTU=0 VLAN child must not gain a [Link] section:\n%s", got)
	}
}

// Non-VLAN controls: interfaces already covered by .link/.netdev output keep
// their MTU there — the .network stays unchanged.
func TestGenerateNetwork_NonVLANMTUStaysInLinkNetdev_10435(t *testing.T) {
	m := New()
	// Physical interface: MTU lives in .link.
	phys := InterfaceConfig{
		Name:       "ge-0-0-1",
		MACAddress: "52:54:00:aa:bb:cc",
		Addresses:  []string{"10.0.1.2/24"},
		MTU:        9000,
	}
	if got := m.generateNetwork(phys); strings.Contains(got, "MTUBytes") {
		t.Errorf("physical .network must not duplicate the .link MTU:\n%s", got)
	}
	if got := m.generateLink(phys); !strings.Contains(got, "MTUBytes=9000\n") {
		t.Errorf(".link lost the physical MTU:\n%s", got)
	}
	// Bond device: MTU lives in .netdev.
	bond := InterfaceConfig{
		Name:      "bond0",
		IsBond:    true,
		Addresses: []string{"10.0.2.2/24"},
		MTU:       9000,
	}
	if got := m.generateNetwork(bond); strings.Contains(got, "MTUBytes") {
		t.Errorf("bond .network must not duplicate the .netdev MTU:\n%s", got)
	}
	if got := m.generateNetdev(bond); !strings.Contains(got, "MTUBytes=9000\n") {
		t.Errorf(".netdev lost the bond MTU:\n%s", got)
	}
	// Bridge device: MTU lives in .netdev.
	bridge := InterfaceConfig{
		Name:      "br0",
		IsBridge:  true,
		Addresses: []string{"10.0.3.2/24"},
		MTU:       9000,
	}
	if got := m.generateNetwork(bridge); strings.Contains(got, "MTUBytes") {
		t.Errorf("bridge .network must not duplicate the .netdev MTU:\n%s", got)
	}
	// VLAN parent: MTU lives in .link; the parent .network keeps only its
	// RequiredForOnline arm.
	parent := InterfaceConfig{
		Name:         "ge-0-0-1",
		MACAddress:   "52:54:00:aa:bb:cc",
		IsVLANParent: true,
		MTU:          9000,
	}
	if got := m.generateNetwork(parent); strings.Contains(got, "MTUBytes") {
		t.Errorf("VLAN-parent .network must not duplicate the .link MTU:\n%s", got)
	}
	// MAC-less VLAN parent: the IsVLANParent guard alone must suppress the
	// duplicate (no MACAddress arm to mask a regression).
	macless := InterfaceConfig{
		Name:         "ge-0-0-2",
		IsVLANParent: true,
		MTU:          9000,
	}
	if got := m.generateNetwork(macless); strings.Contains(got, "MTUBytes") {
		t.Errorf("MAC-less VLAN-parent .network must not emit MTUBytes:\n%s", got)
	}
	// Unmanaged/disabled: the early-return path carries no MTU.
	down := InterfaceConfig{Name: "ge-0-0-9", Unmanaged: true, MTU: 9000}
	if got := m.generateNetwork(down); strings.Contains(got, "MTUBytes") {
		t.Errorf("unmanaged .network must not emit MTUBytes:\n%s", got)
	}
	down = InterfaceConfig{Name: "ge-0-0-10", Disable: true, MTU: 9000}
	if got := m.generateNetwork(down); strings.Contains(got, "MTUBytes") {
		t.Errorf("disabled .network must not emit MTUBytes:\n%s", got)
	}
}
