package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15934: VLAN-qualified zone refs ("ge-0/0/0.100:12") must resolve the
// unit-disable through hostInboundInterfaceAdminDisabled. Pre-fix the
// naive first-dot cut fed "100:12" to Atoi, which failed, so a disabled
// VLAN unit parsed as enabled.
func TestVlanQualifiedRefAdminDisabled15934(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name: "ge-0/0/0",
					Units: map[int]*config.InterfaceUnit{
						100: {Number: 100, VlanID: 100, Disable: true},
						101: {Number: 101, VlanID: 101},
					},
				},
			},
		},
	}
	if !hostInboundInterfaceAdminDisabled(cfg, "ge-0/0/0.100:12") {
		t.Errorf("VLAN-qualified disabled unit ref parsed as enabled (#15934)")
	}
	if hostInboundInterfaceAdminDisabled(cfg, "ge-0/0/0.101:12") {
		t.Errorf("VLAN-qualified enabled unit ref parsed as disabled (#15934)")
	}
	// Plain unit refs keep their pre-fix behaviour.
	if !hostInboundInterfaceAdminDisabled(cfg, "ge-0/0/0.100") {
		t.Errorf("plain disabled unit ref parsed as enabled")
	}
	if hostInboundInterfaceAdminDisabled(cfg, "ge-0/0/0.101") {
		t.Errorf("plain enabled unit ref parsed as disabled")
	}
	// Malformed suffixes stay enabled (inert), as before.
	if hostInboundInterfaceAdminDisabled(cfg, "ge-0/0/0.abc") {
		t.Errorf("malformed unit ref must stay enabled/inert")
	}
	// Signed / out-of-range VLAN qualifiers are NOT stripped: the ref
	// stays malformed and inert even against a disabled unit.
	for _, ref := range []string{"ge-0/0/0.100:-1", "ge-0/0/0.100:+12", "ge-0/0/0.100:4095", "ge-0/0/0.100:"} {
		if hostInboundInterfaceAdminDisabled(cfg, ref) {
			t.Errorf("malformed qualifier ref %q must stay enabled/inert", ref)
		}
	}
}
