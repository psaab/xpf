package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7153: an UNTAGGED unit N > 0 never resolved. The map keyed it under its unit
// NUMBER while every session row for it carries wire VID 0, so
// sessionFilter.resolveIngressIfaces missed and fell back to every interface
// bound to the ifindex — silently widening a filter the operator wrote to be
// exact.
//
// The table is the four config shapes from the issue, and the third row is the
// defect. The first two are the controls that stop the fix being "return 0
// always": an explicit vlan-id must still key on it, which is what the real
// cluster config (docs/ha-cluster-userspace.conf) uses.
func TestUntaggedUnitResolvesOnWireVID_7153(t *testing.T) {
	for _, tc := range []struct {
		name    string
		unit    *config.InterfaceUnit
		wantVID uint16
	}{
		{"explicit vlan-id keys on it", &config.InterfaceUnit{Number: 50, VlanID: 50}, 50},
		{"vlan-id differs from number", &config.InterfaceUnit{Number: 80, VlanID: 50}, 50},
		{"UNTAGGED unit N>0 keys on 0", &config.InterfaceUnit{Number: 3}, 0},
		{"unit 0", &config.InterfaceUnit{Number: 0}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// #16065: the VID rule is config.SessionIfaceNames' key
			// derivation (uint16(unit.VlanID), never the number); the
			// old sessionDisplayVLANID helper is gone. Exercise it
			// through the map: a lone unit on device ge-0-0-0 (42).
			cfg := &config.Config{
				Interfaces: config.InterfacesConfig{
					Interfaces: map[string]*config.InterfaceConfig{
						"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
							tc.unit.Number: tc.unit,
						}},
					},
				},
			}
			m := buildSessionEgressIfacesWithLookup(cfg, func(string) (int, error) { return 42, nil })
			for key := range m {
				if key.VlanID != tc.wantVID {
					t.Errorf("unit %+v keyed at VID %d, want %d (wire VID only, never the unit number)", tc.unit, key.VlanID, tc.wantVID)
				}
			}
		})
	}
}

// End to end through the map builder, which is where the miss actually bit.
// #16065: an untagged unit N>0 resolves to its OWN device. ResolveKernelIfName
// names it "ge-0-0-0.3" (base + "." + number for a non-zero unit with no
// vlan-id — a device nothing creates on a plain NIC, but the resolver's
// contract), so the injected lookup keys it at its own ifindex 44, NOT
// the parent's 42. A session row for the unit carries that device's
// ifindex with VID 0.
func TestUntaggedUnitIsReachableInTheEgressMap_7153(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					3: {Number: 3}, // no vlan-id -> untagged
				}},
			},
		},
	}
	m := buildSessionEgressIfacesWithLookup(cfg, func(name string) (int, error) {
		switch name {
		case "ge-0-0-0.3":
			return 44, nil
		default:
			t.Fatalf("unexpected lookup %q (want the unit's own device)", name)
			return 0, nil
		}
	})

	// The key a session row for this unit actually carries: its own
	// device ifindex, wire VID 0.
	if got, ok := m[sessionIfaceKey{Ifindex: 44, VlanID: 0}]; !ok || got != "ge-0/0/0.3" {
		t.Errorf("the WIRE key {44,0} does not resolve (got %q, ok=%v). Session rows for an "+
			"untagged unit carry VID 0 on the unit's own device, so this is the only key "+
			"that can match one; before #7153 the unit was filed under its number as a "+
			"VID and resolveIngressIfaces fell back to every interface on the ifindex", got, ok)
	}
	// And the old keys must be gone, or the map merely gained an entry and the
	// stale one still shadows a real unit 3 elsewhere.
	if got, ok := m[sessionIfaceKey{Ifindex: 44, VlanID: 3}]; ok {
		t.Errorf("the unit is STILL filed under its number as {44,3} -> %q; the number is not "+
			"a wire VID and nothing keys there", got)
	}
	if got, ok := m[sessionIfaceKey{Ifindex: 42, VlanID: 0}]; ok {
		t.Errorf("the unit is STILL filed under the PARENT ifindex as {42,0} -> %q; "+
			"#16065 keys it on its own device (44)", got)
	}
}

// #16065 (was #7153's lowest-unit rule): two units with no vlan-id on one
// interface are no longer resolved by picking the lowest. Each keys on
// its OWN device (unit 0 -> the parent device, unit 3 -> "ge-0-0-0.3"),
// so there is no collision to arbitrate; on a device they genuinely
// SHARE (the WireGuard TUN) the shared key is refused instead — see
// pkg/config's TestSessionIfaceNamesWireGuardSharedDeviceRefused16065.
func TestUntaggedCollisionResolvesToLowestUnit_7153(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0},
					3: {Number: 3},
				}},
			},
		},
	}
	for i := range 8 {
		m := buildSessionEgressIfacesWithLookup(cfg, func(name string) (int, error) {
			switch name {
			case "ge-0-0-0":
				return 42, nil
			case "ge-0-0-0.3":
				return 44, nil
			}
			return 42, nil
		})
		if got := m[sessionIfaceKey{Ifindex: 42, VlanID: 0}]; got != "ge-0/0/0" {
			t.Fatalf("iteration %d: {42,0} = %q, want \"ge-0/0/0\" (unit 0 on its own device)", i, got)
		}
		if got := m[sessionIfaceKey{Ifindex: 44, VlanID: 0}]; got != "ge-0/0/0.3" {
			t.Fatalf("iteration %d: {44,0} = %q, want \"ge-0/0/0.3\" (unit 3 on its own device, "+
				"not collapsed onto the parent or dropped as a collision)", i, got)
		}
	}
}
