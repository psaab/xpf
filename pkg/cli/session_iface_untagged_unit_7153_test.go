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
// #16065 dual keying: an untagged unit 3 registers {parent 42, VID 0}
// (the AF_XDP ingress stamp — untagged frames arrive on the parent)
// AND {own device 44, VID 0} ("ge-0-0-0.3"). The number is never a VID.
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
		case "ge-0-0-0":
			return 42, nil
		case "ge-0-0-0.3":
			return 44, nil
		default:
			t.Fatalf("unexpected lookup %q", name)
			return 0, nil
		}
	})

	if got, ok := m[sessionIfaceKey{Ifindex: 42, VlanID: 0}]; !ok || got != "ge-0/0/0.3" {
		t.Errorf("the ingress WIRE key {42,0} (parent stamp) does not resolve (got %q, ok=%v)", got, ok)
	}
	if got, ok := m[sessionIfaceKey{Ifindex: 44, VlanID: 0}]; !ok || got != "ge-0/0/0.3" {
		t.Errorf("the own-device key {44,0} does not resolve (got %q, ok=%v)", got, ok)
	}
	if got, ok := m[sessionIfaceKey{Ifindex: 44, VlanID: 3}]; ok {
		t.Errorf("the unit is STILL filed under its number as {44,3} -> %q; the number is not "+
			"a wire VID and nothing keys there", got)
	}
	if got, ok := m[sessionIfaceKey{Ifindex: 42, VlanID: 3}]; ok {
		t.Errorf("the unit is STILL filed under its number as {42,3} -> %q", got)
	}
}

// Two untagged units of one interface share the PARENT stamp {42,0}:
// that key is REFUSED (ambiguous), while each unit's own-device key
// still resolves. This is the narrowed replacement for #7153's
// lowest-unit winner.
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
	lookup := func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 42, nil
		case "ge-0-0-0.3":
			return 44, nil
		}
		return 42, nil
	}
	for range 8 {
		table := buildSessionTableWithLookup(cfg, lookup)
		if _, ok := table.Names[sessionIfaceKey{Ifindex: 42, VlanID: 0}]; ok {
			t.Fatalf("shared parent key {42,0} named %q — untagged units 0/3 share the parent stamp and must refuse it", table.Names[sessionIfaceKey{Ifindex: 42, VlanID: 0}])
		}
		if !table.IsAmbiguous(sessionIfaceKey{Ifindex: 42, VlanID: 0}) {
			t.Fatal("{42,0} must be recorded ambiguous (units 0 and 3 both claim the parent stamp)")
		}
		if got := table.Names[sessionIfaceKey{Ifindex: 44, VlanID: 0}]; got != "ge-0/0/0.3" {
			t.Fatalf("{44,0} = %q, want ge-0/0/0.3 (unit 3 on its own device)", got)
		}
	}
}
