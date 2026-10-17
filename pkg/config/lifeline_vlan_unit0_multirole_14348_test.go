package config

import "testing"

// #14348 (D8-01): HostInboundLifelineSet clobbers configured lifeline
// roles on VLAN-tagged unit 0 and same-trunk multi-role configurations.
//
//   - A role spelled ge-0/0/0.0 whose unit 0 carries vlan-id 100 names
//     that tagged unit's own netdev (ge-0-0-0.100-style VLAN netdev), so
//     the explicit .0 lifeline must survive: the #14192 VLAN demotion in
//     markBaseLifeline must not overwrite the positive role entry with
//     false, and the bare parent — a different (physical) netdev — must
//     not be promoted either.
//   - The same tagged unit 0 under a BARE role (control-interface
//     ge-0/0/0) must NOT alias to ge-0/0/0.0: unit 0 is VLAN-tagged, so
//     it does not share the parent netdev. The bare parent stays the
//     lifeline; the tagged .0 stays ordinary (fail-closed, no fail-open
//     exemption of the transit/tagged netdev).
//   - Same-trunk multi-role: control-interface ge-0/0/0.0 plus
//     fabric-interface ge-0/0/0.100 on one trunk. The fabric role's
//     non-zero-unit demotion of the bare parent must not overwrite the
//     control role's positive entries, and the control role must not
//     strand the fabric unit.
//
// FAIL-ON-REVERT: restoring the unconditional set[name+".0"]=true alias,
// the markBaseLifeline VLAN overwrite, or the set[base]=false demotions
// makes the assertions below go RED.

func lifelineVlanUnit0Cfg14348(control, fabric string) *Config {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: control, FabricInterface: fabric}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0:   {Number: 0, VlanID: 100},
			100: {Number: 100, VlanID: 100},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0},
		}},
	}
	return cfg
}

func TestHostInboundLifelineSetVlanUnit0AndMultiRoleTrunk(t *testing.T) {
	t.Run("dotted unit0 role with VLAN-tagged unit 0", func(t *testing.T) {
		cfg := lifelineVlanUnit0Cfg14348("ge-0/0/0.0", "")
		set := HostInboundLifelineSet(cfg)
		// The explicitly configured lifeline unit itself stays exempt.
		if !HostInboundLifelineInterface("ge-0/0/0.0", set) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (explicit control-interface ge-0/0/0.0, VLAN-tagged unit 0)", "ge-0/0/0.0")
		}
		// The bare parent is a distinct physical netdev carrying other
		// units; a VLAN-tagged unit 0 does not share it, so the parent
		// must not be promoted by the .0 role.
		for _, name := range []string{"ge-0/0/0", "ge-0/0/0.100", "ge-0/0/1", "ge-0/0/1.0"} {
			if HostInboundLifelineInterface(name, set) {
				t.Errorf("HostInboundLifelineInterface(%q) = true, want false (not the designated lifeline)", name)
			}
		}
	})

	t.Run("bare role with VLAN-tagged unit 0", func(t *testing.T) {
		cfg := lifelineVlanUnit0Cfg14348("ge-0/0/0", "")
		set := HostInboundLifelineSet(cfg)
		// The bare parent itself is the designated lifeline.
		if !HostInboundLifelineInterface("ge-0/0/0", set) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (explicit control-interface ge-0/0/0)", "ge-0/0/0")
		}
		// Its VLAN-tagged unit 0 has a distinct netdev and must not
		// inherit the exemption (fail-closed).
		for _, name := range []string{"ge-0/0/0.0", "ge-0/0/0.100", "ge-0/0/1", "ge-0/0/1.0"} {
			if HostInboundLifelineInterface(name, set) {
				t.Errorf("HostInboundLifelineInterface(%q) = true, want false (VLAN-tagged unit / unrelated interface stays ordinary)", name)
			}
		}
	})

	t.Run("control unit0 plus fabric unit100 same trunk untagged unit0", func(t *testing.T) {
		cfg := &Config{}
		cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "ge-0/0/0.0", FabricInterface: "ge-0/0/0.100"}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
				0:   {Number: 0},
				100: {Number: 100, VlanID: 100},
			}},
		}
		set := HostInboundLifelineSet(cfg)
		// Both designated units and their shared untagged parent netdev
		// stay lifelines; the fabric role's parent demotion must not
		// clobber the control role's base entry.
		for _, name := range []string{"ge-0/0/0", "ge-0/0/0.0", "ge-0/0/0.100"} {
			if !HostInboundLifelineInterface(name, set) {
				t.Errorf("HostInboundLifelineInterface(%q) = false, want true (designated same-trunk lifeline)", name)
			}
		}
	})

	t.Run("control unit0 VLAN-tagged plus fabric unit100 same trunk", func(t *testing.T) {
		cfg := lifelineVlanUnit0Cfg14348("ge-0/0/0.0", "ge-0/0/0.100")
		set := HostInboundLifelineSet(cfg)
		// Both tagged units are designated lifelines on their own
		// netdevs; neither role may clobber the other, and the bare
		// parent stays ordinary.
		for _, name := range []string{"ge-0/0/0.0", "ge-0/0/0.100"} {
			if !HostInboundLifelineInterface(name, set) {
				t.Errorf("HostInboundLifelineInterface(%q) = false, want true (designated same-trunk lifeline)", name)
			}
		}
		if HostInboundLifelineInterface("ge-0/0/0", set) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (bare parent of VLAN-tagged units stays ordinary)", "ge-0/0/0")
		}
	})
}

// Fabric member links go through the base-lifeline walk too: a bare
// member designates the member interface itself, so it stays exempt
// even when its unit 0 is VLAN-tagged, and that tagged unit — the
// netdev actually carrying the fabric traffic — is exempt alongside
// it (mirroring a bare control/fabric role on a tagged unit 0).
func TestHostInboundLifelineFabricMemberVlanUnit014348(t *testing.T) {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"fab0": {Name: "fab0", FabricMembers: []string{"ge-0/0/2"}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{
			0: {Number: 0, VlanID: 200},
		}},
	}
	set := HostInboundLifelineSet(cfg)
	if !HostInboundLifelineInterface("fab0", set) || !HostInboundLifelineInterface("fab0.0", set) {
		t.Errorf("fabric aggregate fab0/fab0.0 not lifelines: %v", set)
	}
	for _, name := range []string{"ge-0/0/2", "ge-0/0/2.0"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (designated fabric member / its tagged unit 0)", name)
		}
	}
}
