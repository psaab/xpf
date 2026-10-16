package config

import "testing"

// #14302: a DOTTED lifeline that is itself a DECLARED interface
// (control-interface hb.1, interface hb.1 declared) owns its declared
// units: hb.1.<unit> are units OF the lifeline interface, not units of
// a shorter parent hb. #14192 registered every declared unit false and
// only re-marked the base key, so the only declared unit of hb.1 (7)
// read false and the userspace ingress helper — which enumerates only
// declared-unit spellings — lost the control link's netdev (hb.1.7).
//
// Preserved invariants:
//   - #14192: a BARE lifeline parent (control-interface ge-0/0/0) still
//     does NOT cover its declared transit VLAN unit (ge-0/0/0.100).
//   - #13137: a role rooted only at a non-zero unit of a declared bare
//     parent (fabric-interface ge-0/0/0.100) still does NOT exempt the
//     bare parent or its unit 0.
//   - #12848: dotted siblings (hb.2) of a declared dotted lifeline stay
//     ordinary, and the bare prefix (hb) is not promoted.
//
// FAIL-ON-REVERT: dropping the declared-dotted re-mark makes the
// hb.1.7 / hb.1.3 true-assertions below go RED (exact key false).
func TestLifelineDottedDeclaredUnit14302(t *testing.T) {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "hb.1"}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"hb.1": {Name: "hb.1", Units: map[int]*InterfaceUnit{7: {Number: 7}}},
		"hb.2": {Name: "hb.2", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	set := HostInboundLifelineSet(cfg)
	for _, name := range []string{"hb.1", "hb.1.0", "hb.1.7"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (dotted lifeline and its declared unit)", name)
		}
	}
	for _, name := range []string{"hb", "hb.0", "hb.2", "hb.2.0"} {
		if HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (prefix/sibling stays ordinary)", name)
		}
	}
}

// The dotted lifeline owns EVERY declared unit, including a VLAN-tagged
// one: hb.1.3 is the lifeline's own netdev, not a transit VLAN riding a
// bare lifeline parent (#14192's demotion targets the bare-parent case).
func TestLifelineDottedDeclaredVLANUnit14302(t *testing.T) {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "hb.1"}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"hb.1": {Name: "hb.1", Units: map[int]*InterfaceUnit{3: {Number: 3, VlanID: 3}}},
	}
	set := HostInboundLifelineSet(cfg)
	if !HostInboundLifelineInterface("hb.1.3", set) {
		t.Errorf("HostInboundLifelineInterface(%q) = false, want true (declared dotted lifeline owns its VLAN unit)", "hb.1.3")
	}
}

// Controls: the #14192 bare-parent transit unit and the #13137
// non-zero-unit-of-bare-parent parent stay ordinary under the same set
// construction the dotted cases use.
func TestLifelineDottedUnitControls14302(t *testing.T) {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{
		ControlInterface: "ge-0/0/0",
		FabricInterface:  "ge-0/0/1.100",
	}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 100: {Number: 100, VlanID: 100}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {Number: 0}, 100: {Number: 100, VlanID: 100}}},
	}
	set := HostInboundLifelineSet(cfg)
	for _, name := range []string{"ge-0/0/0", "ge-0/0/0.0", "ge-0/0/1.100"} {
		if !HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = false, want true (designated lifeline)", name)
		}
	}
	for _, name := range []string{"ge-0/0/0.100", "ge-0/0/1", "ge-0/0/1.0"} {
		if HostInboundLifelineInterface(name, set) {
			t.Errorf("HostInboundLifelineInterface(%q) = true, want false (bare-parent transit unit / non-zero-unit parent stays ordinary)", name)
		}
	}
}
