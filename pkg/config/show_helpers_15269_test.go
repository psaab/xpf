package config

import "testing"

// #15269 C09-02/B18-05 helpers.

func TestSyslogZoneNamesSurvivor15269(t *testing.T) {
	if StableZoneID("z174") != StableZoneID("z214") {
		t.Fatal("premise: z174/z214 must collide")
	}
	cfg := &Config{}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"z174": {Name: "z174"}, "z214": {Name: "z214"},
	}
	got := SyslogZoneNames(cfg)
	id := StableZoneID("z174")
	if got[id] != "z174" {
		t.Errorf("SyslogZoneNames[%d]=%q, want z174 (survivor)", id, got[id])
	}
	if len(got) != 1 {
		t.Errorf("len=%d, want 1: %v", len(got), got)
	}
}

func TestTerseUnitDisabled15269(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*InterfaceUnit{
			50: {Number: 50, Disable: true, Addresses: []string{"10.0.50.1/24"}},
			51: {Number: 51, Addresses: []string{"10.0.51.1/24"}},
		}},
		"ge-0/0/5": {Name: "ge-0/0/5", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Disable: true, Addresses: []string{"10.0.5.1/24"}},
		}},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
	}
	if !TerseUnitDisabled(cfg, "reth0", 50) {
		t.Error("reth0.50 disabled not detected")
	}
	if TerseUnitDisabled(cfg, "reth0", 51) {
		t.Error("reth0.51 wrongly disabled")
	}
	if !TerseUnitDisabled(cfg, "ge-0/0/5", 0) {
		t.Error("ge-0/0/5.0 disabled not detected")
	}
	if TerseUnitDisabled(cfg, "ge-0/0/5", 99) {
		t.Error("missing unit wrongly disabled")
	}
	// Interface-level disable also disables.
	cfg.Interfaces.Interfaces["ge-0/0/5"].Disable = true
	cfg.Interfaces.Interfaces["ge-0/0/5"].Units[0].Disable = false
	if !TerseUnitDisabled(cfg, "ge-0/0/5", 0) {
		t.Error("interface-level disable not detected")
	}
}
