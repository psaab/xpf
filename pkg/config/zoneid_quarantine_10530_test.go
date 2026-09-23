package config

import "testing"

func TestSurvivorZoneNamesQuarantineCollision10530(t *testing.T) {
	if StableZoneID("z174") != StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg := &Config{Security: SecurityConfig{Zones: map[string]*ZoneConfig{
		"trust": {Name: "trust"},
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
	}}}
	zoneIDs := map[string]uint16{
		"trust": StableZoneID("trust"),
		"z174":  StableZoneID("z174"),
		"z214":  StableZoneID("z214"),
	}
	for i := range 100 {
		got := SurvivorZoneNames(zoneIDs, cfg)
		if got[zoneIDs["z174"]] != "z174" {
			t.Fatalf("iteration %d survivor reverse map = %v, want collision owner z174", i, got)
		}
	}
}

func TestSurvivorZoneNamesNilConfigCollisionDeterministic10530(t *testing.T) {
	zoneIDs := map[string]uint16{
		"z174": StableZoneID("z174"),
		"z214": StableZoneID("z214"),
	}
	for i := range 100 {
		got := SurvivorZoneNames(zoneIDs, nil)
		if got[zoneIDs["z174"]] != "z174" {
			t.Fatalf("iteration %d nil-config reverse map = %v, want sorted survivor z174", i, got)
		}
	}
}

func TestSurvivorZoneNamesOrdinaryZonesUnchanged10530(t *testing.T) {
	cfg := &Config{Security: SecurityConfig{Zones: map[string]*ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}}}
	zoneIDs := map[string]uint16{
		"trust":   StableZoneID("trust"),
		"untrust": StableZoneID("untrust"),
	}
	got := SurvivorZoneNames(zoneIDs, cfg)
	for name, id := range zoneIDs {
		if got[id] != name {
			t.Fatalf("ordinary reverse map[%d] = %q, want %q", id, got[id], name)
		}
	}
}
