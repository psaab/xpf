package config

import "testing"

func TestSurvivorZoneNamesQuarantineCollision10530(t *testing.T) {
	if StableZoneID("zzq17760") != StableZoneID("zzq8100") {
		t.Fatal("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := &Config{Security: SecurityConfig{Zones: map[string]*ZoneConfig{
		"trust":    {Name: "trust"},
		"zzq17760": {Name: "zzq17760"},
		"zzq8100":  {Name: "zzq8100"},
	}}}
	zoneIDs := map[string]uint32{
		"trust":    StableZoneID("trust"),
		"zzq17760": StableZoneID("zzq17760"),
		"zzq8100":  StableZoneID("zzq8100"),
	}
	for i := range 100 {
		got := SurvivorZoneNames(zoneIDs, cfg)
		if got[zoneIDs["zzq17760"]] != "zzq17760" {
			t.Fatalf("iteration %d survivor reverse map = %v, want collision owner zzq17760", i, got)
		}
	}
}

func TestSurvivorZoneNamesNilConfigCollisionDeterministic10530(t *testing.T) {
	zoneIDs := map[string]uint32{
		"zzq17760": StableZoneID("zzq17760"),
		"zzq8100":  StableZoneID("zzq8100"),
	}
	for i := range 100 {
		got := SurvivorZoneNames(zoneIDs, nil)
		if got[zoneIDs["zzq17760"]] != "zzq17760" {
			t.Fatalf("iteration %d nil-config reverse map = %v, want sorted survivor zzq17760", i, got)
		}
	}
}

func TestSurvivorZoneNamesOrdinaryZonesUnchanged10530(t *testing.T) {
	cfg := &Config{Security: SecurityConfig{Zones: map[string]*ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}}}
	zoneIDs := map[string]uint32{
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
