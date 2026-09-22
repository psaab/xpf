package userspace

import "testing"

func TestZoneSetValidationMarkerRejectsQuarantineAndAcceptsCleanSet10510(t *testing.T) {
	cleanCfg := compileWithStubbedLinks6722(t, []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone lan interfaces reth1",
	}, map[string]int{"ge-0-0-1": 24}, map[string]string{
		"ge-0-0-1": "02:bf:72:01:00:01",
	}, true)
	clean, err := buildSnapshot(cleanCfg, deriveUserspaceConfig(cleanCfg), 0, 0)
	if err != nil {
		t.Fatalf("clean buildSnapshot: %v", err)
	}
	if !clean.ZoneSetValidated {
		t.Fatal("a populated collision-free zone set must carry zone_set_validated=true")
	}

	collisionCfg := compileWithStubbedLinks6722(t, quarantineCollisionLines6722(t), map[string]int{
		"ge-0-0-1": 24,
		"ge-0-0-2": 25,
	}, map[string]string{
		"ge-0-0-1": "02:bf:72:01:00:01",
		"ge-0-0-2": "02:bf:72:01:00:02",
	}, true)
	collision, err := buildSnapshot(collisionCfg, deriveUserspaceConfig(collisionCfg), 0, 0)
	if err != nil {
		t.Fatalf("collision buildSnapshot: %v", err)
	}
	if len(collision.zoneIDCollisions) == 0 {
		t.Fatal("fixture did not produce a StableZoneID quarantine")
	}
	if collision.ZoneSetValidated {
		t.Fatal("a quarantined zone set must not authorize removed-zone purge")
	}
}
