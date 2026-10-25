package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func cfgWithZones(names ...string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = make(map[string]*config.ZoneConfig, len(names))
	for _, n := range names {
		cfg.Security.Zones[n] = &config.ZoneConfig{Name: n}
	}
	return cfg
}

func zoneNameByID(cr *CompileResult, id uint32) string {
	for name, v := range cr.ZoneIDs {
		if v == id {
			return name
		}
	}
	return ""
}

// TestAssignZoneIDStableAcrossEarlierZoneAdd is the #3075 fail-on-revert guard —
// the exact scenario the issue describes.
//
// A live session stores a numeric zone id. Under the OLD sorted 1..N positional
// assignment, adding a zone whose name sorts BEFORE an existing zone renumbered
// every later zone, so the stored id then reverse-resolved to the WRONG zone
// name (wrong policy/zone attribution + HA mismatch). The stable name-hash makes
// the id a pure function of the name, so an earlier-sorting add never moves it.
//
// Reverting assignZoneIDs to the sorted-positional loop makes this RED: adding
// "alpha" would shift untrust from id 2 to id 3, and the stored id 2 would then
// reverse-resolve to "trust".
func TestAssignZoneIDStableAcrossEarlierZoneAdd(t *testing.T) {
	first := &CompileResult{ZoneIDs: make(map[string]uint32)}
	assignZoneIDs(first, cfgWithZones("trust", "untrust"))
	idUntrust := first.ZoneIDs["untrust"]
	if idUntrust == 0 {
		t.Fatalf("untrust got id 0")
	}

	// Add "alpha", which sorts before both. Sorted 1..N would renumber untrust.
	second := &CompileResult{ZoneIDs: make(map[string]uint32)}
	assignZoneIDs(second, cfgWithZones("alpha", "trust", "untrust"))

	if second.ZoneIDs["untrust"] != idUntrust {
		t.Fatalf("untrust id changed across earlier-zone add: was %d, now %d (sorted-positional assignment reverted?)", idUntrust, second.ZoneIDs["untrust"])
	}
	// The session's stored numeric id must still reverse-resolve to "untrust"
	// — never the wrong zone. This is the mis-map the issue reports.
	if got := zoneNameByID(second, idUntrust); got != "untrust" {
		t.Fatalf("stored zone id %d reverse-resolves to %q after the config edit, want \"untrust\" (the #3075 mis-map)", idUntrust, got)
	}
}

// TestAssignZoneIDStableAcrossRemoval proves a surviving zone keeps its id when
// an unrelated earlier-sorting zone is removed (the inverse edit).
func TestAssignZoneIDStableAcrossRemoval(t *testing.T) {
	withAlpha := &CompileResult{ZoneIDs: make(map[string]uint32)}
	assignZoneIDs(withAlpha, cfgWithZones("alpha", "trust", "untrust"))
	idTrustWith := withAlpha.ZoneIDs["trust"]

	withoutAlpha := &CompileResult{ZoneIDs: make(map[string]uint32)}
	assignZoneIDs(withoutAlpha, cfgWithZones("trust", "untrust"))
	if withoutAlpha.ZoneIDs["trust"] != idTrustWith {
		t.Fatalf("trust id changed when unrelated zone alpha was removed: was %d, now %d", idTrustWith, withoutAlpha.ZoneIDs["trust"])
	}
}

// TestAssignZoneIDMatchesSSOT pins the compiler assignment to the
// config.StableZoneID SSOT — the property the HA-symmetry test in pkg/daemon
// (buildZoneIDs == this) and the wire round-trip both rely on.
func TestAssignZoneIDMatchesSSOT(t *testing.T) {
	result := &CompileResult{ZoneIDs: make(map[string]uint32)}
	zones := []string{"trust", "untrust", "dmz", "wan", "lan", "mgmt"}
	assignZoneIDs(result, cfgWithZones(zones...))
	for _, name := range zones {
		if result.ZoneIDs[name] != config.StableZoneID(name) {
			t.Fatalf("assignZoneIDs(%q) = %d, want config.StableZoneID = %d", name, result.ZoneIDs[name], config.StableZoneID(name))
		}
	}
}
