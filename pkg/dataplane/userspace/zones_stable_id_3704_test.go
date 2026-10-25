// #3704: buildZoneSnapshots must stamp the STABLE name-hash zone id
// (config.StableZoneID) onto the live dataplane wire — the SAME namespace the
// compiler (pkg/dataplane.assignZoneIDs -> CompileResult.ZoneIDs), the HA name
// fallback (pkg/daemon.buildZoneIDs), the zone->RG map (pkg/daemon.buildZoneRGMap
// key space consumed by cluster.ShouldSyncZone), and every CLI/API session
// zone-name display use.
//
// #3075 moved the compiler/CLI/API/HA namespace to StableZoneID but LEFT this
// wire builder on the legacy SORTED-POSITIONAL uint16(i+1). For any >=2-zone
// config the two namespaces split, which:
//   - mis-mapped session zone-name display (positional session id reverse-mapped
//     through the name-hash map -> "zone-N" fallback / wrong name), and
//   - defeated per-RG active/active session-sync ownership (ShouldSyncZone looked
//     up the name-hash zoneRGMap with a positional session IngressZone -> miss ->
//     collapse to the global primary).
//
// These tests all go RED if buildZoneSnapshots is reverted to uint16(i+1): the
// fixture names' StableZoneIDs are far from their sorted-positional indices.
package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// threeZoneCfg is a >=2-zone fixture whose StableZoneIDs are all distinct and
// none equal to their sorted-positional index (verified below), so a positional
// revert flips every assertion in this file.
func threeZoneCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		// sorted order: dmz(1), trust(2), untrust(3), wan(4)
		"dmz":     {Name: "dmz"},
		"trust":   {Name: "trust", Interfaces: []string{"reth0.0"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth1.0"}},
		"wan":     {Name: "wan"},
	}
	return cfg
}

// TestBuildZoneSnapshotsStableZoneID asserts the wire zone id equals
// config.StableZoneID(name) for every zone (the #3704 fix), and that this is
// NOT the legacy sorted-positional id (RED-on-revert guard).
func TestBuildZoneSnapshotsStableZoneID(t *testing.T) {
	cfg := threeZoneCfg()
	snaps := buildZoneSnapshots(cfg)
	if len(snaps) != len(cfg.Security.Zones) {
		t.Fatalf("got %d zone snapshots, want %d", len(snaps), len(cfg.Security.Zones))
	}

	seen := make(map[uint32]string, len(snaps))
	positionalDivergences := 0
	for i, z := range snaps {
		want := config.StableZoneID(z.Name)
		if z.ID != want {
			t.Errorf("zone %q: wire id = %d, want StableZoneID = %d "+
				"(#3704: wire builder must use the name-hash namespace)",
				z.Name, z.ID, want)
		}
		// The wire ids must be collision-free within a config for the
		// reverse-map (display) and the zoneRGMap key space to be 1:1.
		if prev, dup := seen[z.ID]; dup {
			t.Errorf("zone id collision: %q and %q both = %d", prev, z.Name, z.ID)
		}
		seen[z.ID] = z.Name
		// snaps is emitted in sorted-name order, so i+1 is exactly the legacy
		// positional id this fix replaced. Confirm the fixture actually diverges
		// so a positional revert is guaranteed to fail the assertion above.
		if want != uint32(i+1) {
			positionalDivergences++
		}
	}
	if positionalDivergences == 0 {
		t.Fatal("fixture no longer diverges from positional ids; the " +
			"RED-on-revert guard is toothless — pick different zone names")
	}
}

// TestBuildZoneSnapshotsSessionDisplayReverseMap models api/sessions.go's
// zone-id -> name reverse map, which is built from the name-hash namespace
// (CompileResult.ZoneIDs / config.StableZoneID). It then reverse-maps each
// zone's WIRE id (what a session's stored IngressZone/EgressZone carries) and
// asserts the name resolves — no "zone-N" fallback and no wrong-name collision.
// On a positional-wire revert this lookup misses for every zone whose positional
// index != StableZoneID (RED-on-revert).
func TestBuildZoneSnapshotsSessionDisplayReverseMap(t *testing.T) {
	cfg := threeZoneCfg()

	// Namespace A: the display reverse map (api/sessions.go:600 builds
	// zoneNames[id]=name from cr.ZoneIDs, i.e. config.StableZoneID).
	zoneNames := make(map[uint32]string, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames[config.StableZoneID(name)] = name
	}

	// Namespace B: the wire ids a session actually carries.
	for _, z := range buildZoneSnapshots(cfg) {
		got, ok := zoneNames[z.ID]
		if !ok {
			t.Errorf("session-display miss for zone %q (wire id %d): would render "+
				"the %q fallback instead of the name (#3704 namespace split)",
				z.Name, z.ID, fmt.Sprintf("zone-%d", z.ID))
			continue
		}
		if got != z.Name {
			t.Errorf("session-display mis-attribution: wire id %d reverse-maps to "+
				"%q, want %q", z.ID, got, z.Name)
		}
	}
}

// TestBuildZoneSnapshotsPerRGOwnershipLookup models the cluster.ShouldSyncZone
// per-RG ownership lookup: `rgID, ok := s.zoneRGMap[session.IngressZone]`. The
// zoneRGMap is keyed by the name-hash namespace (pkg/daemon.buildZoneRGMap keys
// on buildZoneIDs = config.StableZoneID); the session's IngressZone is the WIRE
// id from buildZoneSnapshots. For the RETH zones this lookup MUST hit so per-RG
// ownership (IsPrimaryForRGFn) is consulted instead of collapsing to the global
// primary. On a positional-wire revert the wire id is not a key in the
// name-hash map -> ok=false -> per-RG ownership defeated (RED-on-revert).
func TestBuildZoneSnapshotsPerRGOwnershipLookup(t *testing.T) {
	cfg := threeZoneCfg()

	// The zoneRGMap key space, exactly as pkg/daemon.buildZoneRGMap produces it:
	// keyed by config.StableZoneID(name) for zones on a RETH interface.
	zoneRGMap := map[uint32]int{
		config.StableZoneID("trust"):   1, // trust -> reth0 -> RG 1
		config.StableZoneID("untrust"): 2, // untrust -> reth1 -> RG 2
	}

	wireID := make(map[string]uint32)
	for _, z := range buildZoneSnapshots(cfg) {
		wireID[z.Name] = z.ID
	}

	for zone, wantRG := range map[string]int{"trust": 1, "untrust": 2} {
		id, ok := wireID[zone]
		if !ok {
			t.Fatalf("zone %q missing from wire snapshot", zone)
		}
		rg, hit := zoneRGMap[id]
		if !hit {
			t.Errorf("per-RG ownership lookup MISSED for zone %q (session "+
				"IngressZone=%d): wire-id namespace != zoneRGMap namespace, so "+
				"ShouldSyncZone falls back to the global primary and per-RG "+
				"active/active ownership collapses (#3704)", zone, id)
			continue
		}
		if rg != wantRG {
			t.Errorf("zone %q: per-RG lookup got RG %d, want %d", zone, rg, wantRG)
		}
	}
}
