package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// TestZoneRGMapKeyedByStableZoneID verifies the daemon/cluster side of the
// #3704 contract: buildZoneRGMap keys on config.StableZoneID(name) (via
// buildZoneIDs), the SAME namespace pkg/dataplane/userspace.buildZoneSnapshots
// now stamps onto the live wire (and thus onto a session's IngressZone). A
// session whose IngressZone carries that stable id therefore RESOLVES in the
// zoneRGMap, so cluster.ShouldSyncZone consults per-RG ownership
// (IsPrimaryForRGFn) instead of collapsing to the global primary.
//
// Before #3704 the wire/session id was sorted-positional while this map was
// name-hash, so the lookup missed for every >=2-zone config and per-RG
// active/active session-sync ownership silently degraded to the global primary
// decision. This test locks the key space to StableZoneID and exercises the
// real ShouldSyncZone against it.
func TestZoneRGMapKeyedByStableZoneID(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust", Interfaces: []string{"reth0.0"}},
				"untrust": {Name: "untrust", Interfaces: []string{"reth1.0"}},
				"dmz":     {Name: "dmz", Interfaces: []string{"ge-0/0/2"}}, // no RG
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"reth1":    {Name: "reth1", RedundancyGroup: 2},
				"ge-0/0/2": {Name: "ge-0/0/2"},
			},
		},
	}

	zoneIDs := buildZoneIDs(cfg)
	rgMap := buildZoneRGMap(cfg, zoneIDs)

	// The RETH zones must key on their STABLE name-hash id, not a positional id.
	for _, tc := range []struct {
		zone string
		rg   int
	}{
		{"trust", 1},
		{"untrust", 2},
	} {
		stable := config.StableZoneID(tc.zone)
		if zoneIDs[tc.zone] != stable {
			t.Errorf("buildZoneIDs[%q] = %d, want StableZoneID %d",
				tc.zone, zoneIDs[tc.zone], stable)
		}
		if rgs, ok := rgMap[stable]; !ok || len(rgs) != 1 || rgs[0] != tc.rg {
			t.Errorf("zoneRGMap[StableZoneID(%q)=%d] = (%v, %v), want ([%d], true)",
				tc.zone, stable, rgs, ok, tc.rg)
		}
	}

	// End-to-end: the real cluster.ShouldSyncZone, given a session IngressZone
	// equal to the stable wire id, must consult per-RG ownership.
	ss := cluster.NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.IsPrimaryFn = func() bool { return false }                  // NOT global primary
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 } // primary for RG 1 only
	ss.SetZoneOwnership(rgMap, nil, nil)

	// trust -> RG 1 (primary): syncs via per-RG ownership despite IsPrimaryFn=false.
	if !ss.ShouldSyncZone(config.StableZoneID("trust")) {
		t.Error("ShouldSyncZone(StableZoneID(trust)) = false; per-RG ownership " +
			"for RG 1 was not consulted (namespace split would cause this)")
	}
	// untrust -> RG 2 (not primary): must NOT sync.
	if ss.ShouldSyncZone(config.StableZoneID("untrust")) {
		t.Error("ShouldSyncZone(StableZoneID(untrust)) = true; RG 2 is not primary")
	}
}
