package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #15122 (#14357 regression): the multi-RG cluster-synced guard returned
// false for EVERY unattributable peer-synced row in a multi-RG zone, even
// when this node is primary for every RG in that zone. After a full
// takeover the survivor holds inherited peer-synced rows for RGs it now
// wholly owns; judging them not-owned lets the next peer BulkEnd reconcile
// delete those live sessions when they are absent from the rejoining
// peer's bulk.
//
// FAIL-ON-REVERT: restore the len(rgs) > 1 guard in
// ShouldSyncSessionV4/V6 and zoneOwnershipSnapshot.shouldSyncV4/V6 and
// the all-primary mirror rows below read as not owned (false) again.
func TestPeerSyncedMirrorRowOwnedWhenPrimaryForAllRGs15122(t *testing.T) {
	const zone uint16 = 42

	// Mirror row: fold/ifindex scrubbed, only the origin bit survives.
	mirrorV4 := dataplane.SessionValue{IngressZone: zone, Flags: dataplane.SessFlagClusterSynced}
	mirrorV6 := dataplane.SessionValueV6{IngressZone: zone, Flags: dataplane.SessFlagClusterSynced}
	localV4 := dataplane.SessionValue{IngressZone: zone}
	localV6 := dataplane.SessionValueV6{IngressZone: zone}

	newSync := func(isPrimaryForRG func(int) bool) *SessionSync {
		ss := NewSessionSync(":0", "10.0.0.1:4785", &mockSweepDP{})
		ss.IsPrimaryFn = func() bool { return false }
		ss.IsPrimaryForRGFn = isPrimaryForRG
		ss.SetZoneOwnership(ZoneRGMap{zone: {1, 2}}, map[uint32]int{0x1101: 1, 0x2202: 2}, nil)
		return ss
	}

	// Primary for EVERY RG of the zone: the zone answer is unambiguous
	// (any == all), so inherited peer-synced rows are locally owned and
	// must survive BulkEnd reconcile / be re-exported by the sweep.
	all := newSync(func(rg int) bool { return rg == 1 || rg == 2 })
	if !all.ShouldSyncSessionV4(mirrorV4) {
		t.Fatal("peer-synced mirror v4 row judged not owned on node primary for all RGs of the zone")
	}
	if !all.ShouldSyncSessionV6(mirrorV6) {
		t.Fatal("peer-synced mirror v6 row judged not owned on node primary for all RGs of the zone")
	}
	snapAll := all.snapshotZoneOwnership()
	if snapAll == nil {
		t.Fatal("snapshotZoneOwnership returned nil for installed map")
	}
	if !snapAll.shouldSyncV4(mirrorV4) {
		t.Fatal("snapshot: peer-synced mirror v4 row purged by bulk reconcile on all-RG primary")
	}
	if !snapAll.shouldSyncV6(mirrorV6) {
		t.Fatal("snapshot: peer-synced mirror v6 row purged by bulk reconcile on all-RG primary")
	}
	if !snapAll.shouldSyncV4(localV4) || !snapAll.shouldSyncV6(localV6) {
		t.Fatal("snapshot: local unattributable row lost zone fallback on all-RG primary")
	}

	// #14357 control: primary for RG1 only (mixed ownership) — the guard
	// must still judge the unattributable peer row not owned.
	mixed := newSync(func(rg int) bool { return rg == 1 })
	if mixed.ShouldSyncSessionV4(mirrorV4) {
		t.Fatal("peer-synced mirror v4 row judged locally owned in mixed-primary multi-RG zone")
	}
	if mixed.ShouldSyncSessionV6(mirrorV6) {
		t.Fatal("peer-synced mirror v6 row judged locally owned in mixed-primary multi-RG zone")
	}
	snapMixed := mixed.snapshotZoneOwnership()
	if snapMixed.shouldSyncV4(mirrorV4) {
		t.Fatal("snapshot: peer-synced mirror v4 row kept by bulk reconcile in mixed-primary zone")
	}
	if snapMixed.shouldSyncV6(mirrorV6) {
		t.Fatal("snapshot: peer-synced mirror v6 row kept by bulk reconcile in mixed-primary zone")
	}

	// Primary for none of the zone's RGs: not owned.
	none := newSync(func(rg int) bool { return false })
	if none.ShouldSyncSessionV4(mirrorV4) || none.ShouldSyncSessionV6(mirrorV6) {
		t.Fatal("peer-synced mirror row judged locally owned on node primary for no RG of the zone")
	}
	snapNone := none.snapshotZoneOwnership()
	if snapNone.shouldSyncV4(mirrorV4) || snapNone.shouldSyncV6(mirrorV6) {
		t.Fatal("snapshot: peer-synced mirror row kept by bulk reconcile on no-RG primary")
	}
}
