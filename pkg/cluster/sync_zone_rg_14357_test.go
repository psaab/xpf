package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #14357: a peer-installed session read back through the BPF mirror has lost
// both ingress identity carriers — IngressIfaceFold is not persisted in the
// on-map ABI and ScrubNodeLocal zeroed IngressIfindex/IngressVlanID at
// install. In a multi-RG zone on a node primary for only one RG, the old
// predicates fell back to zoneSetSyncs(zone)==true and judged the peer RG
// row locally owned: sweep re-exported it (echo) and BulkEnd never purged it.
//
// FAIL-ON-REVERT: revert the cluster-synced multi-RG guard in
// ShouldSyncSessionV4/V6 and zoneOwnershipSnapshot.shouldSyncV4/V6 and the
// mirrored peer rows below read as locally owned (true) again.
func TestPeerSyncedMirrorRowNotOwnedInMultiRGZone14357(t *testing.T) {
	const zone uint16 = 42
	const foldRG2 uint32 = 0x2202

	// Mirror row: exactly what production read-back yields for a peer RG2
	// session — fold 0, ifindex 0, only the origin bit survives.
	mirrorV4 := dataplane.SessionValue{IngressZone: zone, Flags: dataplane.SessFlagClusterSynced}
	mirrorV6 := dataplane.SessionValueV6{IngressZone: zone, Flags: dataplane.SessFlagClusterSynced}
	// Local controls in the same zone: no origin bit. Attributable local
	// RG1 row and unattributable local row must both stay zone-owned.
	localV4 := dataplane.SessionValue{IngressZone: zone}
	localV6 := dataplane.SessionValueV6{IngressZone: zone}
	// Attributable peer row: fold still present (wire path, pre-mirror) must
	// still resolve to RG2 and be judged not-owned.
	attribPeerV4 := dataplane.SessionValue{IngressZone: zone, IngressIfaceFold: foldRG2, Flags: dataplane.SessFlagClusterSynced}

	ss := NewSessionSync(":0", "10.0.0.1:4785", &mockSweepDP{})
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rg int) bool { return rg == 1 }
	ss.SetZoneOwnership(ZoneRGMap{zone: {1, 2}}, map[uint32]int{0x1101: 1, foldRG2: 2}, nil)

	if ss.ShouldSyncSessionV4(mirrorV4) {
		t.Fatal("peer-synced mirror v4 row (fold lost) judged locally owned in multi-RG zone")
	}
	if ss.ShouldSyncSessionV6(mirrorV6) {
		t.Fatal("peer-synced mirror v6 row (fold lost) judged locally owned in multi-RG zone")
	}
	if !ss.ShouldSyncSessionV4(localV4) || !ss.ShouldSyncSessionV6(localV6) {
		t.Fatal("local unattributable row in multi-RG zone lost zone fallback")
	}
	if ss.ShouldSyncSessionV4(attribPeerV4) {
		t.Fatal("attributable peer RG2 row judged locally owned on RG1 primary")
	}

	snap := ss.snapshotZoneOwnership()
	if snap == nil {
		t.Fatal("snapshotZoneOwnership returned nil for installed map")
	}
	if snap.shouldSyncV4(mirrorV4) {
		t.Fatal("snapshot: peer-synced mirror v4 row kept by bulk reconcile")
	}
	if snap.shouldSyncV6(mirrorV6) {
		t.Fatal("snapshot: peer-synced mirror v6 row kept by bulk reconcile")
	}
	if !snap.shouldSyncV4(localV4) || !snap.shouldSyncV6(localV6) {
		t.Fatal("snapshot: local unattributable row lost zone fallback")
	}

	// Single-RG zone: the zone answer is unambiguous, guard must not fire.
	ss1 := NewSessionSync(":0", "10.0.0.1:4785", &mockSweepDP{})
	ss1.IsPrimaryFn = func() bool { return false }
	ss1.IsPrimaryForRGFn = func(rg int) bool { return rg == 1 }
	ss1.SetZoneOwnership(ZoneRGMap{zone: {1}}, map[uint32]int{0x1101: 1}, nil)
	if !ss1.ShouldSyncSessionV4(mirrorV4) {
		t.Fatal("peer-synced row in single-RG locally-owned zone must keep zone answer")
	}
	snap1 := ss1.snapshotZoneOwnership()
	if !snap1.shouldSyncV4(mirrorV4) {
		t.Fatal("snapshot: peer-synced row in single-RG locally-owned zone must be kept")
	}
}
