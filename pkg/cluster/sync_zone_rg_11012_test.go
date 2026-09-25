package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// FAIL-ON-REVERT: an RG1 and RG2 primary share this zone. Replacing the
// per-row bulk/reconcile predicates with ShouldSyncZone sends both groups from
// each node and leaves peer-owned stale rows instead of deleting them.
func TestActiveActiveBulkSyncUsesEachSessionRedundancyGroup11012(t *testing.T) {
	const zone uint16 = 42
	const foldRG1 uint32 = 0x1101
	const foldRG2 uint32 = 0x2202

	liveRG1 := dataplane.SessionKey{SrcIP: [4]byte{10, 1, 0, 1}, DstIP: [4]byte{192, 0, 2, 1}, Protocol: 6, SrcPort: 1001, DstPort: 443}
	liveRG2 := dataplane.SessionKey{SrcIP: [4]byte{10, 2, 0, 1}, DstIP: [4]byte{192, 0, 2, 2}, Protocol: 6, SrcPort: 1002, DstPort: 443}
	deletedRG1 := dataplane.SessionKey{SrcIP: [4]byte{10, 1, 0, 2}, DstIP: [4]byte{192, 0, 2, 3}, Protocol: 6, SrcPort: 1003, DstPort: 443}
	deletedRG2 := dataplane.SessionKey{SrcIP: [4]byte{10, 2, 0, 2}, DstIP: [4]byte{192, 0, 2, 4}, Protocol: 6, SrcPort: 1004, DstPort: 443}
	liveRG1V6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 1, 0xdb, 8, 1}, DstIP: [16]byte{0x20, 1, 0xdb, 8, 2}, Protocol: 6, SrcPort: 2001, DstPort: 443}
	liveRG2V6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 1, 0xdb, 8, 3}, DstIP: [16]byte{0x20, 1, 0xdb, 8, 4}, Protocol: 6, SrcPort: 2002, DstPort: 443}
	deletedRG1V6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 1, 0xdb, 8, 5}, DstIP: [16]byte{0x20, 1, 0xdb, 8, 6}, Protocol: 6, SrcPort: 2003, DstPort: 443}
	deletedRG2V6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 1, 0xdb, 8, 7}, DstIP: [16]byte{0x20, 1, 0xdb, 8, 8}, Protocol: 6, SrcPort: 2004, DstPort: 443}

	v4 := func(fold uint32, flags uint16) dataplane.SessionValue {
		return dataplane.SessionValue{IngressZone: zone, IngressIfaceFold: fold, Flags: flags}
	}
	v6 := func(fold uint32, flags uint16) dataplane.SessionValueV6 {
		return dataplane.SessionValueV6{IngressZone: zone, IngressIfaceFold: fold, Flags: flags}
	}

	newNode := func(name string, primaryRG int, valuesV4 map[dataplane.SessionKey]dataplane.SessionValue, valuesV6 map[dataplane.SessionKeyV6]dataplane.SessionValueV6) (*SessionSync, *mockSweepDP) {
		dp := &mockSweepDP{v4sessions: valuesV4, v6sessions: valuesV6}
		ss := NewSessionSync(":0", name, dp)
		ss.IsPrimaryFn = func() bool { return false }
		ss.IsPrimaryForRGFn = func(rg int) bool { return rg == primaryRG }
		ss.SetZoneOwnership(ZoneRGMap{zone: {1, 2}}, map[uint32]int{foldRG1: 1, foldRG2: 2}, nil)
		return ss, dp
	}

	// Each primary carries one live local row and one stale peer-owned row in
	// each family. Both rows share a zone, so only their stable ingress folds
	// can distinguish ownership.
	peerSynced := uint16(dataplane.SessFlagClusterSynced)
	rg1, dp1 := newNode("10.0.0.1:4785", 1,
		map[dataplane.SessionKey]dataplane.SessionValue{
			liveRG1:    v4(foldRG1, 0),
			deletedRG2: v4(foldRG2, peerSynced),
		},
		map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			liveRG1V6:    v6(foldRG1, 0),
			deletedRG2V6: v6(foldRG2, peerSynced),
		},
	)
	rg2, dp2 := newNode("10.0.0.2:4785", 2,
		map[dataplane.SessionKey]dataplane.SessionValue{
			liveRG2:    v4(foldRG2, 0),
			deletedRG1: v4(foldRG1, peerSynced),
		},
		map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			liveRG2V6:    v6(foldRG2, 0),
			deletedRG1V6: v6(foldRG1, peerSynced),
		},
	)

	if !rg1.ShouldSyncZone(zone) || !rg2.ShouldSyncZone(zone) {
		t.Fatal("zone-level fallback must recognize that each node owns one RG represented by the zone")
	}
	if !rg1.ShouldSyncSessionV4(v4(foldRG1, 0)) || rg1.ShouldSyncSessionV4(v4(foldRG2, 0)) {
		t.Fatal("RG1 primary did not select only sessions owned by RG1")
	}
	if !rg2.ShouldSyncSessionV6(v6(foldRG2, 0)) || rg2.ShouldSyncSessionV6(v6(foldRG1, 0)) {
		t.Fatal("RG2 primary did not select only sessions owned by RG2")
	}

	// Each node's complete bulk snapshot installs the peer's live group and
	// removes stale peer-origin rows for that same group. Local-owned rows stay.
	pumpBulk(t, rg1, rg2)
	pumpBulk(t, rg2, rg1)

	for name, dp := range map[string]*mockSweepDP{"RG1": dp1, "RG2": dp2} {
		for key, want := range map[dataplane.SessionKey]bool{liveRG1: true, liveRG2: true, deletedRG1: false, deletedRG2: false} {
			if _, ok := dp.v4sessions[key]; ok != want {
				t.Errorf("%s v4 session %v present=%v, want %v", name, key, ok, want)
			}
		}
		for key, want := range map[dataplane.SessionKeyV6]bool{liveRG1V6: true, liveRG2V6: true, deletedRG1V6: false, deletedRG2V6: false} {
			if _, ok := dp.v6sessions[key]; ok != want {
				t.Errorf("%s v6 session %v present=%v, want %v", name, key, ok, want)
			}
		}
	}
}
func TestSyncSweepSelectsSessionsByRGWithinOneZone11012(t *testing.T) {
	now := monotonicSeconds()
	const zone uint16 = 42
	const foldRG1 uint32 = 0x1101
	const foldRG2 uint32 = 0x2202
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 1, 0, 1}, Protocol: 6}: {Created: now, IngressZone: zone, IngressIfindex: 11},
			{SrcIP: [4]byte{10, 2, 0, 1}, Protocol: 6}: {Created: now, IngressZone: zone, IngressIfindex: 22},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			{SrcIP: [16]byte{0x20, 1, 0xdb, 8, 1}, Protocol: 6}: {Created: now, IngressZone: zone, IngressIfindex: 11},
			{SrcIP: [16]byte{0x20, 1, 0xdb, 8, 2}, Protocol: 6}: {Created: now, IngressZone: zone, IngressIfindex: 22},
		},
	}
	ss := NewSessionSync(":0", "10.0.0.1:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rg int) bool { return rg == 1 }
	ss.SetZoneOwnership(ZoneRGMap{zone: {1, 2}}, map[uint32]int{foldRG1: 1, foldRG2: 2}, func(ifindex uint32, _ uint16) uint32 {
		if ifindex == 11 {
			return foldRG1
		}
		if ifindex == 22 {
			return foldRG2
		}
		return 0
	})
	ss.lastSweepTime = now

	if sent := ss.syncSweep(); sent != 2 {
		t.Fatalf("RG1 primary swept %d sessions, want the v4 and v6 rows owned by RG1 only", sent)
	}
	if got := ss.stats.SessionsSent.Load(); got != 2 {
		t.Fatalf("sweep session counter = %d, want 2", got)
	}
}
