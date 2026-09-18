package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9655/#10227: the zone-ownership snapshot a bulk's reconcile judges by is
// taken at bulk start, and its safety rules cover both failover transitions:
//
//   - a zone map installed DURING the bulk leaves the snapshot judging by the
//     ownership that applied at bulk start, so a moved zone cannot delete flows
//     this node now owns;
//   - a nil zone map takes no snapshot, while an installed empty map is a
//     valid all-unmapped snapshot that still reconciles using the RG 0 fallback;
//   - with a non-empty snapshot, a zone it does not name uses that fallback.
//     On the RG 0 secondary, the dataplane origin bit deletes only peer-synced
//     rows while a row promoted to local ownership during failover survives.

var (
	staleUnmapped9655 = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 7, 50}, DstIP: [4]byte{172, 16, 80, 200}, Protocol: 6, SrcPort: 42000, DstPort: 5201}
	ownRG1Local9655   = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 3001, DstPort: 22}
	promotedUnmapped9655 = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 7, 51}, DstIP: [4]byte{172, 16, 80, 200}, Protocol: 6, SrcPort: 42001, DstPort: 5201}
	stalePeerRG9655   = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 5, 77}, DstIP: [4]byte{172, 16, 80, 200}, Protocol: 6, SrcPort: 43000, DstPort: 5201}
)

const unmappedZone9655 = 7

// emptyWindowSender9655 is a primary whose authoritative table is empty, so
// every session the receiver judges as not its own is stale.
func emptyWindowSender9655(t *testing.T) *SessionSync {
	t.Helper()
	ss := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}})
	ss.IsPrimaryFn = func() bool { return true }
	ss.BulkSnapshotSource = func() (BulkSnapshot, error) { return BulkSnapshot{}, nil }
	return ss
}

// receiver9655 holds a stale session in an RG-unmapped zone, a stale session in
// the peer-owned mapped zone 5, and its own RG 1 session. zoneRG nil means the
// map was never set.
func receiver9655(t *testing.T, rg0Primary bool, zoneRG map[uint16]int) (*SessionSync, *mockSweepDP) {
	t.Helper()
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
		staleUnmapped9655:    {State: dataplane.SessStateEstablished, IngressZone: unmappedZone9655, Flags: dataplane.SessFlagClusterSynced},
		promotedUnmapped9655: establishedIn(unmappedZone9655),
		ownRG1Local9655:      establishedIn(1),
		stalePeerRG9655:      establishedIn(5),
	}}
	ss := NewSessionSync(":0", "10.0.0.3:4785", dp)
	ss.IsPrimaryFn = func() bool { return rg0Primary }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	if zoneRG != nil {
		ss.SetZoneRGMap(zoneRG)
	}
	return ss, dp
}

// An RG-unmapped zone uses the RG 0 fallback captured at bulk start. On the
// RG 0 secondary, the origin bit removes stale peer-synced rows while keeping
// rows promoted to local ownership during failover; the primary keeps both.
func TestUnmappedZoneSessionSurvivesTheReconcile_9655(t *testing.T) {
	rx, dp := receiver9655(t, false, map[uint16]int{1: 1, 5: 5})
	pumpBulk(t, emptyWindowSender9655(t), rx)
	if _, ok := dp.v4sessions[staleUnmapped9655]; ok {
		t.Errorf("#10227: stale peer-synced row in an RG-unmapped zone survived the reconcile")
	}
	if _, ok := dp.v4sessions[promotedUnmapped9655]; !ok {
		t.Errorf("#10227: failover-promoted local row in an RG-unmapped zone was deleted")
	}
	if _, ok := dp.v4sessions[stalePeerRG9655]; ok {
		t.Errorf("control: the stale session in the peer-owned MAPPED zone was not reconciled")
	}
	if _, ok := dp.v4sessions[ownRG1Local9655]; !ok {
		t.Errorf("this node's own RG 1 session was reconciled away")
	}
}

func TestUnmappedZoneSessionIsKeptOnTheRG0Primary_9655(t *testing.T) {
	rx, dp := receiver9655(t, true, map[uint16]int{1: 1, 5: 5})
	pumpBulk(t, emptyWindowSender9655(t), rx)
	if _, ok := dp.v4sessions[staleUnmapped9655]; !ok {
		t.Error("#9655: stale peer-synced row in an RG-unmapped zone was deleted on the RG 0 primary")
	}
	if _, ok := dp.v4sessions[promotedUnmapped9655]; !ok {
		t.Errorf("#10227: failover-promoted local row in an RG-unmapped zone was deleted on the RG 0 primary")
	}
	if _, ok := dp.v4sessions[stalePeerRG9655]; ok {
		t.Errorf("control: the stale session in the peer-owned mapped zone was not reconciled")
	}
}

// The fallback is immutable for the bulk: flipping the live RG 0 answer after
// BulkStart must not change the answer used by BulkEnd's reconcile.
func TestUnmappedZoneUsesRG0FallbackCapturedAtBulkStart_9655(t *testing.T) {
	rx, dp := receiver9655(t, true, map[uint16]int{1: 1, 5: 5})
	rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
	rx.IsPrimaryFn = func() bool { return false }
	rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
	if _, ok := dp.v4sessions[staleUnmapped9655]; !ok {
		t.Fatal("#9655: the bulk re-queried live RG 0 ownership instead of using its start snapshot")
	}
}

// An installed empty map is still a real snapshot. It must reconcile on the
// RG 0 primary using the captured fallback rather than silently skipping.
func TestInstalledEmptyZoneMapUsesRG0Fallback_9655(t *testing.T) {
	rx, dp := receiver9655(t, true, map[uint16]int{})
	snap := rx.snapshotZoneOwnership()
	if snap == nil || len(snap.zones) != 0 {
		t.Fatalf("#9655: installed empty map did not produce a valid empty snapshot: %#v", snap)
	}
	pumpBulk(t, emptyWindowSender9655(t), rx)
	if _, ok := dp.v4sessions[staleUnmapped9655]; !ok {
		t.Fatal("#9655: valid empty snapshot skipped RG 0 fallback reconciliation")
	}
}

// An unwired nil map still takes no snapshot. An installed empty map is a
// valid all-unmapped snapshot and reconciles using the captured RG 0 fallback:
// the secondary's origin gate removes stale peer-synced rows but keeps local.
func TestAZoneMapNamingNoZoneSkipsTheReconcile_9655(t *testing.T) {
	for _, tc := range []struct {
		name    string
		zoneRG  map[uint16]int
		nilSnap bool
	}{
		{"installed but naming no zone", map[uint16]int{}, false},
		{"never installed", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rx, dp := receiver9655(t, false, tc.zoneRG)
			snap := rx.snapshotZoneOwnership()
			if tc.nilSnap {
				if snap != nil {
					t.Fatalf("#9655: nil zone map produced a snapshot (%d zones, mapGen %d)",
						len(snap.zones), snap.mapGen)
				}
			} else if snap == nil || len(snap.zones) != 0 {
				t.Fatalf("#10227: installed empty zone map must produce an all-unmapped snapshot, got %#v", snap)
			}
			pumpBulk(t, emptyWindowSender9655(t), rx)
			if tc.nilSnap {
				for what, key := range map[string]dataplane.SessionKey{
					"the peer-synced row in an RG-unmapped zone": staleUnmapped9655,
					"the promoted row in an RG-unmapped zone":     promotedUnmapped9655,
					"the session in the mapped zone 5":            stalePeerRG9655,
					"this node's own RG 1 session":                ownRG1Local9655,
				} {
					if _, ok := dp.v4sessions[key]; !ok {
						t.Errorf("#9655: %s was reconciled away without a zone snapshot", what)
					}
				}
			} else {
				if _, ok := dp.v4sessions[staleUnmapped9655]; ok {
					t.Error("#10227: empty all-unmapped snapshot kept stale peer-synced row")
				}
				for what, key := range map[string]dataplane.SessionKey{
					"the promoted row in an RG-unmapped zone": promotedUnmapped9655,
					"the session in the mapped zone 5":         stalePeerRG9655,
					"this node's own RG 1 session":             ownRG1Local9655,
				} {
					if _, ok := dp.v4sessions[key]; !ok {
						t.Errorf("#10227: empty all-unmapped snapshot deleted %s", what)
					}
				}
			}
		})
	}
}

// A zone map installed during the bulk with different contents skips the
// reconcile; an identical map re-set by a config apply does not.
func TestReconcileIsSkippedOnlyWhenTheZoneMapChangedDuringTheBulk_9655(t *testing.T) {
	bulk := func(during func(*SessionSync)) *mockSweepDP {
		rx, dp := receiver9655(t, false, map[uint16]int{1: 1, 5: 5})
		rx.handleMessage(nil, syncMsgBulkStart, bulkStartPayload(1, nil))
		during(rx)
		rx.handleMessage(nil, syncMsgBulkEnd, bulkStartPayload(1, nil))
		return dp
	}
	moved := bulk(func(rx *SessionSync) { rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 1}) })
	if _, ok := moved.v4sessions[stalePeerRG9655]; !ok {
		t.Errorf("#9655: zone 5 moved to this node's RG 1 during the bulk, and the reconcile still judged it by the " +
			"snapshot's 'peer-owned' answer and deleted a session this node now owns")
	}
	same := bulk(func(rx *SessionSync) { rx.SetZoneRGMap(map[uint16]int{1: 1, 5: 5}) })
	if _, ok := same.v4sessions[stalePeerRG9655]; ok {
		t.Errorf("re-setting an IDENTICAL zone map during the bulk skipped the reconcile. The daemon re-sets the map " +
			"on every config apply, so any commit during a bulk would cost it its reconcile")
	}
}
