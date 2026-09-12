package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9655, first half. The zone-ownership snapshot a bulk's reconcile judges by
// is taken at bulk start, and two of its properties were wrong:
//
//   - a zone map installed DURING the bulk left the snapshot judging by
//     ownership that no longer applied, so a zone moved to this node had its
//     sessions deleted;
//   - "no snapshot" and "a snapshot naming no zone" were not distinguished.
//
// Both are fixed here. What is NOT fixed here is the issue's headline: a stale
// peer-owned session in an RG-UNMAPPED zone still survives the reconcile.
//
// Answering an unmapped zone the way the live sweep does — RG 0 ownership — was
// implemented and then withdrawn on measurement. A zone of node-local, non-RETH
// interfaces is RG-unmapped too, and no cluster-mode commit rule rejects one, so
// on the RG 0 secondary that answer deletes the node's OWN live flows in such a
// zone at every bulk; a TCP flow then dies on its next non-SYN packet. Deleting
// only the SYNCED copy needs a per-session origin bit, which the
// session_value/HA-wire prerequisite carries. Until then an unmapped zone is
// kept whole, and this issue stays open for that half.

var (
	staleUnmapped9655 = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 7, 50}, DstIP: [4]byte{172, 16, 80, 200}, Protocol: 6, SrcPort: 42000, DstPort: 5201}
	ownRG1Local9655   = dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 3001, DstPort: 22}
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
		staleUnmapped9655: establishedIn(unmappedZone9655),
		ownRG1Local9655:   establishedIn(1),
		stalePeerRG9655:   establishedIn(5),
	}}
	ss := NewSessionSync(":0", "10.0.0.3:4785", dp)
	ss.IsPrimaryFn = func() bool { return rg0Primary }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	if zoneRG != nil {
		ss.SetZoneRGMap(zoneRG)
	}
	return ss, dp
}

// An RG-unmapped zone is NOT judged: its sessions are kept, on either node.
// This is the withheld half, pinned so the RG 0 answer cannot return without a
// cell changing — and the cell that changes says why it must not.
func TestUnmappedZoneSessionSurvivesTheReconcile_9655(t *testing.T) {
	rx, dp := receiver9655(t, false, map[uint16]int{1: 1, 5: 5})
	pumpBulk(t, emptyWindowSender9655(t), rx)
	if _, ok := dp.v4sessions[staleUnmapped9655]; !ok {
		t.Errorf("#9655: a session in an RG-unmapped zone was reconciled away on the RG 0 secondary. An unmapped " +
			"zone may be node-local (non-RETH) interfaces, so this deletes the node's OWN live flows at every " +
			"bulk and a TCP flow dies on its next non-SYN packet. Deleting only the SYNCED copy needs the " +
			"per-session origin bit")
	}
	if _, ok := dp.v4sessions[stalePeerRG9655]; ok {
		t.Errorf("control: the stale session in the peer-owned MAPPED zone was not reconciled, so this fixture is not reconciling at all")
	}
	if _, ok := dp.v4sessions[ownRG1Local9655]; !ok {
		t.Errorf("this node's own RG 1 session was reconciled away")
	}
}

func TestUnmappedZoneSessionIsKeptOnTheRG0Primary_9655(t *testing.T) {
	rx, dp := receiver9655(t, true, map[uint16]int{1: 1, 5: 5})
	pumpBulk(t, emptyWindowSender9655(t), rx)
	if _, ok := dp.v4sessions[staleUnmapped9655]; !ok {
		t.Errorf("#9655: a session in an RG-unmapped zone was deleted on the RG 0 primary. The zone is not judged " +
			"at all now, so the answer must not depend on which node runs the reconcile")
	}
	if _, ok := dp.v4sessions[stalePeerRG9655]; ok {
		t.Errorf("control: the stale session in the peer-owned mapped zone was not reconciled")
	}
}

// A snapshot that names NO zone judges nothing, whether the map was never
// installed (nil) or installed naming no zone (buildZoneRGMap's empty map). Both
// skip, so every session is kept — including, deliberately, the stale one.
// TestReconcileSkipsNonEmptyBulkWithoutZoneSnapshot keeps the nil guard from
// master; this cell adds the installed-empty case beside it.
func TestAZoneMapNamingNoZoneSkipsTheReconcile_9655(t *testing.T) {
	for _, tc := range []struct {
		name   string
		zoneRG map[uint16]int
	}{
		{"installed but naming no zone", map[uint16]int{}},
		{"never installed", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rx, dp := receiver9655(t, false, tc.zoneRG)
			// THE PROPERTY: no snapshot is taken at all. Asserting only that
			// nothing was deleted cannot see this — with an empty snapshot every
			// zone falls to shouldSync's unnamed-zone default, which KEEPS, so a
			// bulk that wrongly snapshots deletes nothing either and the cell
			// passes for the wrong reason.
			if snap := rx.snapshotZoneOwnership(); snap != nil {
				t.Errorf("#9655: a zone map naming no zone produced a snapshot (%d zones, mapGen %d); the "+
					"reconcile must take none and skip, so the next bulk can judge by a real map",
					len(snap.zones), snap.mapGen)
			}
			pumpBulk(t, emptyWindowSender9655(t), rx)
			for what, key := range map[string]dataplane.SessionKey{
				"the session in an RG-unmapped zone": staleUnmapped9655,
				"the session in the mapped zone 5":   stalePeerRG9655,
				"this node's own RG 1 session":       ownRG1Local9655,
			} {
				if _, ok := dp.v4sessions[key]; !ok {
					t.Errorf("#9655: %s was reconciled away, but the snapshot named no zone: there is nothing to "+
						"judge ownership by, so the bulk must delete nothing and let the next one try", what)
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
