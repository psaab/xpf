package cluster

// #9752: the sender-side installing-table memo. A mirror-sourced resend
// (sweep/bulk/store) rebuilds its value from the BPF mirror, which has no
// slot for sync-only fields — without the memo it resends (0,0) and the
// peer's stamped copy goes back to the default table. These cells drive the
// real QueueSessionV4, syncSweep and takeDeleteGenV4, mirroring the #9412
// close-class cells.

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func installTableFixture9752(t *testing.T, sessionID uint64) (*SessionSync, *mockSweepDP, dataplane.SessionKey) {
	t.Helper()
	base := monotonicSeconds()
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 47912, DstPort: 5203}
	dp := &mockSweepDP{
		// As the BPF mirror holds it: InstallTable* are sync-only, so always 0.
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {State: dataplane.SessStateEstablished, Created: base - 5, SessionID: sessionID},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base - 10
	// Post-discovery steady state: these cells pin MEMO behavior, so the
	// fence must pass (its own cells cover withhold/discovery).
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
	return ss, dp, key
}

// sentTablesV4_9752 drains the send queue and returns each v4 session frame's
// installing-table identity.
func sentTablesV4_9752(t *testing.T, ss *SessionSync) [][2]uint32 {
	t.Helper()
	var out [][2]uint32
	for len(ss.sendCh) > 0 {
		msg := <-ss.sendCh
		if len(msg) < syncHeaderSize || msg[4] != syncMsgSessionV4 {
			continue
		}
		_, val, ok := decodeSessionV4Payload(msg[syncHeaderSize:])
		if !ok {
			t.Fatal("undecodable queued v4 session frame")
		}
		out = append(out, [2]uint32{val.InstallTableDomain, val.InstallTableCheck})
	}
	return out
}

func sweepOnce9752(t *testing.T, ss *SessionSync, dp *mockSweepDP, key dataplane.SessionKey) [][2]uint32 {
	t.Helper()
	if v := dp.v4sessions[key]; v.InstallTableDomain != 0 || v.InstallTableCheck != 0 {
		t.Fatal("FIXTURE: the mirror row must carry (0,0), or the sweep could copy the stamp from the row")
	}
	ss.syncSweep()
	return sentTablesV4_9752(t, ss)
}

func TestSweepResendKeepsTheAnnouncedInstallTable9752(t *testing.T) {
	ss, dp, key := installTableFixture9752(t, 77)
	upd := dp.v4sessions[key]
	upd.InstallTableDomain, upd.InstallTableCheck = 525590, 3318534811
	ss.QueueSessionV4(key, upd)
	if got := sentTablesV4_9752(t, ss); len(got) != 1 || got[0] != [2]uint32{525590, 3318534811} {
		t.Fatalf("FIXTURE: the delta-path Update must queue one frame with the stamp, got %v", got)
	}
	if got := sweepOnce9752(t, ss, dp, key); len(got) != 1 || got[0] != [2]uint32{525590, 3318534811} {
		t.Fatalf("#9752: the sweep resent the stamped session with %v, not the identity "+
			"already sent for this incarnation; the peer's copy goes back to the default table", got)
	}
}

func TestReusedTupleNeverInheritsTheOldInstallTable9752(t *testing.T) {
	ss, dp, key := installTableFixture9752(t, 77)
	old := dp.v4sessions[key]
	old.InstallTableDomain, old.InstallTableCheck = 525590, 3318534811
	ss.QueueSessionV4(key, old)
	_ = sentTablesV4_9752(t, ss)
	reused := dp.v4sessions[key]
	reused.SessionID = 78 // the tuple reopened: a new incarnation
	dp.v4sessions[key] = reused
	if got := sweepOnce9752(t, ss, dp, key); len(got) != 1 || got[0] != [2]uint32{0, 0} {
		t.Fatalf("#9752: a reused tuple (new SessionID) was sent with %v; its live new "+
			"session would resolve in the old installation's table", got)
	}
}

func TestNoSessionIdentityNeverRecordsOrApplies9752(t *testing.T) {
	ss, dp, key := installTableFixture9752(t, 0)
	v := dp.v4sessions[key]
	v.InstallTableDomain, v.InstallTableCheck = 525590, 3318534811
	ss.QueueSessionV4(key, v)
	_ = sentTablesV4_9752(t, ss)
	if got := sweepOnce9752(t, ss, dp, key); len(got) != 1 || got[0] != [2]uint32{0, 0} {
		t.Fatalf("#9752: with no incarnation identity (SessionID 0) the sweep must send (0,0), "+
			"never a guessed stamp; got %v", got)
	}
}

func TestDeleteEvictsTheInstallTableMemo9752(t *testing.T) {
	ss, dp, key := installTableFixture9752(t, 77)
	v := dp.v4sessions[key]
	v.InstallTableDomain, v.InstallTableCheck = 525590, 3318534811
	ss.QueueSessionV4(key, v)
	_ = sentTablesV4_9752(t, ss)
	_ = ss.takeDeleteGenV4(key)
	if got := sweepOnce9752(t, ss, dp, key); len(got) != 1 || got[0] != [2]uint32{0, 0} {
		t.Fatalf("#9752: after the session's delete the memo must be gone, but the sweep sent %v", got)
	}
}
