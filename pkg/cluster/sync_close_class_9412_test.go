package cluster

// #9412: the sender-side close-class memo. The live cluster measured the defect:
// a flow that opened and closed inside one 15 s sweep window sent Open(0), then
// Update(1), then a SWEEP RESEND FROM THE MIRROR with class 0, and the peer's
// closing copy went back to the established window. These cells drive the real
// QueueSessionV4, syncSweep, takeDeleteGenV4 and installClusterSyncedV4, using the
// #7842 sweep fixture shape: rows Created inside the window and behind the sweep
// clock.

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func closeClassFixture9412(t *testing.T, sessionID uint64) (*SessionSync, *mockSweepDP, dataplane.SessionKey) {
	t.Helper()
	base := monotonicSeconds()
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 47912, DstPort: 5203}
	dp := &mockSweepDP{
		// As the BPF mirror holds it: TCPCloseClass is sync-only, so always 0.
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {State: dataplane.SessStateEstablished, Created: base - 5, SessionID: sessionID},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base - 10
	return ss, dp, key
}

// sentClassesV4_9412 drains the send queue and returns each v4 session frame's close class.
func sentClassesV4_9412(t *testing.T, ss *SessionSync) []uint8 {
	t.Helper()
	var out []uint8
	for len(ss.sendCh) > 0 {
		msg := <-ss.sendCh
		if len(msg) < syncHeaderSize || msg[4] != syncMsgSessionV4 {
			continue
		}
		_, val, ok := decodeSessionV4Payload(msg[syncHeaderSize:])
		if !ok {
			t.Fatal("undecodable queued v4 session frame")
		}
		out = append(out, val.TCPCloseClass)
	}
	return out
}

func sweepOnce9412(t *testing.T, ss *SessionSync, dp *mockSweepDP, key dataplane.SessionKey) []uint8 {
	t.Helper()
	if dp.v4sessions[key].TCPCloseClass != 0 {
		t.Fatal("FIXTURE: the mirror row must carry class 0, or the sweep could copy the class from the row")
	}
	ss.syncSweep()
	return sentClassesV4_9412(t, ss)
}

func TestSweepResendKeepsTheAnnouncedCloseClass9412(t *testing.T) {
	ss, dp, key := closeClassFixture9412(t, 77)
	upd := dp.v4sessions[key]
	upd.TCPCloseClass = 1
	ss.QueueSessionV4(key, upd)
	if got := sentClassesV4_9412(t, ss); len(got) != 1 || got[0] != 1 {
		t.Fatalf("FIXTURE: the delta-path Update must queue one frame with class 1, got %v", got)
	}
	if got := sweepOnce9412(t, ss, dp, key); len(got) != 1 || got[0] != 1 {
		t.Fatalf("#9412: the sweep resent the closing session with close class %v, not the class 1 "+
			"already sent for this incarnation; the peer's copy goes back to the established window", got)
	}
}

func TestReusedTupleNeverInheritsTheOldCloseClass9412(t *testing.T) {
	ss, dp, key := closeClassFixture9412(t, 77)
	old := dp.v4sessions[key]
	old.TCPCloseClass = 3
	ss.QueueSessionV4(key, old)
	_ = sentClassesV4_9412(t, ss)
	reused := dp.v4sessions[key]
	reused.SessionID = 78 // the tuple reopened: a new incarnation
	dp.v4sessions[key] = reused
	if got := sweepOnce9412(t, ss, dp, key); len(got) != 1 || got[0] != 0 {
		t.Fatalf("#9412: a reused tuple (new SessionID) was sent with close class %v; its live new "+
			"session would be reaped early after a failover", got)
	}
}

func TestNoSessionIdentityNeverRecordsOrApplies9412(t *testing.T) {
	ss, dp, key := closeClassFixture9412(t, 0)
	v := dp.v4sessions[key]
	v.TCPCloseClass = 1
	ss.QueueSessionV4(key, v)
	_ = sentClassesV4_9412(t, ss)
	if got := sweepOnce9412(t, ss, dp, key); len(got) != 1 || got[0] != 0 {
		t.Fatalf("#9412: with no incarnation identity (SessionID 0) the sweep must send class 0, "+
			"never a guessed one; got %v", got)
	}
}

func TestDeleteEvictsTheCloseClassMemo9412(t *testing.T) {
	ss, dp, key := closeClassFixture9412(t, 77)
	v := dp.v4sessions[key]
	v.TCPCloseClass = 1
	ss.QueueSessionV4(key, v)
	_ = sentClassesV4_9412(t, ss)
	_ = ss.takeDeleteGenV4(key)
	if got := sweepOnce9412(t, ss, dp, key); len(got) != 1 || got[0] != 0 {
		t.Fatalf("#9412: after the session's delete the memo must be gone, but the sweep sent class %v", got)
	}
}

func TestCloseClassNeverRegressesWithinAnIncarnation9412(t *testing.T) {
	ss, dp, key := closeClassFixture9412(t, 77)
	rst := dp.v4sessions[key]
	rst.TCPCloseClass = 3
	ss.QueueSessionV4(key, rst)
	stale := dp.v4sessions[key]
	stale.TCPCloseClass = 1
	ss.QueueSessionV4(key, stale)
	if got := sentClassesV4_9412(t, ss); len(got) != 2 || got[0] != 3 || got[1] != 3 {
		t.Fatalf("#9412: close classes only progress within an incarnation; a later CLOSING frame after "+
			"RST must still send RST, got %v", got)
	}
}

func TestSweepResendKeepsTheAnnouncedCloseClassV6_9412(t *testing.T) {
	base := monotonicSeconds()
	key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 47913, DstPort: 5204}
	key.SrcIP[15], key.DstIP[15] = 1, 2
	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			key: {State: dataplane.SessStateEstablished, Created: base - 5, SessionID: 91},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base - 10
	upd := dp.v6sessions[key]
	upd.TCPCloseClass = 2
	ss.QueueSessionV6(key, upd)
	for len(ss.sendCh) > 0 {
		<-ss.sendCh
	}
	ss.syncSweep()
	var got []uint8
	for len(ss.sendCh) > 0 {
		msg := <-ss.sendCh
		if len(msg) < syncHeaderSize || msg[4] != syncMsgSessionV6 {
			continue
		}
		_, val, ok := decodeSessionV6Payload(msg[syncHeaderSize:])
		if !ok {
			t.Fatal("undecodable queued v6 session frame")
		}
		got = append(got, val.TCPCloseClass)
	}
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("#9412: the v6 sweep resent the closing session with close class %v, want 2", got)
	}
}

// frameCaptureConn records every frame BulkSync writes. writeMsg builds the whole
// frame and writes it in one call, so one Write is one frame.
type frameCaptureConn struct {
	net.Conn
	frames [][]byte
}

func (c *frameCaptureConn) SetDeadline(time.Time) error      { return nil }
func (c *frameCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *frameCaptureConn) SetWriteDeadline(time.Time) error { return nil }
func (c *frameCaptureConn) Write(b []byte) (int, error) {
	c.frames = append(c.frames, append([]byte(nil), b...))
	return len(b), nil
}

// The bulk window is the third send path. On the live cluster, a failover
// re-prime of the peer walked the mirror and sent class 0 for a session whose
// Update had already gone out.
func TestBulkResendKeepsTheAnnouncedCloseClass9412(t *testing.T) {
	ss, dp, key := closeClassFixture9412(t, 77)
	row := dp.v4sessions[key]
	row.IngressZone = 1
	dp.v4sessions[key] = row
	upd := row
	upd.TCPCloseClass = 2
	ss.QueueSessionV4(key, upd)
	for len(ss.sendCh) > 0 {
		<-ss.sendCh
	}
	conn := &frameCaptureConn{}
	ss.mu.Lock()
	ss.conn0 = conn
	ss.mu.Unlock()
	if err := ss.BulkSync(); err != nil {
		t.Fatalf("BulkSync failed: %v", err)
	}
	var got []uint8
	for _, f := range conn.frames {
		if len(f) < syncHeaderSize || f[4] != syncMsgSessionV4 {
			continue
		}
		_, val, ok := decodeSessionV4Payload(f[syncHeaderSize:])
		if !ok {
			t.Fatal("undecodable bulk v4 session frame")
		}
		got = append(got, val.TCPCloseClass)
	}
	if len(got) != 1 {
		t.Fatalf("FIXTURE: the bulk window must send the one mirror row, sent %d session frames", len(got))
	}
	if got[0] != 2 {
		t.Fatalf("#9412: the bulk window resent the closing session with close class %d, not the class 2 "+
			"already sent for this incarnation", got[0])
	}
}

// The one order identity cannot see: the OLD incarnation's own closing frame
// arriving after a reused tuple's newer frame. Redundant fabric connections can
// reorder (#5706). The receiver must refuse it by generation, so the live new
// session keeps its window. A CONTROL delivers the same two frames in order.
func TestLateOldIncarnationCloseFrameIsRefused9412(t *testing.T) {
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		Protocol: 6, SrcPort: 47912, DstPort: 5203}
	oldClosing := dataplane.SessionValue{State: dataplane.SessStateEstablished, SessionID: 77, TCPCloseClass: 1, Generation: 10}
	newOpen := dataplane.SessionValue{State: dataplane.SessStateEstablished, SessionID: 78, TCPCloseClass: 0, Generation: 20}

	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.installClusterSyncedV4(key, oldClosing)
	ss.installClusterSyncedV4(key, newOpen)
	if got := dp.v4sessions[key]; got.SessionID != 78 || got.TCPCloseClass != 0 {
		t.Fatalf("CONTROL: in-order delivery must leave the new incarnation stored, got id=%d class=%d",
			got.SessionID, got.TCPCloseClass)
	}
	if n := ss.stats.InstallsStaleIgnored.Load(); n != 0 {
		t.Fatalf("CONTROL: in-order delivery refused %d install(s)", n)
	}

	dp2 := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss2 := NewSessionSync(":0", "10.0.0.2:4785", dp2)
	ss2.installClusterSyncedV4(key, newOpen)
	if _, ok := dp2.v4sessions[key]; !ok {
		t.Fatal("FIXTURE: the new incarnation was never stored, so 'unchanged' below would prove nothing")
	}
	ss2.installClusterSyncedV4(key, oldClosing)
	if got := dp2.v4sessions[key]; got.SessionID != 78 || got.TCPCloseClass != 0 {
		t.Fatalf("#9412: the old incarnation's late closing frame overwrote the live new session "+
			"(id=%d class=%d); after a failover it would reap on the close window", got.SessionID, got.TCPCloseClass)
	}
	if n := ss2.stats.InstallsStaleIgnored.Load(); n != 1 {
		t.Fatalf("the late frame must be refused as stale by generation; InstallsStaleIgnored=%d", n)
	}
}

// The memo is bounded like the generation maps. At the cap a NEW record is not
// written, which fails toward class 0 (the pre-fix window, never an early reap).
// A key already recorded keeps being honoured and updated, so a flow that closed
// before the table filled still resends its class. Driven on the generic helper
// directly, with int keys, so the cell does not build 200000 session keys.
func TestCloseClassMemoIsBoundedAtTheGenerationCap9412(t *testing.T) {
	m := make(map[int]sentCloseClass, genGuardMapCap)
	for i := 0; i < genGuardMapCap; i++ {
		m[i] = sentCloseClass{sessionID: uint64(i + 1), class: 1}
	}

	fresh := uint8(2)
	stampCloseClassLocked(m, genGuardMapCap, 900001, &fresh)
	if _, grew := m[genGuardMapCap]; grew || len(m) != genGuardMapCap {
		t.Fatalf("#9412: the close-class memo grew past genGuardMapCap (len=%d)", len(m))
	}
	if fresh != 2 {
		t.Fatalf("a frame's own class must be sent unchanged when the memo is full, got %d", fresh)
	}

	existing := uint8(3) // key 7's own incarnation (sessionID 8) progresses to RST
	stampCloseClassLocked(m, 7, 8, &existing)
	if rec := m[7]; rec.class != 3 {
		t.Fatalf("#9412: at the cap an existing record must still progress, got class %d", rec.class)
	}
	resend := uint8(0)
	stampCloseClassLocked(m, 7, 8, &resend)
	if resend != 3 {
		t.Fatalf("#9412: at the cap a resend of a recorded incarnation must keep its class, got %d", resend)
	}
}
