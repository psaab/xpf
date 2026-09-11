package cluster

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9626: the cold-prime obligation (needColdPrime) was discharged by a LOCAL
// write and was an unversioned boolean.
//
//   - Item 1. doBulkSync returning nil means the frames through BulkEnd were
//     WRITTEN. A fabric that dies after the kernel took them, but before the
//     peer consumed them, left the debt cleared and the peer's table empty.
//     Measured on master 538a89100: after a completed bulk with no BulkAck,
//     needColdPrime was already false.
//   - Item 2. A success path cleared the flag with Store(false), outside s.mu,
//     after its bulk. A reboot classified while that bulk ran re-armed the flag,
//     and the older bulk's success then cleared the newer debt.
//
// The debt is now discharged only by the peer's BulkAck for a bulk, and only if
// no arm has happened since that bulk STARTED. Each arm bumps coldPrimeGen under
// s.mu. The bulk records the generation it was sent to pay, and the ack compares
// the two under s.mu. Because the discharge now waits for the peer, the sweep's
// owed re-drive does not re-send while the ack for the current debt is younger
// than BulkAckPendingRetryAfter.

// epochPayload9626 is a BulkAck payload for epoch.
func epochPayload9626(epoch uint64) []byte {
	var p [8]byte
	binary.LittleEndian.PutUint64(p[:], epoch)
	return p[:]
}

// primeFixture9626 is a primary with one session to send, and the cold prime
// armed by the first install after a full disconnect.
func primeFixture9626(t *testing.T) (*SessionSync, *bulkCaptureConn) {
	t.Helper()
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.SetRuntime(&mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 7, 1}, DstIP: [4]byte{10, 0, 8, 1}, Protocol: 6, SrcPort: 1200, DstPort: 80}: {IngressZone: 2},
		},
		sessionCounter: 1,
	})
	ss.IsPrimaryFn = func() bool { return true }
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	if d := ss.installConn(0, conn); !d.shouldColdPrime || !ss.needColdPrime.Load() {
		t.Fatalf("setup: the first install after a full disconnect must arm the cold prime (%+v)", d)
	}
	ss.lastSweepTime = monotonicSeconds()
	return ss, conn
}

// sweepBulk9626 runs one sweep tick and returns the pending epoch of the bulk it
// sent. It fails the test if the tick sent no bulk.
func sweepBulk9626(t *testing.T, ss *SessionSync) uint64 {
	t.Helper()
	before := ss.stats.BulkSyncs.Load()
	ss.syncSweep()
	if got := ss.stats.BulkSyncs.Load(); got != before+1 {
		t.Fatalf("the sweep tick sent %d bulks, want 1", got-before)
	}
	epoch, _, ok := ss.PendingBulkAck()
	if !ok {
		t.Fatal("a completed bulk left no pending ack")
	}
	return epoch
}

func TestOwedColdPrimeStaysOwedUntilThePeerAcks_9626(t *testing.T) {
	ss, conn := primeFixture9626(t)
	epoch := sweepBulk9626(t, ss)

	if !ss.needColdPrime.Load() {
		t.Fatal("#9626 item 1: the owed cold prime was discharged by the WRITE of its bulk; a fabric that dies " +
			"before the peer consumes the frames leaves the peer's table empty with nothing owed")
	}
	// An ack for some other epoch is not this bulk's receipt (#9177).
	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch+1))
	if !ss.needColdPrime.Load() {
		t.Fatal("an ack for a different epoch discharged the owed cold prime")
	}
	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch))
	if ss.needColdPrime.Load() {
		t.Fatal("#9626: the peer acknowledged the bulk sent for the debt, and the debt is still owed")
	}
}

func TestAnAckCannotDischargeADebtArmedAfterItsBulkStarted_9626(t *testing.T) {
	ss, c0 := primeFixture9626(t)
	epoch := sweepBulk9626(t, ss)
	stamp := ss.pendingBulkOwed.Load()

	// A NEW peer incarnation supersedes fabric 0 before the first bulk's ack
	// arrives: a real arm, through installConn's supersession edge.
	c0b := newBulkCaptureConn()
	t.Cleanup(func() { c0b.Close() })
	ss.installConn(0, c0b)
	if got := ss.coldPrimeOwedGen(); got == 0 || got == stamp {
		t.Fatalf("attribution: the supersession did not re-arm under a new generation (owed gen %d, bulk stamp %d)", got, stamp)
	}

	// The OLD bulk's ack now arrives. It paid the old debt, not this one.
	ss.handleMessage(c0, syncMsgBulkAck, epochPayload9626(epoch))
	if !ss.needColdPrime.Load() {
		t.Fatal("#9626 item 2: an ack for a bulk that started before the latest arm discharged that newer debt; " +
			"the replacement's table is never sent")
	}

	// The newer debt is still paid off normally: the next re-drive's ack clears it.
	epoch2 := sweepBulk9626(t, ss)
	ss.handleMessage(c0b, syncMsgBulkAck, epochPayload9626(epoch2))
	if ss.needColdPrime.Load() {
		t.Fatal("the re-drive sent for the newer debt was acknowledged, and the debt is still owed")
	}
}

func TestSweepDoesNotRebulkWhileTheAckForThisDebtIsYoung_9626(t *testing.T) {
	ss, conn := primeFixture9626(t)
	epoch := sweepBulk9626(t, ss)

	for i := 0; i < 3; i++ {
		ss.syncSweep()
	}
	if got := ss.stats.BulkSyncs.Load(); got != 1 {
		t.Fatalf("#9626: the sweep re-sent the owed cold prime %d times while the ack for it was still young; "+
			"waiting for the peer must not become a bulk every tick", got-1)
	}

	// Past the bound the ack is treated as lost, and the bulk goes again.
	ss.pendingBulkAckSince.Store(time.Now().Add(-(BulkAckPendingRetryAfter + time.Second)).UnixNano())
	epoch2 := sweepBulk9626(t, ss)
	if epoch2 == epoch {
		t.Fatalf("the re-drive past the bound reused epoch %d", epoch)
	}

	// The lost bulk's late ack is not the receipt for the resend.
	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch))
	if !ss.needColdPrime.Load() {
		t.Fatal("a late ack for the bulk the re-drive replaced discharged the debt")
	}
	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch2))
	if ss.needColdPrime.Load() {
		t.Fatal("the re-drive's own ack did not discharge the debt")
	}
}

// midBulkDP9626 runs during once, inside the bulk's v4 store walk: after the
// BulkStart is written and before the bulk records its pending ack. It overrides
// Sessions so the store the bulk walks is built over this wrapper, not the inner
// mock.
type midBulkDP9626 struct {
	*mockSweepDP
	during func()
}

func (m *midBulkDP9626) Sessions() dataplane.SessionStore {
	return dataplane.NewDataPlaneSessionStore(m)
}

func (m *midBulkDP9626) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return m.mockSweepDP.IterateSessions(func(k dataplane.SessionKey, v dataplane.SessionValue) bool {
		if d := m.during; d != nil {
			m.during = nil
			d()
		}
		return fn(k, v)
	})
}

func (m *midBulkDP9626) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return m.IterateSessions(fn)
}

// A reboot classified WHILE the bulk is on the wire is a newer debt than the one
// that bulk started for. The stamp is taken when the bulk starts, not when it
// records its pending ack, so that bulk's ack cannot pay the newer debt.
func TestAnArmDuringTheBulkIsNotPaidByThatBulk_9626(t *testing.T) {
	ss, conn := primeFixture9626(t)
	dp := &midBulkDP9626{mockSweepDP: &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 7, 1}, DstIP: [4]byte{10, 0, 8, 1}, Protocol: 6, SrcPort: 1200, DstPort: 80}: {IngressZone: 2},
		},
		sessionCounter: 1,
	}}
	var armedGen uint64
	dp.during = func() {
		ss.mu.Lock()
		ss.armColdPrimeLocked()
		armedGen = ss.coldPrimeGen.Load()
		ss.mu.Unlock()
	}
	ss.SetRuntime(dp)

	epoch := sweepBulk9626(t, ss)
	if armedGen == 0 {
		t.Fatal("attribution: the mid-bulk arm never ran, so this cell would not isolate the start-time stamp")
	}
	if stamp := ss.pendingBulkOwed.Load(); stamp == armedGen {
		t.Fatalf("#9626: the bulk was stamped with the debt armed WHILE it ran (generation %d); it must carry the debt it started for", stamp)
	}
	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch))
	if !ss.needColdPrime.Load() {
		t.Fatal("#9626 item 2: the ack for a bulk that started before a reboot was classified discharged the reboot's debt")
	}
}

// Negative control for the stamp: a bulk sent while NO cold prime was owed paid
// nothing, so its ack cannot discharge a debt armed while it was in flight.
func TestAnAckForABulkThatPaidNoDebtDischargesNothing_9626(t *testing.T) {
	ss, conn := primeFixture9626(t)
	ss.needColdPrime.Store(false) // steady state: primed and acked earlier

	if err := ss.BulkSync(); err != nil {
		t.Fatalf("routine bulk: %v", err)
	}
	epoch, _, ok := ss.PendingBulkAck()
	if !ok || ss.pendingBulkOwed.Load() != 0 {
		t.Fatalf("setup: a bulk sent with nothing owed must be pending and carry stamp 0 (pending=%v stamp=%d)",
			ok, ss.pendingBulkOwed.Load())
	}
	ss.mu.Lock()
	ss.armColdPrimeLocked()
	ss.mu.Unlock()

	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch))
	if !ss.needColdPrime.Load() {
		t.Fatal("#9626: the ack for a bulk that paid no debt discharged a debt armed while it was in flight")
	}
}
