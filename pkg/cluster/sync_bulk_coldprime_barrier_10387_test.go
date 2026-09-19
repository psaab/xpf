package cluster

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #10387: a source failure with no queued bulk leaves an authoritative
// cold-prime debt. The daemon's drain gate consumes this predicate before it
// can write a Barrier marker; the generic ordered-barrier primitive remains
// usable for callers that are not performing a demotion drain.
//
// Fail-on-revert: the daemon-level drain cell exercises the refusal itself;
// this cell pins the generation-safe needColdPrime/pendingBulkOwed state that
// the gate must consume.
func TestColdPrimeOwedWithoutPendingBulkIsObservable_10387(t *testing.T) {
	ss := dualSync9508(t)
	c := newHeldConn9508("fab0")
	if d := ss.installConn(0, c); !d.shouldColdPrime || !ss.needColdPrime.Load() {
		t.Fatalf("FIXTURE: the first install after a full disconnect must arm the cold prime (%+v)", d)
	}
	if _, _, ok := ss.PendingBulkAck(); ok {
		t.Fatal("FIXTURE: no bulk was ever queued, so no bulk may be pending")
	}
	if !ss.ColdPrimeOwedWithoutPendingBulk() {
		t.Fatal("FIXTURE: an armed debt with no pending bulk must read as owed-without-bulk")
	}
}

// #10387 generation guard: an arm racing the pending-state sample cannot make
// an older bulk satisfy the newer cold-prime debt.
func TestColdPrimeOwedWithoutPendingBulkRejectsStalePendingGeneration_10387(t *testing.T) {
	ss, _ := primeFixture9626(t)
	sweepBulk9626(t, ss)
	staleStamp := ss.pendingBulkOwed.Load()
	var newStamp uint64
	ss.testAfterColdPrimePendingRead = func() {
		ss.testAfterColdPrimePendingRead = nil
		ss.mu.Lock()
		ss.armColdPrimeLocked()
		newStamp = ss.coldPrimeGen.Load()
		ss.mu.Unlock()
	}
	if !ss.ColdPrimeOwedWithoutPendingBulk() {
		t.Fatal("#10387: a pending bulk must not satisfy a debt armed after the pending-state sample")
	}
	if newStamp == 0 || newStamp == staleStamp {
		t.Fatalf("FIXTURE: hook must re-arm a newer debt during the predicate (old=%d new=%d)", staleStamp, newStamp)
	}
}

// #10387 control: a primed peer (debt discharged) keeps the historical barrier.
func TestPrimedBarrierUnaffected_10387(t *testing.T) {
	ss := dualSync9508(t)
	c := newHeldConn9508("fab0")
	ss.installConn(0, c)
	ss.dischargeColdPrime(ss.coldPrimeOwedGen())
	if ss.needColdPrime.Load() {
		t.Fatal("FIXTURE: the discharge must clear the debt")
	}
	if ss.ColdPrimeOwedWithoutPendingBulk() {
		t.Fatal("FIXTURE: a discharged debt must not read as owed-without-bulk")
	}
	if err := barrierOutcome9508(t, ss, c); err != nil {
		t.Fatalf("#10387 control: a primed barrier must still succeed: %v", err)
	}
}

// #10387 contract: an owed debt WITH its bulk in flight keeps the ordered
// barrier — the barrier queues behind the bulk's frames, so its ack proves
// the peer processed them. Only the absence of any qualifying bulk refuses.
func TestOwedWithPendingBulkKeepsOrderedBarrier_10387(t *testing.T) {
	ss := dualSync9508(t)
	ss.SetRuntime(&mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 7, 1}, DstIP: [4]byte{10, 0, 8, 1}, Protocol: 6, SrcPort: 1200, DstPort: 80}: {IngressZone: 2},
		},
		sessionCounter: 1,
	})
	ss.IsPrimaryFn = func() bool { return true }
	c := newHeldConn9508("fab0")
	if d := ss.installConn(0, c); !d.shouldColdPrime || !ss.needColdPrime.Load() {
		t.Fatalf("FIXTURE: the first install after a full disconnect must arm the cold prime (%+v)", d)
	}
	ss.lastSweepTime = monotonicSeconds()
	epoch := sweepBulk9626(t, ss)
	if !ss.needColdPrime.Load() {
		t.Fatal("FIXTURE: the debt must stay owed until the peer acks (#9626)")
	}
	if stamp := ss.pendingBulkOwed.Load(); stamp == 0 || stamp != ss.coldPrimeOwedGen() {
		t.Fatalf("FIXTURE: the pending bulk must carry the current debt (epoch=%d stamp=%d)", epoch, stamp)
	}
	if !ss.coldPrimeAckAwaited() {
		t.Fatal("FIXTURE: a just-sent bulk for the current debt must read as ack-awaited")
	}
	if ss.ColdPrimeOwedWithoutPendingBulk() {
		t.Fatal("FIXTURE: an owed debt WITH a qualifying pending bulk must not read as owed-without-bulk")
	}
	if err := barrierOutcome9508(t, ss, c); err != nil {
		t.Fatalf("#10387: an owed debt with its bulk in flight must keep the ordered barrier: %v", err)
	}
	barrierQueued := false
	for _, f := range c.frames() {
		if f.typ == syncMsgBarrier {
			barrierQueued = true
			break
		}
	}
	if !barrierQueued {
		t.Fatal("#10387: the ordered barrier was never queued, so the success says nothing about the pending case")
	}
}

// #10387: a survivor clear/re-drive cannot pass the cold-prime gate after it
// has observed a qualifying pending bulk. The replacement waits for the same
// bulk-send admission that queues the barrier marker.
func TestBarrierAdmissionSerializesSurvivorReplacement_10387(t *testing.T) {
	ss := dualSync9508(t)
	c := newHeldConn9508("fab0")
	if d := ss.installConn(0, c); !d.shouldColdPrime || !ss.needColdPrime.Load() {
		t.Fatalf("FIXTURE: the first install must arm the cold prime (%+v)", d)
	}
	owed := ss.coldPrimeOwedGen()
	ss.pendingBulkOwed.Store(owed)
	ss.pendingBulkAckEpoch.Store(1)
	ss.pendingBulkAckSince.Store(time.Now().UnixNano())

	reachedGate := make(chan struct{})
	releaseGate := make(chan struct{})
	ss.testAfterColdPrimeBarrierGate = func() {
		close(reachedGate)
		<-releaseGate
	}
	t.Cleanup(func() {
		select {
		case <-releaseGate:
		default:
			close(releaseGate)
		}
	})

	barrierDone := make(chan error, 1)
	go func() { barrierDone <- ss.WaitForPeerBarrierAfterColdPrimeGate(time.Second) }()
	select {
	case <-reachedGate:
	case <-time.After(time.Second):
		t.Fatal("FIXTURE: barrier did not reach its post-gate rendezvous")
	}

	replacementStarted := make(chan struct{})
	replacementDone := make(chan error, 1)
	ss.BulkSnapshotSource = func() (BulkSnapshot, error) {
		close(replacementStarted)
		return BulkSnapshot{}, nil
	}
	go func() {
		ss.bulkSendMu.Lock()
		ss.clearPendingBulkAck()
		err := ss.doBulkSyncWithBulkSend(true)
		ss.bulkSendMu.Unlock()
		replacementDone <- err
	}()
	select {
	case <-replacementStarted:
		t.Fatal("#10387: survivor replacement bulk started before the barrier admission released")
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseGate)
	waitForFrame9508(t, c, syncMsgBarrier)
	var seq uint64
	for _, f := range c.frames() {
		if f.typ == syncMsgBarrier && len(f.payload) >= 8 {
			seq = binary.LittleEndian.Uint64(f.payload[:8])
			break
		}
	}
	if seq == 0 {
		t.Fatal("FIXTURE: barrier frame had no sequence")
	}
	var ack [24]byte
	binary.LittleEndian.PutUint64(ack[:8], seq)
	ss.handleMessage(c, syncMsgBarrierAck, ack[:])
	if err := <-barrierDone; err != nil {
		t.Fatalf("#10387: serialized barrier failed: %v", err)
	}
	select {
	case err := <-replacementDone:
		if err != nil {
			t.Fatalf("#10387: replacement bulk failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FIXTURE: survivor replacement did not run after barrier admission")
	}
	frames := c.frames()
	barrierIndex, bulkStartIndex := -1, -1
	for i, f := range frames {
		switch f.typ {
		case syncMsgBarrier:
			if barrierIndex == -1 {
				barrierIndex = i
			}
		case syncMsgBulkStart:
			if bulkStartIndex == -1 {
				bulkStartIndex = i
			}
		}
	}
	if barrierIndex < 0 || bulkStartIndex <= barrierIndex {
		t.Fatalf("#10387: barrier must reach the wire before replacement BulkStart (barrier=%d bulk_start=%d frames=%v)",
			barrierIndex, bulkStartIndex, frames)
	}
}

// #10387: a new cold-prime arm after the readiness sample must not let the
// gated barrier certify an incarnation that the sample did not cover.
func TestBarrierAdmissionRejectsColdPrimeRearm_10387(t *testing.T) {
	ss := dualSync9508(t)
	c := newHeldConn9508("fab0")
	if d := ss.installConn(0, c); !d.shouldColdPrime || !ss.needColdPrime.Load() {
		t.Fatalf("FIXTURE: the first install must arm the cold prime (%+v)", d)
	}
	owed := ss.coldPrimeOwedGen()
	ss.pendingBulkOwed.Store(owed)
	ss.pendingBulkAckEpoch.Store(1)
	ss.pendingBulkAckSince.Store(time.Now().UnixNano())
	ss.testAfterColdPrimeBarrierGate = func() {
		ss.testAfterColdPrimeBarrierGate = nil
		ss.mu.Lock()
		ss.armColdPrimeLocked()
		ss.mu.Unlock()
	}
	err := ss.WaitForPeerBarrierAfterColdPrimeGate(time.Second)
	if err == nil {
		t.Fatal("#10387: a cold-prime re-arm after the gate sample must reject the barrier")
	}
	for _, f := range c.frames() {
		if f.typ == syncMsgBarrier {
			t.Fatal("#10387: a generation-invalid barrier must not be written")
		}
	}
	ss.barrierWaitMu.Lock()
	waiters := len(ss.barrierWaiters)
	ss.barrierWaitMu.Unlock()
	if waiters != 0 {
		t.Fatalf("#10387: rejected generation must remove its barrier waiter (waiters=%d)", waiters)
	}
}

// #10387: the demotion-specific wrapper must refuse an owed debt with no
// qualifying bulk before writing a marker, clean up any waiter, and release its
// admission lock on the early return.
func TestBarrierWrapperRefusesOwedWithoutBulk_10387(t *testing.T) {
	ss := dualSync9508(t)
	c := newHeldConn9508("fab0")
	if d := ss.installConn(0, c); !d.shouldColdPrime || !ss.needColdPrime.Load() {
		t.Fatalf("FIXTURE: the first install must arm the cold prime (%+v)", d)
	}
	if _, _, pending := ss.PendingBulkAck(); pending {
		t.Fatal("FIXTURE: no qualifying bulk may be pending")
	}
	if !ss.ColdPrimeOwedWithoutPendingBulk() {
		t.Fatal("FIXTURE: the debt must be owed without pending bulk")
	}
	err := ss.WaitForPeerBarrierAfterColdPrimeGate(time.Second)
	if err == nil {
		t.Fatal("#10387: the gated barrier must refuse owed debt with no pending bulk")
	}
	if !strings.Contains(err.Error(), "cold prime owed without pending outbound bulk") {
		t.Fatalf("#10387: refusal returned the wrong error: %v", err)
	}
	for _, f := range c.frames() {
		if f.typ == syncMsgBarrier {
			t.Fatal("#10387: refusal must not write a barrier marker")
		}
	}
	ss.barrierWaitMu.Lock()
	waiters := len(ss.barrierWaiters)
	ss.barrierWaitMu.Unlock()
	if waiters != 0 {
		t.Fatalf("#10387: refusal must remove all barrier waiters (waiters=%d)", waiters)
	}
	if !ss.bulkSendMu.TryLock() {
		t.Fatal("#10387: refusal must release bulkSendMu")
	}
	ss.bulkSendMu.Unlock()
}
