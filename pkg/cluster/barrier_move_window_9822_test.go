package cluster

import (
	"strings"
	"testing"
	"time"
)

// waitForBarrierWaiter9822 blocks until a barrier has registered its waiter.
func waitForBarrierWaiter9822(t *testing.T, ss *SessionSync) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ss.barrierWaitMu.Lock()
		n := len(ss.barrierWaiters)
		ss.barrierWaitMu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("FIXTURE: no barrier waiter registered within 3s")
}

// #9822: a barrier that registers BETWEEN the epoch bump and the waiter sweep
// reported a DISCONNECT instead of a fence.
//
// The stream-move handling is deliberately two steps: noteStreamConnLocked bumps
// the epoch under writeMu, the caller releases writeMu, and onStreamMoved then
// sweeps every pending waiter (all three callers do this — sync_conn_write.go,
// sync_bulk.go and captureBarrierFenceForBulk). WaitForPeerBarrier tells a fence
// from a disconnect by comparing the epoch it captured at start: a change means
// fenced, no change plus no ACK means the connection went away.
//
// That inference has a hole exactly one window wide. A barrier starting after
// the bump but before the sweep captures the ALREADY-BUMPED epoch, so it sees no
// change; then the sweep closes its waiter, and it reports a disconnect that did
// not happen. Under a loaded `make test` this surfaced as
// TestAStoreWalkRePrimeDischargesTheFence_9508 failing with "session sync
// disconnected during barrier wait seq=2", with the sweep's own
// "released_barrier_waiters=1" logged immediately before it (#9822).
//
// The caller's remedy for a fenced barrier is to re-prime and retry; its remedy
// for a disconnect is not. So the misreport is not cosmetic.
func TestABarrierInsideTheStreamMoveWindowIsFencedNotDisconnected_9822(t *testing.T) {
	ss := dualSyncWith9508(t, &mockSweepDP{})
	fab0, fab1 := newHeldConn9508("fab0"), newHeldConn9508("fab1")
	ss.installConn(1, fab1)
	ss.QueueSessionV4(key9508(), val9508())
	waitForFrame9508(t, fab1, syncMsgSessionV4)

	ss.installConn(0, fab0)

	// The window, opened deliberately. Every caller bumps the epoch under writeMu,
	// RELEASES writeMu, and only then sweeps — so the sweep can land arbitrarily
	// late. Here it is held back while the fence is discharged by an ACKed
	// re-prime, which is what makes the next barrier admissible at all.
	ss.writeMu.Lock()
	moved := ss.noteStreamConnLocked(fab0)
	ss.writeMu.Unlock()
	if !moved {
		t.Fatal("FIXTURE: installing a second connection must move the ordered stream")
	}
	if !ss.barrierFenced() {
		t.Fatal("FIXTURE: the epoch bump must leave barriers fenced until a re-prime is acked")
	}
	ss.dischargeBarrierFence(ss.fence.epoch.Load() + 1)
	if ss.barrierFenced() {
		t.Fatal("FIXTURE: the discharge must admit the next barrier")
	}

	// A barrier starts INSIDE the window and captures the already-bumped epoch.
	errCh := make(chan error, 1)
	go func() { errCh <- ss.WaitForPeerBarrier(3 * time.Second) }()
	waitForBarrierWaiter9822(t, ss)

	// Now the sweep runs, closing that waiter.
	ss.onStreamMoved(false)

	var err error
	select {
	case err = <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("FIXTURE: WaitForPeerBarrier did not return within 5s")
	}
	if err == nil {
		t.Fatal("FIXTURE: a barrier swept by a stream move must not succeed")
	}
	if strings.Contains(err.Error(), "disconnected during barrier wait") {
		t.Errorf("#9822: a barrier released by the stream-move sweep reported a DISCONNECT: %v. "+
			"Nothing disconnected — onStreamMoved closed its waiter. It captured the epoch AFTER the bump, "+
			"so the epoch comparison cannot see the fence, and the caller is told to handle a lost connection "+
			"instead of re-priming and retrying", err)
	}
}
