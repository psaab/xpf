package cluster

import (
	"testing"
	"time"
)

// #18028: ReconcileConnectionAuth used to snapshot the accepted-key ring
// BEFORE taking writeMu, the same snapshot-before-lock shape #18016 fixed
// in enforceStrictSessionAuth. Two reconciles that overlap a finalize make
// it fatal: the older pass parks between its snapshot and the lock, the
// finalize pass anchors the #16857 retired-key grace under the finalized
// ring, and the older pass then resumes with its stale set — under which
// the connection's PSK still looks accepted — and CLEARS the fresh anchor.
// The anchor stays zero, every later enforcement pass skips the connection,
// and the retired-key connection is never evicted.
//
// The fix snapshots under writeMu (one section for the whole batch), so a
// parked pass holds the lock across its snapshot and the finalize pass
// cannot anchor until the stale evaluation is finished — the clear lands
// before the anchor exists and is a no-op.

func TestRetirementGraceSurvivesConcurrentReconcileSnapshot18028(t *testing.T) {
	e := retiredEnd(t)
	provider := &gatedAcceptedKeysProvider18016{
		key:            []byte(retiredKeyA16857),
		accepted:       [][]byte{[]byte(retiredKeyA16857)},
		firstEntered:   make(chan struct{}),
		firstRelease:   make(chan struct{}),
		secondSnapshot: make(chan struct{}),
	}
	e.s.SetAuthProvider(provider)

	firstDone := make(chan struct{})
	go func() {
		e.s.ReconcileConnectionAuth("pre-finalize-commit")
		close(firstDone)
	}()
	select {
	case <-provider.firstEntered:
	case <-time.After(3 * time.Second):
		close(provider.firstRelease)
		t.Fatal("first reconcile did not reach the accepted-key snapshot")
	}

	// The gate makes it observable whether the parked reconcile took writeMu
	// before asking for accepted keys. With the #18028 ordering it holds the
	// lock here; on the old ordering it does not.
	firstHoldsWriteMu := !e.s.writeMu.TryLock()
	if !firstHoldsWriteMu {
		e.s.writeMu.Unlock()
	}
	provider.setRing([]byte(retiredKeyB16857), [][]byte{[]byte(retiredKeyB16857)})

	secondDone := make(chan struct{})
	go func() {
		e.s.ReconcileConnectionAuth("finalize")
		close(secondDone)
	}()

	if firstHoldsWriteMu {
		// The finalize reconcile cannot even snapshot until the parked pass
		// releases writeMu, so the gate must open first. Its anchor then
		// lands strictly AFTER the stale pass's evaluation is done, which is
		// the invariant that keeps the anchor alive.
		close(provider.firstRelease)
	} else {
		// Old ordering: the parked pass holds nothing, so the finalize
		// reconcile runs to completion while it waits and anchors the
		// retired-key grace. Releasing the gate afterwards lets the stale
		// pass clear that anchor — the defect this cell pins.
		select {
		case <-secondDone:
		case <-time.After(3 * time.Second):
			close(provider.firstRelease)
			t.Fatal("finalize reconcile did not complete while the stale pass was parked")
		}
		close(provider.firstRelease)
	}

	select {
	case <-firstDone:
	case <-time.After(3 * time.Second):
		t.Fatal("pre-finalize reconcile did not finish after the gate opened")
	}
	select {
	case <-secondDone:
	case <-time.After(3 * time.Second):
		t.Fatal("finalize reconcile did not finish")
	}

	e.s.writeMu.Lock()
	anchor := e.ac.strictGraceStart
	retired := e.ac.strictGraceRetired
	e.s.writeMu.Unlock()
	if anchor == 0 || !retired {
		t.Fatalf("fresh retirement grace was cleared by the concurrent stale-snapshot reconcile: "+
			"start=%d retired=%v", anchor, retired)
	}

	backdateGrace16857(e)
	if n := e.s.enforceStrictSessionAuth(); n != 1 {
		t.Fatalf("evicted %d connections after the concurrent retirement grace expired, want 1", n)
	}
	if connStillInstalled(e) {
		t.Fatal("retired-key connection survived past the concurrent retirement grace")
	}
}
