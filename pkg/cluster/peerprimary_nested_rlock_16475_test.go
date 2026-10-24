package cluster

import (
	"sync"
	"testing"
	"time"
)

// #16475: PeerPrimaryRGs held m.mu.RLock while calling DataGroupIDs,
// which takes m.mu.RLock again. Go's sync.RWMutex prohibits recursive
// read locking: a writer queued between the two RLocks blocks the inner
// RLock, while the writer itself can never acquire because the outer
// RLock is never released — the cluster-manager mutex wedges for good
// (heartbeats, election, status all freeze until restart).
//
// This test drives the exact deadlock geometry against the real
// accessors: a reader runs PeerPrimaryRGs repeatedly while a writer
// churns m.mu.Lock, so a writer is routinely queued while the reader
// works. With the nested RLock the reader never finishes an iteration
// (and the writer never completes); with dataGroupIDsLocked under one
// outer RLock both make progress. Bounded at 5s per the acceptance
// criterion: a concurrent writer-plus-PeerPrimaryRGs loop runs 5s
// without stalling, and every participant must still be progressing
// at the end (a wedged loop stalls long before the window expires).
func TestPeerPrimaryRGsNoNestedRLock16475(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 100, 1: 90}),
		makeRG(1, true, map[int]int{0: 100, 1: 90}),
		makeRG(2, true, map[int]int{0: 100, 1: 90}),
	)
	m.UpdateConfig(cfg)
	m.SetPeerGroupStateForTesting(1, StatePrimary)
	m.SetPeerGroupStateForTesting(2, StateSecondary)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var readerIters, writerIters int64
	var mu sync.Mutex
	record := func(reader bool) {
		mu.Lock()
		if reader {
			readerIters++
		} else {
			writerIters++
		}
		mu.Unlock()
	}
	snapshot := func() (int64, int64) {
		mu.Lock()
		defer mu.Unlock()
		return readerIters, writerIters
	}

	// Reader: the real reconcile accessor, back-to-back.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			m.PeerPrimaryRGs()
			record(true)
		}
	}()

	// Writer: models handlePeerHeartbeat's m.mu.Lock churn queueing
	// behind the reader between its two RLocks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			m.mu.Lock()
			m.mu.Unlock()
			record(false)
		}
	}()

	// Acceptance: 5s of concurrent writer+reader without stalling.
	// Sample progress twice; both counters must strictly advance
	// across the second half of the window. A nested-RLock wedge
	// freezes both counters on the first queued writer.
	time.Sleep(2500 * time.Millisecond)
	r1, w1 := snapshot()
	time.Sleep(2500 * time.Millisecond)
	r2, w2 := snapshot()
	close(stop)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PeerPrimaryRGs/writer goroutines did not exit after stop: m.mu is wedged (#16475)")
	}

	if r2 <= r1 {
		t.Fatalf("PeerPrimaryRGs stalled under a queued writer: iterations %d -> %d (#16475 nested RLock wedge)", r1, r2)
	}
	if w2 <= w1 {
		t.Fatalf("m.mu writer stalled behind PeerPrimaryRGs: iterations %d -> %d (#16475 nested RLock wedge)", w1, w2)
	}
	if r2 == 0 || w2 == 0 {
		t.Fatalf("no progress at all: reader=%d writer=%d", r2, w2)
	}

	// Post-churn value sanity (single-threaded now): RG1 only, RG0
	// excluded, peer alive.
	rgs, alive := m.PeerPrimaryRGs()
	if !alive || len(rgs) != 1 || rgs[0] != 1 {
		t.Fatalf("PeerPrimaryRGs = %v, alive=%v; want [1], true", rgs, alive)
	}
}
