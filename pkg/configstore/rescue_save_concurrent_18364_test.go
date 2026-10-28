package configstore

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// TestConcurrentSaveRescueConfigUniqueMonotonicGenerations_18364 proves
// that concurrent SaveRescueConfig calls each claim a unique, monotonically
// consumed generation (#18364). Before the fix the save claimed rescueSeq
// under s.mu.RLock only, so concurrent saves could read the same pre-claim
// value and mint duplicate generations: the supersede check then saw equal
// generations for distinct snapshots and both writers proceeded, letting an
// older snapshot overwrite a newer one, and the race detector flagged the
// unsynchronized increment itself.
//
// All saves are released together and held at rescueWriteBarrier after
// claiming their generation. That ensures the complete concurrent batch has
// claimed before any writer can apply its generation, making both the
// generation count and the single-winner assertion deterministic.
func TestConcurrentSaveRescueConfigUniqueMonotonicGenerations_18364(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SyncApply("system { host-name rescue-18364; }", nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}

	const savers = 16
	reached := make(chan struct{}, savers)
	release := make(chan struct{})
	var releaseOnce sync.Once
	oldBarrier := rescueWriteBarrier
	rescueWriteBarrier = func() {
		reached <- struct{}{}
		<-release
	}
	defer func() {
		releaseOnce.Do(func() { close(release) })
		rescueWriteBarrier = oldBarrier
	}()

	start := make(chan struct{})
	errs := make(chan error, savers)
	var wg sync.WaitGroup
	for range savers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.SaveRescueConfig()
		}()
	}
	close(start)

	for range savers {
		select {
		case <-reached:
		case <-time.After(60 * time.Second):
			releaseOnce.Do(func() { close(release) })
			wg.Wait()
			t.Fatal("concurrent SaveRescueConfig calls did not reach rescueWriteBarrier")
		}
	}
	claimed := s.rescueSeqSnapshot()
	releaseOnce.Do(func() { close(release) })
	wg.Wait()
	close(errs)

	var succeeded, superseded int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrRescueSaveSuperseded):
			superseded++
		default:
			t.Fatalf("concurrent SaveRescueConfig: unexpected error %v", err)
		}
	}
	if claimed != savers {
		t.Fatalf("rescueSeq=%d after %d concurrent claims, want %d "+
			"(a lost update consumed fewer generations than saves)",
			claimed, savers, savers)
	}
	if succeeded != 1 || superseded != savers-1 {
		t.Fatalf("concurrent saves: succeeded=%d superseded=%d, want 1 and %d "+
			"(duplicate generations let multiple saves write)",
			succeeded, superseded, savers-1)
	}
	if _, err := os.Stat(s.rescuePath()); err != nil {
		t.Fatalf("rescue.conf missing after concurrent saves: %v", err)
	}

	// The next save claims the next generation and succeeds.
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("SaveRescueConfig after concurrent batch: %v", err)
	}
	if got := s.rescueSeqSnapshot(); got != savers+1 {
		t.Fatalf("rescueSeq=%d after follow-up save, want %d; generations must stay monotonic",
			got, savers+1)
	}
}
