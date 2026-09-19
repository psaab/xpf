package daemon

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #10387: explicit demotion must refuse the drain while a cold-prime debt is
// owed with no bulk pending or acked, instead of running a vacuous barrier.
//
// Fixture: a real loopback pair whose post-connect auto-bulk fails cleanly
// (nil session store, "session store not ready" before any write), leaving
// the full-disconnect edge's debt armed with nothing pending — the
// bulk-source-failure + drain-during-retry-wait window.
//
// Fail-on-revert: without the gate the barrier's real ack succeeds and
// prepareUserspaceManualFailover returns nil, so the want-error assertion
// below fails.
func TestDemotionRefusedWhenColdPrimeOwedWithoutPendingBulk_10387(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ss := connectedSyncPairForDrainTest(t, ctx)
	if _, _, ok := ss.PendingBulkAck(); ok {
		t.Fatal("FIXTURE: the pair's auto-bulk must have failed cleanly, leaving nothing pending")
	}

	d := &Daemon{sessionSync: ss, userspaceDemotionPrepUntil: make(map[int]time.Time)}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	t.Cleanup(func() { d.syncPrimeRetryGen.Add(1) })

	retryEntered := make(chan struct{})
	retryRelease := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	d.syncPrimeRetryBeforeSleepForTest = func() {
		enteredOnce.Do(func() {
			close(retryEntered)
			<-retryRelease
		})
	}
	t.Cleanup(func() { releaseOnce.Do(func() { close(retryRelease) }) })
	d.startSessionSyncPrimeRetry(d.syncPrimeRetryGen.Load())
	select {
	case <-retryEntered:
		// The retry goroutine is held at the sleep boundary. The drain below
		// therefore lands before the retry can make another bulk attempt.
	case <-time.After(time.Second):
		t.Fatal("FIXTURE: bulk-prime retry loop did not reach its sleep boundary")
	}
	err := d.prepareUserspaceManualFailover(0)
	releaseOnce.Do(func() { close(retryRelease) })
	if err == nil {
		t.Fatal("#10387: explicit demotion succeeded with a cold prime owed and no bulk pending or acked; " +
			"the barrier ack proves nothing about the peer's table")
	}
	if !strings.Contains(err.Error(), "cold prime") {
		t.Fatalf("#10387: demotion refused, but not for the cold-prime debt: %v", err)
	}
	if !cluster.IsRetryablePreFailoverError(err) {
		t.Fatalf("#10387: a cold-prime refusal must be retryable (re-prime and retry): %v", err)
	}
}

// #10387 control: a primed peer (debt discharged) keeps the historical drain.
func TestDemotionProceedsWhenPrimed_10387(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ss := connectedSyncPairForDrainTest(t, ctx)
	ss.DischargeColdPrimeForTesting()

	d := &Daemon{sessionSync: ss, userspaceDemotionPrepUntil: make(map[int]time.Time)}
	if err := d.prepareUserspaceManualFailover(0); err != nil {
		t.Fatalf("#10387 control: primed explicit demotion must still succeed: %v", err)
	}
}

// #10387 contract: an owed debt with its current-generation bulk pending
// keeps the ordered barrier path; only an owed debt with no bulk refuses.
func TestDemotionProceedsWithPendingColdPrime_10387(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ss := connectedSyncPairForDrainTest(t, ctx)
	if !ss.SetPendingColdPrimeForTesting() {
		t.Fatal("FIXTURE: connected pair must owe a cold prime before publishing pending state")
	}

	d := &Daemon{sessionSync: ss, userspaceDemotionPrepUntil: make(map[int]time.Time)}
	if err := d.prepareUserspaceManualFailover(0); err != nil {
		t.Fatalf("#10387: current-generation pending bulk must keep demotion barrier admissible: %v", err)
	}
}
