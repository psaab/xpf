package daemon

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

func TestInterfaceLinkSnapshotDebounceCoalescesBurst11530(t *testing.T) {
	wake := make(chan string, 4)
	wake <- "ge-0-0-0"
	started := make(chan struct{})
	result := make(chan string, 1)
	go func() {
		close(started)
		name, ok := debounceInterfaceLinkSnapshot(context.Background(), wake, "ge-0-0-0", 40*time.Millisecond)
		if ok {
			result <- name
		}
	}()
	<-started
	time.Sleep(5 * time.Millisecond)
	wake <- "ge-0-0-1"
	time.Sleep(5 * time.Millisecond)
	wake <- "ge-0-0-2"
	select {
	case got := <-result:
		if got != "ge-0-0-2" {
			t.Fatalf("debounced link = %q, want newest burst member ge-0-0-2", got)
		}
	case <-time.After(time.Second):
		t.Fatal("link debounce did not finish after the quiet period")
	}
}

func TestInterfaceLinkSnapshotWorkerCancellationPreservesOwnerAndDebt11530(t *testing.T) {
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store: testStoreWithSetConfig(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		}),
	}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("hold applySem as unrelated owner: %v", err)
	}
	ownerHeld := true
	defer func() {
		if ownerHeld {
			d.applySem.Release(1)
		}
	}()

	d.interfaceLinkSnapshotPending.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	wake := make(chan string, 1)
	wake <- "ge-0-0-0"
	var workerWG sync.WaitGroup
	workerWG.Add(1)
	go func() {
		defer workerWG.Done()
		d.interfaceLinkSnapshotRefreshLoop(ctx, wake)
	}()
	done := make(chan struct{})
	go func() {
		workerWG.Wait()
		close(done)
	}()

	// Let the queued event pass its quiet-period debounce and reach the held
	// apply semaphore before shutdown cancels the worker.
	select {
	case <-done:
		t.Fatal("refresh worker exited before cancellation")
	case <-time.After(interfaceLinkSnapshotDebounce + 250*time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh worker remained joined behind an unrelated applySem owner after cancellation")
	}
	if !d.InterfaceLinkSnapshotPending() {
		t.Fatal("cancellation was treated as successful refresh convergence and cleared retry debt")
	}
	if d.applySem.TryAcquire(1) {
		d.applySem.Release(1)
		t.Fatal("canceled refresh consumed or released the unrelated applySem owner's permit")
	}

	// Positive control: with authority available, the worker traverses the
	// active-config path once; with no dataplane published yet, it must not
	// claim a snapshot publication or leave false retry debt.
	d.applySem.Release(1)
	ownerHeld = false
	liveCtx, liveCancel := context.WithCancel(context.Background())
	t.Cleanup(liveCancel)
	liveWake := make(chan string, 1)
	liveWake <- "ge-0-0-0"
	var liveWG sync.WaitGroup
	liveWG.Add(1)
	go func() {
		defer liveWG.Done()
		d.interfaceLinkSnapshotRefreshLoop(liveCtx, liveWake)
	}()
	liveDone := make(chan struct{})
	go func() {
		liveWG.Wait()
		close(liveDone)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for d.InterfaceLinkSnapshotPending() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if d.InterfaceLinkSnapshotPending() {
		liveCancel()
		select {
		case <-liveDone:
		case <-time.After(time.Second):
			t.Fatal("positive-control worker did not join after cancellation")
		}
		t.Fatal("uncanceled worker did not complete its refresh attempt once applySem became available")
	}
	liveCancel()
	select {
	case <-liveDone:
	case <-time.After(time.Second):
		t.Fatal("positive-control worker did not join after cancellation")
	}
	if d.interfaceLinkSnapshotManager() != nil {
		t.Fatal("positive control unexpectedly had a dataplane manager to publish through")
	}
}
