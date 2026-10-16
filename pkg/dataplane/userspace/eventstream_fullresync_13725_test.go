package userspace

// Regression coverage for #13725. ExportOwnerRGSessionsPaged is not an
// atomic snapshot: a paged export scans shards incrementally, so a
// FullResync barrier emitted after the in-flight export started cannot be
// covered by that export — sessions dropped in already-scanned shards
// would never be re-exported, yet the barrier would be retired and
// Every barrier, queued or running, retains its own export.

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventStreamFullResyncArrivingDuringInFlightWorkerRunsPostBarrierExport13725(t *testing.T) {
	es := NewEventStream(filepath.Join(t.TempDir(), "events.sock"))
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var exports atomic.Int32
	// Observation point for "seq 2 ACKed": lastAppliedSeq reaching 2 means
	// the seq-2 barrier was retired and cumulatively acknowledged.
	appliedSeqAtExport := make([]uint64, 0, 2)
	var mu sync.Mutex
	es.SetOnFullResync(func() bool {
		n := exports.Add(1)
		if n == 1 {
			<-release
		}
		mu.Lock()
		appliedSeqAtExport = append(appliedSeqAtExport, es.lastAppliedSeq.Load())
		mu.Unlock()
		return true
	})
	defer es.Close()

	if !es.dispatchOrQueueFullResyncFrame(1) {
		t.Fatal("first FullResync barrier did not queue")
	}
	wait9630(t, 2*time.Second,
		func() bool { return exports.Load() == 1 },
		"first FullResync export did not start")
	// While export 1 is blocked mid-scan, the helper records more drops in
	// already-scanned shards and emits a second barrier.
	if !es.dispatchOrQueueFullResyncFrame(2) {
		t.Fatal("second FullResync barrier did not queue during in-flight export")
	}
	if got := es.lastAppliedSeq.Load(); got != 0 {
		t.Fatalf("ACK watermark advanced while first export blocked: %d", got)
	}

	unblock()
	// The post-drop barrier must run its own export BEFORE seq 2 retires.
	wait9630(t, 2*time.Second,
		func() bool { return exports.Load() == 2 },
		"FullResync arriving during in-flight export did not run a post-barrier export")
	wait9630(t, 2*time.Second,
		func() bool { return es.lastAppliedSeq.Load() == 2 },
		"second FullResync barrier did not retire after its export")
	mu.Lock()
	defer mu.Unlock()
	if len(appliedSeqAtExport) != 2 {
		t.Fatalf("export observation count = %d, want 2", len(appliedSeqAtExport))
	}
	if appliedSeqAtExport[1] >= 2 {
		t.Fatalf("seq 2 was applied before its own export ran (watermark %d at export 2)", appliedSeqAtExport[1])
	}
}

func TestEventStreamFullResyncFailureRetriesEveryBarrier13725(t *testing.T) {
	es := NewEventStream(filepath.Join(t.TempDir(), "events.sock"))
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var exports atomic.Int32
	es.SetOnFullResync(func() bool {
		n := exports.Add(1)
		if n == 1 {
			<-release
			return false // first export fails
		}
		return true
	})
	defer es.Close()

	if !es.dispatchOrQueueFullResyncFrame(1) {
		t.Fatal("first FullResync barrier did not queue")
	}
	wait9630(t, 2*time.Second,
		func() bool { return exports.Load() == 1 },
		"first FullResync export did not start")
	// Two more barriers arrive while the first export is in flight. None can
	// be covered by the failed export, so they each need their own successful
	// post-barrier export before the cumulative watermark may pass them.
	if !es.dispatchOrQueueFullResyncFrame(2) {
		t.Fatal("second FullResync barrier did not queue during in-flight export")
	}
	if !es.dispatchOrQueueFullResyncFrame(3) {
		t.Fatal("third FullResync barrier did not queue during in-flight export")
	}
	unblock()
	wait9630(t, 2*time.Second, func() bool {
		es.resyncMu.Lock()
		defer es.resyncMu.Unlock()
		return !es.resyncInFlight
	}, "failed FullResync worker did not complete")
	es.flushPendingCallbackFrames()
	wait9630(t, 2*time.Second,
		func() bool { return es.lastAppliedSeq.Load() == 3 },
		"barriers did not retire after retry export")
	if got := exports.Load(); got != 4 {
		t.Fatalf("FullResync exports = %d, want 4 (failed attempt + retry and two later barriers)", got)
	}
}
