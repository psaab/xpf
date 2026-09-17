package userspace

// Regression coverage for #9630. A helper FullResync starts the potentially
// long paged owner-RG export, so the event-stream reader must keep draining
// frames while that export is blocked. Multiple wire barriers observed during
// one export share the callback but retain FIFO ACK markers.

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func wait9630(t *testing.T, timeout time.Duration, ready func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		time.Sleep(time.Millisecond)
	}
}

func startEventStream9630(t *testing.T, callback func() bool) (*EventStream, net.Conn) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "events.sock")
	es := NewEventStream(sockPath)
	es.SetOnFullResync(callback)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		es.Close()
	})
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream: %v", err)
	}
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial event stream: %v", err)
	}
	wait9630(t, 2*time.Second, es.IsConnected, "event stream did not connect")
	t.Cleanup(func() { conn.Close() })
	return es, conn
}

func TestEventStreamFullResyncReaderProgressWhileExportBlocked9630(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var entered atomic.Bool
	es, conn := startEventStream9630(t, func() bool {
		entered.Store(true)
		<-release
		return true
	})

	if err := writeFrame(conn, EventTypeFullResync, 1, nil); err != nil {
		t.Fatalf("write FullResync: %v", err)
	}
	wait9630(t, 2*time.Second, entered.Load, "FullResync export did not start")

	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	const keepalives = 5000
	for seq := uint64(2); seq <= keepalives+1; seq++ {
		if err := writeFrame(conn, EventTypeKeepalive, seq, nil); err != nil {
			t.Fatalf("write keepalive %d: %v", seq, err)
		}
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear write deadline: %v", err)
	}
	wait9630(t, 2*time.Second,
		func() bool { return es.FramesRead.Load() >= keepalives+1 },
		"reader stopped draining frames while FullResync export was blocked")
	if got := es.lastAppliedSeq.Load(); got != 0 {
		t.Fatalf("FullResync ACK watermark advanced while export was blocked: %d", got)
	}

	unblock()
	wait9630(t, 2*time.Second,
		func() bool { return es.lastAppliedSeq.Load() >= 1 },
		"FullResync barrier was not applied after export completed")
}

func TestEventStreamFullResyncCoalescesConcurrentBarriers9630(t *testing.T) {
	es := NewEventStream(filepath.Join(t.TempDir(), "events.sock"))
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var exports atomic.Int32
	es.SetOnFullResync(func() bool {
		exports.Add(1)
		<-release
		return true
	})

	first := make(chan bool, 1)
	second := make(chan bool, 1)
	go func() { first <- es.dispatchOrQueueFullResyncFrame(7) }()
	wait9630(t, 2*time.Second,
		func() bool { return exports.Load() == 1 },
		"first FullResync export did not start")
	go func() { second <- es.dispatchOrQueueFullResyncFrame(8) }()
	select {
	case <-second:
	case <-time.After(2 * time.Second):
		t.Fatal("second FullResync dispatch did not return while first export was blocked")
	}

	unblock()
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("first FullResync dispatch did not return after export completed")
	}
	if got := exports.Load(); got != 1 {
		t.Fatalf("FullResync exports = %d, want one coalesced export", got)
	}
	wait9630(t, 2*time.Second,
		func() bool { return es.lastAppliedSeq.Load() == 8 },
		"coalesced FullResync marker did not retire in FIFO order")
}

func TestEventStreamFullResyncCoalescesPendingBeforeCallback9630(t *testing.T) {
	es := NewEventStream(filepath.Join(t.TempDir(), "events.sock"))
	first := es.dispatchOrQueueFullResyncFrame(7)
	second := es.dispatchOrQueueFullResyncFrame(8)
	if !first || !second {
		t.Fatal("FullResync markers should queue before callback registration")
	}
	defer es.Close()

	var exports atomic.Int32
	es.SetOnFullResync(func() bool {
		exports.Add(1)
		return true
	})
	wait9630(t, 2*time.Second,
		func() bool { return exports.Load() == 1 },
		"queued FullResync export did not start after callback registration")
	wait9630(t, 2*time.Second,
		func() bool { return es.lastAppliedSeq.Load() == 8 },
		"queued FullResync markers did not coalesce and retire in FIFO order")
	if got := exports.Load(); got != 1 {
		t.Fatalf("queued FullResync exports = %d, want one coalesced export", got)
	}
}

func TestEventStreamFullResyncCloseRestartDoesNotRetryOldWorker9630(t *testing.T) {
	es := NewEventStream(filepath.Join(t.TempDir(), "events.sock"))
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var finished = make(chan struct{}, 1)
	var exports atomic.Int32
	es.SetOnFullResync(func() bool {
		exports.Add(1)
		<-release
		finished <- struct{}{}
		return true
	})

	first := make(chan bool, 1)
	go func() { first <- es.dispatchOrQueueFullResyncFrame(7) }()
	wait9630(t, 2*time.Second,
		func() bool { return exports.Load() == 1 },
		"FullResync export did not start")
	if !es.dispatchOrQueueFullResyncFrame(8) {
		t.Fatal("second FullResync marker did not queue")
	}

	es.Close()
	ctx, cancel := context.WithCancel(context.Background())
	if err := es.Start(ctx); err != nil {
		cancel()
		t.Fatalf("restart event stream: %v", err)
	}
	defer func() {
		cancel()
		es.Close()
	}()

	unblock()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("old FullResync worker callback did not finish after release")
	}
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("old FullResync dispatch did not return after release")
	}
	time.Sleep(20 * time.Millisecond)
	if got := exports.Load(); got != 1 {
		t.Fatalf("stale worker launched %d replacement exports after Close/restart, want 1", got)
	}
	if got := es.lastAppliedSeq.Load(); got != 0 {
		t.Fatalf("stale worker advanced ACK watermark after Close/restart: %d", got)
	}
}
