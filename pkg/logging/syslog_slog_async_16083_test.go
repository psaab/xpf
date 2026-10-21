package logging

// #16083 (A9-06): non-event slog forwarding was synchronous —
// SyslogSlogHandler.Handle called SyslogClient.Send directly for every
// non-EventReader caller, so a blackholed TCP/TLS collector could park
// arbitrary daemon goroutines (commit/apply, reconcile, API handlers)
// behind the client mutex for the write/dial timeout, serialised across
// every goroutine that logs. Fix: route ALL slog through the existing
// bounded per-client writer (SendFromEventReader queue) regardless of
// caller context.
//
// RED on pre-fix: TestSlogHandlerNonEventNeverBlocks16083 parks Handle
// for the full stall (the handler synchronously writes), and the overflow
// cells see the records written synchronously instead of dropped+counted.
// GREEN after the cutover: Handle returns in microseconds, the writer
// goroutine owns the stall, overflow drops and counts.

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const slogAsyncBound16083 = 300 * time.Millisecond

// TestSlogHandlerNonEventNeverBlocks16083 is the decisive regression:
// a plain (non-EventReader) slog record through SyslogSlogHandler against
// a stalled collector must return promptly — bounded by the queue
// handoff, not the collector. Pre-fix it parks for the write timeout.
func TestSlogHandlerNonEventNeverBlocks16083(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{client})
	t.Cleanup(handler.Close)

	// Wedge the writer goroutine inside the stalled write, so the queue
	// handoff is the only thing Handle can be doing.
	if !client.SendFromEventReader(SyslogInfo, "primer") {
		t.Fatal("primer not accepted")
	}
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter the stalled connection")
	}

	// Plain slog, no event-reader context marker: the #16083 shape.
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		slog.New(handler).Info("daemon record against a blackholed collector")
	}()
	select {
	case <-done:
		if elapsed := time.Since(start); elapsed >= slogAsyncBound16083 {
			t.Fatalf("non-event Handle took %s against a stalled collector, want <%s (#16083)", elapsed, slogAsyncBound16083)
		}
	case <-time.After(slogAsyncBound16083):
		t.Fatalf("non-event Handle blocked >%s on a stalled collector (#16083: synchronous Send parks the caller)", slogAsyncBound16083)
	}

	// The primer plus this record are accounted: one in flight, one queued.
	// Cleanup closes the client, releasing the stalled write.
}

// TestSlogHandlerQueueOverflowDropsAndCounts16083: with the writer wedged,
// a flood of plain slog records must overflow-drop and count, never block.
func TestSlogHandlerQueueOverflowDropsAndCounts16083(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{client})
	t.Cleanup(handler.Close)

	if !client.SendFromEventReader(SyslogInfo, "primer") {
		t.Fatal("primer not accepted")
	}
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not enter the stalled connection")
	}

	log := slog.New(handler)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range syslogEventQueueDepth * 2 {
			log.Info("flood record")
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slog flood blocked on a full queue (#16083: must drop, not block)")
	}
	if got := client.DroppedWrites(); got == 0 {
		t.Fatal("queue overflow from slog records was not counted in DroppedWrites (#16083)")
	}
}

// TestSlogHandlerOversizeRecordDrops16083: a single record larger than the
// per-message cap is dropped and counted rather than queued, capping the
// in-memory backlog at depth × cap per client.
func TestSlogHandlerOversizeRecordDrops16083(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{client})
	t.Cleanup(handler.Close)

	huge := strings.Repeat("x", syslogEventQueueMaxBytes+1)
	slog.New(handler).Info(huge)
	if got := client.DroppedWrites(); got != 1 {
		t.Fatalf("oversize slog record: DroppedWrites = %d, want 1 (#16083)", got)
	}
	select {
	case <-conn.entered:
		t.Fatal("oversize record reached the wire; it must be dropped at enqueue (#16083)")
	case <-time.After(20 * time.Millisecond):
	}
}

// TestSlogHandlerOrdinaryRecordDelivered16083 is the control: with a
// healthy collector the queued record is actually delivered — the cutover
// must not turn forwarding into a black hole.
func TestSlogHandlerOrdinaryRecordDelivered16083(t *testing.T) {
	conn := &captureSyslogEventConn11697{writes: make(chan []byte, 4)}
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{client})
	t.Cleanup(handler.Close)

	slog.New(handler).Info("ordinary daemon record")
	select {
	case frame := <-conn.writes:
		if !strings.Contains(string(frame), "ordinary daemon record") {
			t.Fatalf("delivered frame does not carry the record: %q", frame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary slog record was not delivered through the queue (#16083)")
	}
}
