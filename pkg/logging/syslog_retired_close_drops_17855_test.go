package logging

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// #17855: the retired drop accumulator snapshots a client BEFORE Close,
// but Close is what discards the client's still-queued records into
// DroppedWrites (writer.stop() / run's closed-branch). A client retired
// with a queued backlog therefore contributed only its pre-Close counts,
// and the records Close discarded were never folded — the exported
// xpf_syslog_messages_dropped_total permanently undercounts exactly the
// losses a reconfiguration causes. Folding must observe the client's
// FINAL counts, exactly once.
//
// The fixture mirrors TestEventReaderSyslogQueueRetirementCountsPending11697:
// a stalled collector parks the writer goroutine inside conn.Write, so a
// deterministic backlog sits in the queue when the set is replaced.

// queueBacklog17855 parks client's writer in conn.Write and returns with
// exactly n records queued behind it and zero drops counted so far.
func queueBacklog17855(t *testing.T, client *SyslogClient, conn *stalledSyslogEventConn11697, n int) {
	t.Helper()
	if !client.SendFromEventReader(SyslogInfo, "in flight") {
		t.Fatal("primer event was not accepted")
	}
	select {
	case <-conn.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not enter the stalled connection")
	}
	for range n {
		if !client.SendFromEventReader(SyslogInfo, "pending") {
			t.Fatal("backlog event was not accepted into the queue")
		}
	}
	if got := client.DroppedWrites(); got != 0 {
		t.Fatalf("DroppedWrites before retirement = %d, want 0 (nothing lost yet)", got)
	}
}

func dropStatFor17855(t *testing.T, stats []SyslogDropStat, sink string) SyslogDropStat {
	t.Helper()
	for _, st := range stats {
		if st.Sink == sink {
			return st
		}
	}
	t.Fatalf("no %q row in drop stats %+v", sink, stats)
	return SyslogDropStat{}
}

func TestSetClientsRetiredTotalsIncludeCloseDiscards17855(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{client})
	t.Cleanup(handler.Close)

	const backlog = 8
	queueBacklog17855(t, client, conn, backlog)

	// Replacing the set closes the old client, discarding the backlog.
	handler.SetClients(nil)

	if got := client.DroppedWrites(); got != backlog {
		t.Fatalf("DroppedWrites after Close = %d, want %d discarded backlog records", got, backlog)
	}
	st := dropStatFor17855(t, handler.SyslogDropStats(), "system")
	if st.Writes != backlog {
		t.Fatalf("retired system Writes = %d, want %d: Close-discard drops were lost at retirement", st.Writes, backlog)
	}
}

func TestSetClientsPreservingRetiredTotalsIncludeCloseDiscards17855(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClientsPreserving([]*SyslogClient{client})
	t.Cleanup(handler.Close)

	const backlog = 8
	queueBacklog17855(t, client, conn, backlog)

	handler.SetClientsPreserving(nil)

	if got := client.DroppedWrites(); got != backlog {
		t.Fatalf("DroppedWrites after Close = %d, want %d discarded backlog records", got, backlog)
	}
	st := dropStatFor17855(t, handler.SyslogDropStats(), "system")
	if st.Writes != backlog {
		t.Fatalf("retired system Writes = %d, want %d: Close-discard drops were lost at retirement", st.Writes, backlog)
	}
}

func TestHandlerCloseRetiredTotalsIncludeCloseDiscards17855(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{client})

	const backlog = 8
	queueBacklog17855(t, client, conn, backlog)

	handler.Close()

	if got := client.DroppedWrites(); got != backlog {
		t.Fatalf("DroppedWrites after Close = %d, want %d discarded backlog records", got, backlog)
	}
	st := dropStatFor17855(t, handler.SyslogDropStats(), "system")
	if st.Writes != backlog {
		t.Fatalf("retired system Writes = %d, want %d: Close-discard drops were lost at retirement", st.Writes, backlog)
	}
}

func TestHandlerShutdownTimeoutRetiredTotalsIncludeDiscards17855(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	handler := NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{client})
	t.Cleanup(func() { _ = client.Close() })

	const backlog = 8
	queueBacklog17855(t, client, conn, backlog)

	// The wedged collector cannot drain; the timeout discards the backlog
	// (and the in-flight primer if the writer's earlier Write succeeded is
	// NOT a drop — the stalled conn reports success once released by its
	// own Close, so only the queued records count).
	handler.ShutdownTimeout(100 * time.Millisecond)

	final := client.DroppedWrites()
	if final == 0 {
		t.Fatal("wedged shutdown discarded nothing; fixture broken")
	}
	st := dropStatFor17855(t, handler.SyslogDropStats(), "system")
	if st.Writes != final {
		t.Fatalf("retired system Writes = %d, want the client's final %d: shutdown discards were lost at retirement", st.Writes, final)
	}
}

func TestReplaceSyslogClientsRetiredTotalsIncludeCloseDiscards17855(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	er := NewEventReader(nil, nil)
	er.SetSyslogClients([]*SyslogClient{client})

	const backlog = 8
	queueBacklog17855(t, client, conn, backlog)

	er.ReplaceSyslogClients(nil)

	if got := client.DroppedWrites(); got != backlog {
		t.Fatalf("DroppedWrites after Close = %d, want %d discarded backlog records", got, backlog)
	}
	st := dropStatFor17855(t, er.SyslogDropStats(), "security")
	if st.Writes != backlog {
		t.Fatalf("retired security Writes = %d, want %d: Close-discard drops were lost at retirement", st.Writes, backlog)
	}
}

// #17855 fold (rev): a stats call between retire and the owner's
// external Close must not consume the pending entry — the Close
// discards still land exactly once at the next stats call.
func TestSetSyslogClientsInterposedStatsStillCountsOnce17855(t *testing.T) {
	conn := newStalledSyslogEventConn11697()
	client := NewSyslogClientWithConn(conn, "tcp")
	er := NewEventReader(nil, nil)
	er.SetSyslogClients([]*SyslogClient{client})

	const backlog = 8
	queueBacklog17855(t, client, conn, backlog)

	// Retire (the daemon caller closes externally, after this returns).
	er.SetSyslogClients(nil)
	// Interposed scrape: client not yet closed; nothing may be lost.
	_ = er.SyslogDropStats()
	// Owner's external Close now discards the backlog.
	if err := client.Close(); err != nil {
		t.Fatalf("external Close: %v", err)
	}
	if got := client.DroppedWrites(); got != backlog {
		t.Fatalf("DroppedWrites after Close = %d, want %d", got, backlog)
	}
	st := dropStatFor17855(t, er.SyslogDropStats(), "security")
	if st.Writes != backlog {
		t.Fatalf("security Writes = %d, want %d after interposed stats", st.Writes, backlog)
	}
	// And exactly once: a second scrape must not double-count.
	st = dropStatFor17855(t, er.SyslogDropStats(), "security")
	if st.Writes != backlog {
		t.Fatalf("security Writes = %d on second scrape, want exactly %d", st.Writes, backlog)
	}
}

// #17855 fold (rev): re-installing a retired-then-closed client must
// not resurrect its already-folded counters — no double count.
func TestReinstalledRetiredClientDoesNotDoubleCount17855(t *testing.T) {
	client := NewSyslogClientWithConn(newStalledSyslogEventConn11697(), "tcp")
	er := NewEventReader(nil, nil)
	er.SetSyslogClients([]*SyslogClient{client})
	er.ReplaceSyslogClients(nil)
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Simulate a caller reinstalling the same (closed) client object.
	er.SetSyslogClients([]*SyslogClient{client})
	st := dropStatFor17855(t, er.SyslogDropStats(), "security")
	live := client.DroppedWrites()
	// The row must equal the client's own counters, never a multiple.
	if st.Writes != live {
		t.Fatalf("security Writes = %d, want client's own %d (no double count on reinstall)", st.Writes, live)
	}
}
