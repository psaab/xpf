package cluster

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// captureSyncWarn17110 installs a Warn-level text slog default writing
// to buf and restores the previous default on cleanup. Mirrors the
// capture shape in heartbeat_read_warn_10316_test.go.
func captureSyncWarn17110(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// TestDeleteJournalFlushWarnFields17110 is the #17110 diagnostic-parity
// cell: when a flush cannot enqueue (full queue / disconnected), the
// bare and scoped flush warnings must carry the SAME diagnostic fields.
// Pre-fix the scoped warning logged only total/flushed/unsent_tail, so
// the scoped leg fails on the missing fields. Each leg also appends one
// frame while its flush is in flight (before the take, via the
// testBefore*JournalTake hook): the appended frame must join the same
// flush and, on failure, be re-journaled in FIFO order behind the
// un-sent tail.
func TestDeleteJournalFlushWarnFields17110(t *testing.T) {
	mk := func(n int) []byte { return encodeDeleteV4(deleteKeyN(n), 0, false) }
	scopedMsg := func() []byte {
		return encodeDeleteScopedV4(scopedCodecKeyV4(), 9, false, 100007, 0xF10512)
	}
	wantFields := []string{"total=6", "flushed=0", "unsent_tail=6",
		"deletes_dropped_total=0", "connected=true", "queue_len=2", "queue_cap=2"}

	t.Run("bare", func(t *testing.T) {
		buf := captureSyncWarn17110(t)
		ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
		ss.sendCh = make(chan []byte, 2)
		ss.sendCh <- []byte{0}
		ss.sendCh <- []byte{0}
		ss.stats.Connected.Store(true)
		for i := range 5 {
			ss.deleteJournal.entries = append(ss.deleteJournal.entries, mk(i))
		}
		extra := mk(99)
		ss.testBeforeJournalTake = func() { ss.journalDelete(extra) }
		ss.flushDeleteJournal()

		out := buf.String()
		for _, f := range wantFields {
			if !strings.Contains(out, f) {
				t.Fatalf("bare flush warn missing %q; log:\n%s", f, out)
			}
		}
		ss.deleteJournalMu.Lock()
		defer ss.deleteJournalMu.Unlock()
		if len(ss.deleteJournal.entries) != 6 {
			t.Fatalf("re-journaled entries = %d, want 6", len(ss.deleteJournal.entries))
		}
		for i := range 5 {
			if string(ss.deleteJournal.entries[i]) != string(mk(i)) {
				t.Fatalf("re-journaled entry %d out of order", i)
			}
		}
		if string(ss.deleteJournal.entries[5]) != string(extra) {
			t.Fatal("concurrently appended delete must trail the un-sent tail")
		}
	})

	t.Run("scoped", func(t *testing.T) {
		buf := captureSyncWarn17110(t)
		ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
		ss.sendCh = make(chan []byte, 2)
		ss.sendCh <- []byte{0}
		ss.sendCh <- []byte{0}
		learnScopedCapable10512(t, ss)
		ss.stats.Connected.Store(true)
		for i := range 5 {
			ss.scopedDeleteJournal.entries = append(ss.scopedDeleteJournal.entries, mk(i))
		}
		extra := scopedMsg()
		ss.testBeforeScopedJournalTake = func() { ss.journalScopedDelete(extra) }
		ss.flushScopedDeleteJournal()

		out := buf.String()
		for _, f := range wantFields {
			if !strings.Contains(out, f) {
				t.Fatalf("scoped flush warn missing %q; log:\n%s", f, out)
			}
		}
		ss.deleteJournalMu.Lock()
		defer ss.deleteJournalMu.Unlock()
		if len(ss.scopedDeleteJournal.entries) != 6 {
			t.Fatalf("re-journaled scoped entries = %d, want 6", len(ss.scopedDeleteJournal.entries))
		}
		for i := range 5 {
			if string(ss.scopedDeleteJournal.entries[i]) != string(mk(i)) {
				t.Fatalf("re-journaled scoped entry %d out of order", i)
			}
		}
		if string(ss.scopedDeleteJournal.entries[5]) != string(extra) {
			t.Fatal("concurrently appended scoped delete must trail the un-sent tail")
		}
	})
}
