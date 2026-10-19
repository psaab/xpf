package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #14999 (D40-05): the binary local-log path in logEvent still called the
// SYNCHRONOUS LocalLogWriter.SendBinary on the EventStream reader goroutine,
// while the text path beside it was moved off that goroutine by #9025 via
// SendFromEventReader. SendBinary does file.Write + inline rotate() (generation
// renames + dir fsync + reopen) under lw.mu, so a stalled disk parks the
// reader — and with it HA session sync (SessionOpen/Update/Close), the ISSU
// drain signal and full-resync — behind one binary audit record.
//
// Fix: SendBinaryFromEventReader hands an immutable copy of the record to the
// same bounded asyncAuditWriter queue SendFromEventReader uses; the writer
// goroutine re-enters SendBinary, so rotation/failure accounting stays inside
// the existing locked write. Direct SendBinary callers keep the synchronous
// contract (#3478 M04).
//
// RED-on-revert: replace the ringbuf.go binary local branch's
// SendBinaryFromEventReader call with synchronous SendBinary (or make
// SendBinaryFromEventReader call SendBinary inline) and both blocking cells
// below fail — the caller parks behind a wedged writer goroutine and the
// queue-full binary record blocks instead of dropping-and-counting.

func wedgeLocalWriter14999(t *testing.T, lw *LocalLogWriter) (entered <-chan struct{}, release func()) {
	t.Helper()
	enteredCh := make(chan struct{})
	releaseCh := make(chan struct{})
	orig := lw.async.write
	first := true
	lw.async.write = func(it auditItem) {
		if first {
			first = false
			close(enteredCh)
		}
		<-releaseCh
		if it.ack == nil {
			orig(it)
		}
	}
	released := false
	return enteredCh, func() {
		if !released {
			released = true
			close(releaseCh)
		}
	}
}

func newBinaryLocalWriter14999(t *testing.T, maxSize int64) (*LocalLogWriter, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "security.binlog")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path, MaxSize: maxSize})
	if err != nil {
		t.Fatal(err)
	}
	lw.Format = "binary"
	t.Cleanup(func() { _ = lw.Close() })
	return lw, path
}

func binaryRecord14999() []byte {
	evt := &rawEvent{EventType: eventTypeSessionOpen, Protocol: 6, Action: actionPermit}
	rec := &EventRecord{Time: time.Now(), SessionID: 99}
	return formatBinaryRecord(evt, rec, SyslogInfo, 0)
}

func TestLocalLogBinaryFromEventReaderDoesNotBlockCaller14999(t *testing.T) {
	lw, _ := newBinaryLocalWriter14999(t, 0)
	entered, release := wedgeLocalWriter14999(t, lw)
	defer release()

	if !lw.SendBinaryFromEventReader(binaryRecord14999()) {
		t.Fatal("first binary record not accepted")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture: writer goroutine never entered the wedged write")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			lw.SendBinaryFromEventReader(binaryRecord14999())
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("#14999: SendBinaryFromEventReader blocked while the disk write was stalled; " +
			"on the EventStream reader this parks HA session sync behind local-log disk I/O")
	}
}

func TestLocalLogBinaryQueueOverflowDropsAndCounts14999(t *testing.T) {
	lw, _ := newBinaryLocalWriter14999(t, 0)
	_, release := wedgeLocalWriter14999(t, lw)
	defer release()

	accepted := 0
	for range auditQueueDepth * 2 {
		if lw.SendBinaryFromEventReader(binaryRecord14999()) {
			accepted++
		}
	}
	if accepted == 0 || accepted > auditQueueDepth+1 {
		t.Fatalf("#14999: accepted %d binary records into a queue of depth %d with the writer wedged; want bounded acceptance", accepted, auditQueueDepth)
	}
	if got := lw.DroppedWrites(); got == 0 {
		t.Fatal("#14999: binary queue overflow was not counted in DroppedWrites — silent audit loss (#3478)")
	}
}

func TestLocalLogBinaryFromEventReaderWritesAndRotates14999(t *testing.T) {
	rec := binaryRecord14999()
	lw, path := newBinaryLocalWriter14999(t, int64(len(rec)*2+1))

	for range 5 {
		if !lw.SendBinaryFromEventReader(rec) {
			t.Fatal("binary record not accepted")
		}
	}
	lw.SyncForTest()

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("#14999: expected rotated generation .1 after async binary writes: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) == 0 || len(content)%len(rec) != 0 {
		t.Fatalf("active file size %d is not a whole number of %d-byte records", len(content), len(rec))
	}
	for off := 0; off < len(content); off += len(rec) {
		if !bytes.Equal(content[off:off+len(rec)], rec) {
			t.Fatalf("record at offset %d differs from offered record", off)
		}
	}
}

func TestRetiredLocalLogBinaryFromEventReaderCountsDrop14999(t *testing.T) {
	lw, _ := newBinaryLocalWriter14999(t, 0)
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	before := lw.DroppedWrites()
	if lw.SendBinaryFromEventReader(binaryRecord14999()) {
		t.Fatal("#14999: binary record accepted by a retired writer")
	}
	if got := lw.DroppedWrites(); got != before+1 {
		t.Fatalf("#14999: retired-writer binary drop not counted: %d -> %d", before, got)
	}
}

func TestLocalLogBinaryFromEventReaderCopiesRecord14999(t *testing.T) {
	lw, path := newBinaryLocalWriter14999(t, 0)
	rec := binaryRecord14999()
	want := bytes.Clone(rec)
	if !lw.SendBinaryFromEventReader(rec) {
		t.Fatal("binary record not accepted")
	}
	for i := range rec {
		rec[i] = 0
	}
	lw.SyncForTest()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, want) {
		t.Fatal("#14999: queued binary record was corrupted by caller mutating the offered slice after handoff")
	}
}
