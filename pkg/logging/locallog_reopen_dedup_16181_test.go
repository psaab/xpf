package logging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16181 acceptance: Closed / file-replaced / short-write / recover cells
// for BOTH writer kinds through the shared ensureOpenForWriter helper.
// Behaviour must match the pre-dedup twins (#9118) in file size, counters,
// and errors.

// --- LocalLogWriter (openHardenedAuditLog on a raw path) ---

func TestLocalWriterDedupFileReplacedResyncs16181(t *testing.T) {
	shortenReopenBackoff9118(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	defer lw.Close()
	if err := lw.Send(6, "before replace"); err != nil {
		t.Fatalf("baseline write: %v", err)
	}
	sizeBefore, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	wedgeLocalWriter9118(t, lw)
	// Replace the active file with a shorter stand-in while wedged.
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lw.Send(6, "after replace"); err != nil {
		t.Fatalf("wedged+replaced writer did not recover: %v", err)
	}
	if got := lw.RecoveredWrites(); got != 1 {
		t.Errorf("RecoveredWrites = %d, want 1", got)
	}
	lw.mu.Lock()
	written := lw.written
	lw.mu.Unlock()
	// written must have resynced to the replacement size (1) + appended line,
	// NOT carried forward from the pre-wedge file.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if written != info.Size() {
		t.Errorf("written = %d, file size = %d (pre-wedge size %d): written did not resync to the replaced file", written, info.Size(), sizeBefore.Size())
	}
	if written >= sizeBefore.Size() && info.Size() < sizeBefore.Size() {
		t.Errorf("written carried forward across file replacement")
	}
}

func TestLocalWriterDedupClosedStaysClosed16181(t *testing.T) {
	shortenReopenBackoff9118(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	if err := lw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := lw.Send(6, "after close"); err == nil {
		t.Error("closed writer accepted a write after dedup")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("closed writer recreated its file after dedup")
	}
	if got := lw.RecoveredWrites(); got != 0 {
		t.Errorf("RecoveredWrites = %d, want 0", got)
	}
	if got := lw.DroppedWrites(); got != 1 {
		t.Errorf("DroppedWrites = %d, want 1", got)
	}
}

func TestLocalWriterDedupShortWrite16181(t *testing.T) {
	shortenReopenBackoff9118(t)
	dir := t.TempDir()
	devNull := "/dev/full"
	if _, err := os.Stat(devNull); err != nil {
		t.Skipf("/dev/full unavailable: %v", err)
	}
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: filepath.Join(dir, "audit.log")})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	defer lw.Close()

	// Swap to /dev/full under lock: writes fail (ENOSPC-like). written must
	// not advance; drops must count; no recovery may be recorded.
	lw.mu.Lock()
	_ = lw.file.Close()
	f, err := os.OpenFile(devNull, os.O_WRONLY, 0)
	if err != nil {
		lw.mu.Unlock()
		t.Skipf("open /dev/full: %v", err)
	}
	lw.file = f
	droppedBefore := lw.DroppedWrites()
	writtenBefore := lw.written
	lw.mu.Unlock()

	if err := lw.Send(6, "cannot land"); err == nil {
		t.Error("short/full write unexpectedly succeeded")
	}
	lw.mu.Lock()
	writtenAfter := lw.written
	lw.mu.Unlock()
	if writtenAfter != writtenBefore {
		t.Errorf("written advanced on failed write: %d -> %d", writtenBefore, writtenAfter)
	}
	if got := lw.DroppedWrites(); got != droppedBefore+1 {
		t.Errorf("DroppedWrites = %d, want %d", got, droppedBefore+1)
	}
	if got := lw.RecoveredWrites(); got != 0 {
		t.Errorf("RecoveredWrites = %d, want 0 (healthy handle, not a reopen)", got)
	}
}

// --- TraceWriter (openTraceFile under traceLogDir, sanitised basename) ---

func wedgeTraceWriter16181(t *testing.T, tw *TraceWriter) {
	t.Helper()
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.file == nil {
		t.Fatal("trace writer was already nil")
	}
	_ = tw.file.Close()
	tw.file = nil
}

func newTraceWriter16181(t *testing.T, dir string) *TraceWriter {
	t.Helper()
	restore := SetTraceLogDirForTest(dir)
	t.Cleanup(restore)
	tw, err := NewTraceWriter(&config.FlowTraceoptions{
		File: "trace.log", FileSize: 1 << 20, FileCount: 3,
		Flags: []string{"basic-datapath"},
	})
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	t.Cleanup(func() { tw.Close() })
	return tw
}

func TestTraceWriterDedupFileReplacedResyncs16181(t *testing.T) {
	shortenReopenBackoff9118(t)
	dir := t.TempDir()
	tw := newTraceWriter16181(t, dir)
	path := filepath.Join(dir, "trace.log")
	rec := EventRecord{Type: "SESSION_CREATE"}
	tw.HandleEvent(rec, nil)
	tw.SyncForTest()
	before, err := os.ReadFile(path)
	if err != nil || len(before) == 0 {
		t.Fatalf("baseline record: len=%d err=%v", len(before), err)
	}

	wedgeTraceWriter16181(t, tw)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tw.HandleEvent(rec, nil)
	tw.SyncForTest()
	if got := tw.RecoveredWrites(); got != 1 {
		t.Errorf("RecoveredWrites = %d, want 1", got)
	}
	tw.mu.Lock()
	written := tw.written
	tw.mu.Unlock()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if written != info.Size() {
		t.Errorf("written = %d, file size = %d (baseline %d): trace written did not resync to replaced file", written, info.Size(), len(before))
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) <= 1 {
		t.Errorf("recovered record did not append after replacement: %d bytes", len(after))
	}
}

func TestTraceWriterDedupClosedStaysClosed16181(t *testing.T) {
	shortenReopenBackoff9118(t)
	dir := t.TempDir()
	tw := newTraceWriter16181(t, dir)
	path := filepath.Join(dir, "trace.log")
	tw.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Direct writeLine (post-Close async is stopped; this exercises the
	// shared helper's closed arm synchronously).
	droppedBefore := tw.DroppedWrites()
	tw.writeLine("after close\n")
	if got := tw.DroppedWrites(); got != droppedBefore+1 {
		t.Errorf("DroppedWrites = %d, want %d (closed write must drop+count)", got, droppedBefore+1)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("closed trace writer recreated its file after dedup")
	}
	if got := tw.RecoveredWrites(); got != 0 {
		t.Errorf("RecoveredWrites = %d, want 0", got)
	}
}

func TestTraceWriterDedupShortWrite16181(t *testing.T) {
	shortenReopenBackoff9118(t)
	dir := t.TempDir()
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skipf("/dev/full unavailable: %v", err)
	}
	tw := newTraceWriter16181(t, dir)
	tw.mu.Lock()
	_ = tw.file.Close()
	f, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		tw.mu.Unlock()
		t.Skipf("open /dev/full: %v", err)
	}
	tw.file = f
	droppedBefore := tw.DroppedWrites()
	writtenBefore := tw.written
	tw.mu.Unlock()

	tw.writeLine("cannot land\n")
	tw.mu.Lock()
	writtenAfter := tw.written
	tw.mu.Unlock()
	if writtenAfter != writtenBefore {
		t.Errorf("written advanced on failed write: %d -> %d", writtenBefore, writtenAfter)
	}
	if got := tw.DroppedWrites(); got != droppedBefore+1 {
		t.Errorf("DroppedWrites = %d, want %d", got, droppedBefore+1)
	}
	if got := tw.RecoveredWrites(); got != 0 {
		t.Errorf("RecoveredWrites = %d, want 0", got)
	}
}
