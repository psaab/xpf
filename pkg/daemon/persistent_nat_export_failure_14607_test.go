package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// #14607: an export failure in the 30 s idle-lease push loop was logged
// only at Debug. It must be counted and warned (rate-limited).

func TestPersistentNatLeaseExportFailureCountedAndWarned14607(t *testing.T) {
	// Reset shared state for determinism.
	persistentNatLeaseExportFailures.Store(0)
	persistentNatLeaseExportWarnThrottle = warnThrottle{}

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	boom := errors.New("helper export boom")
	now := time.Now()
	notePersistentNatLeaseExportFailure(boom, now)
	if got := PersistentNatLeaseExportFailures(); got != 1 {
		t.Fatalf("failures = %d, want 1", got)
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "persistent-NAT idle lease export failed") {
		t.Fatalf("first failure not warned: %q", buf.String())
	}
	// Second failure inside the interval: counted, not re-warned.
	buf.Reset()
	notePersistentNatLeaseExportFailure(boom, now.Add(time.Second))
	if got := PersistentNatLeaseExportFailures(); got != 2 {
		t.Fatalf("failures = %d, want 2", got)
	}
	if strings.Contains(buf.String(), "persistent-NAT idle lease export failed") {
		t.Fatalf("second failure inside interval should be rate-limited, got %q", buf.String())
	}
	// After the interval: warns again.
	buf.Reset()
	notePersistentNatLeaseExportFailure(boom, now.Add(2*time.Minute))
	if got := PersistentNatLeaseExportFailures(); got != 3 {
		t.Fatalf("failures = %d, want 3", got)
	}
	if !strings.Contains(buf.String(), "persistent-NAT idle lease export failed") {
		t.Fatalf("failure after interval not warned: %q", buf.String())
	}
}
