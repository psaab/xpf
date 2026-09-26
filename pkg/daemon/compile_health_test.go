package daemon

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestCompileHealth_RecordFailure pins the #758 state transitions:
//   - recordCompileFailure increments the counter and captures the error
//   - recordCompileSuccess flips EverSucceeded and clears LastError, but
//     preserves the failure count so operators can see past transience
//   - counter-factual: before recording any failure, the snapshot shows
//     EverSucceeded=false with FailureCount=0 — /health treats this as
//     healthy (the "never tried" case matches the "succeeded once" path
//     rather than the "persistent failure" path).
func TestCompileHealth_RecordFailure(t *testing.T) {
	d := &Daemon{}

	// Initial: zero state. /health must treat this as healthy (not
	// degraded) — the gate fires only on FailureCount > 0.
	s := d.CompileHealthSnapshot()
	if s.EverSucceeded || s.FailureCount != 0 || s.LastError != "" {
		t.Errorf("initial snapshot = %+v, want zero value", s)
	}

	// Record a failure. The counter increments; LastError carries
	// through verbatim; EverSucceeded stays false.
	d.recordCompileFailure(errors.New("compile zones: add tx port fab0: key too big for map"))
	s = d.CompileHealthSnapshot()
	if s.EverSucceeded {
		t.Error("EverSucceeded must stay false before any success")
	}
	if s.FailureCount != 1 {
		t.Errorf("FailureCount = %d, want 1", s.FailureCount)
	}
	if s.LastError == "" {
		t.Error("LastError must be populated on failure")
	}

	// Second failure with a different error: counter advances,
	// LastError rewrites to the latest message.
	d.recordCompileFailure(errors.New("different compile failure"))
	s = d.CompileHealthSnapshot()
	if s.FailureCount != 2 {
		t.Errorf("FailureCount after second failure = %d, want 2", s.FailureCount)
	}
	if s.LastError != "different compile failure" {
		t.Errorf("LastError = %q, want the most recent error text", s.LastError)
	}

	// Success flips EverSucceeded and clears LastError but preserves
	// the failure count (monotonic observability counter).
	d.recordCompileSuccess()
	s = d.CompileHealthSnapshot()
	if !s.EverSucceeded {
		t.Error("EverSucceeded must be true after a success")
	}
	if s.LastError != "" {
		t.Errorf("LastError = %q, want empty after success", s.LastError)
	}
	if s.FailureCount != 2 {
		t.Errorf("FailureCount after success = %d, want 2 (preserved)", s.FailureCount)
	}
}

// TestApplyConfigLockedRecordsCompileFailureAndHealth503 guards the production
// ApplyConfig error path and the resulting public readiness response.
func TestApplyConfigLockedRecordsCompileFailureAndHealth503(t *testing.T) {
	d := &Daemon{
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	dp := &runtimeOnlyApplyTestDP{applyErr: dpuserspace.ErrPersistentSourceNATProtocolIncompatible}
	d.setDataplane(dp)

	err := d.applyConfigLocked(context.Background(), &config.Config{})
	if !errors.Is(err, dpuserspace.ErrPersistentSourceNATProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want dataplane apply failure", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("ApplyConfig calls = %d, want 1", dp.applyCalls)
	}
	h := d.CompileHealthSnapshot()
	if h.EverSucceeded || h.FailureCount != 1 || h.LastError != dpuserspace.ErrPersistentSourceNATProtocolIncompatible.Error() {
		t.Fatalf("compile health = %+v, want one recorded failure and no success", h)
	}

	s := api.NewServer(api.Config{
		Addr: "127.0.0.1:0",
		CompileHealthFn: func() api.CompileHealthSnapshot {
			h := d.CompileHealthSnapshot()
			return api.CompileHealthSnapshot{
				EverSucceeded:    h.EverSucceeded,
				FailureCount:     h.FailureCount,
				LastError:        h.LastError,
				LastErrorUnixSec: h.LastErrorUnixSec,
			}
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start health API: %v", err)
	}
	defer func() {
		cancel()
		s.Wait()
	}()

	handler := s.HTTPHandlerForTest()
	if handler == nil {
		t.Fatal("health API has no live HTTP handler")
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/health", nil))
	if rr.Code != 503 {
		t.Fatalf("/health status = %d, want 503; body: %s", rr.Code, rr.Body.String())
	}
}
