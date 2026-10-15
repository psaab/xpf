package userspace

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// #13301 (D5-12): the HA takeover-readiness latches are Go-side Manager
// state invisible to Prometheus unless exposed via HATakeoverReadiness.
func TestHATakeoverReadinessExposesSessionMirrorBlocker13301(t *testing.T) {
	m := New()
	m.mu.Lock()
	m.sessionMirrorFailed = true
	m.sessionMirrorErr = "dial timeout"
	m.mu.Unlock()
	s := m.HATakeoverReadiness()
	if s.Ready {
		t.Fatal("Ready=true with sessionMirrorFailed latched")
	}
	if !s.SessionMirrorFailed {
		t.Fatal("SessionMirrorFailed=false, want true")
	}
	found := false
	for _, b := range s.Blockers {
		if b == "session_mirror_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Blockers=%v, want session_mirror_failed", s.Blockers)
	}
}

func TestHATakeoverReadinessBlockerEnumBounded13301(t *testing.T) {
	m := New()
	// No proc, disabled, unarmed, unsupported, mirror failed, repair
	// overflow, inventory debt, pending clear/replay all latch at once.
	m.mu.Lock()
	m.sessionMirrorFailed = true
	m.sessionRepairOverflowErr = "overflow"
	m.sessionInventoryDebtGen = 7
	m.pendingHAStateClear = true
	m.pendingHAStateReplay = true
	m.mu.Unlock()
	s := m.HATakeoverReadiness()
	if s.Ready || len(s.Blockers) == 0 {
		t.Fatalf("Ready=%v Blockers=%v, want blocked", s.Ready, s.Blockers)
	}
	for _, b := range s.Blockers {
		switch b {
		case "helper_down", "not_enabled", "forwarding_unsupported", "not_armed",
			"not_active", "xsk_liveness_failed", "xsk_unproven",
			"session_mirror_failed", "repair_overflow", "inventory_debt_owed",
			"snapshot_retry_debt", "pending_ha_clear", "pending_ha_replay",
			"event_stream_unbound":
		default:
			t.Fatalf("unbounded blocker %q in %v", b, s.Blockers)
		}
	}
	if !s.InventoryDebtOwed || !s.PendingHAStateClear || !s.PendingHAStateReplay || !s.RepairOverflow {
		t.Fatalf("structured fields missing: %+v", s)
	}
	for _, want := range []string{"pending_ha_clear", "pending_ha_replay"} {
		found := false
		for _, blocker := range s.Blockers {
			found = found || blocker == want
		}
		if !found {
			t.Errorf("missing blocker %q in %v", want, s.Blockers)
		}
	}
	if s.SyncedImportRefusals != 0 {
		t.Fatalf("SyncedImportRefusals=%d, want 0", s.SyncedImportRefusals)
	}
}

func TestSessionSocketRPCCounters13301(t *testing.T) {
	m := New()
	if _, err := m.requestSessionSyncResponse(ControlRequest{Type: "session_sync"}); err == nil {
		t.Fatal("expected error with no session socket")
	}
	s := m.HATakeoverReadiness()
	if s.SessionSocketRequests == 0 {
		t.Fatal("SessionSocketRequests=0 after a request attempt")
	}
	if s.SessionSocketErrors == 0 {
		t.Fatal("SessionSocketErrors=0 after a failed request")
	}
	if s.SessionSocketTimeouts != 0 {
		t.Fatalf("SessionSocketTimeouts=%d, want 0 for non-timeout error", s.SessionSocketTimeouts)
	}
}
func TestSessionSocketRPCCountersTimeout13301(t *testing.T) {
	m := New()
	m.cfg.ControlSocket = filepath.Join(t.TempDir(), "control.sock")
	originalDial, originalRoundTrip := sessionSyncDialTimeout, sessionSyncRoundtripDeadline
	sessionSyncDialTimeout = time.Second
	sessionSyncRoundtripDeadline = 20 * time.Millisecond
	t.Cleanup(func() {
		sessionSyncDialTimeout, sessionSyncRoundtripDeadline = originalDial, originalRoundTrip
	})
	listener, err := net.Listen("unix", m.sessionSocketPath())
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	if _, err := m.requestSessionSyncResponse(ControlRequest{Type: "session_sync"}); err == nil {
		t.Fatal("request succeeded without a session-socket response")
	}
	conn := <-accepted
	_ = conn.Close()
	s := m.HATakeoverReadiness()
	if s.SessionSocketRequests != 1 || s.SessionSocketErrors != 1 || s.SessionSocketTimeouts != 1 {
		t.Fatalf("session-socket counters = requests %d errors %d timeouts %d, want 1/1/1",
			s.SessionSocketRequests, s.SessionSocketErrors, s.SessionSocketTimeouts)
	}
}
