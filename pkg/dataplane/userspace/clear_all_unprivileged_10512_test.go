package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// scriptedClearFake10512 serves scripted mirror_clear_chunk responses
// and records every request for shape pins. Single-shot: the script
// normally holds one response; extra entries observe over-eager
// drivers (a second request is itself the failure).
type scriptedClearFake10512 struct {
	mu     sync.Mutex
	ln     net.Listener
	script []ControlResponse
	reqs   []SessionSyncRequest
}

func startScriptedClearFake10512(t *testing.T, sockPath string, script []ControlResponse) *scriptedClearFake10512 {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen clear fake: %v", err)
	}
	f := &scriptedClearFake10512{ln: ln, script: script}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				f.mu.Lock()
				idx := len(f.reqs)
				if req.SessionSync != nil {
					f.reqs = append(f.reqs, *req.SessionSync)
				}
				resp := ControlResponse{OK: true, SessionMirrorComplete: true}
				if idx < len(f.script) {
					resp = f.script[idx]
				}
				f.mu.Unlock()
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return f
}

func (f *scriptedClearFake10512) requests() []SessionSyncRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SessionSyncRequest(nil), f.reqs...)
}

// newClearOnlyManager10512 builds a Manager that can drive
// mirror_clear_chunk without BPF: no maps, no seed. proc.Process is a
// non-nil stub — ClearAll only nil-checks it (no signal is ever sent),
// and a live child cannot exist in unprivileged CI.
func newClearOnlyManager10512(t *testing.T) (*Manager, string) {
	t.Helper()
	// Short prefix: sun_path is 108 bytes and these test names are
	// long — t.TempDir() + userspace-dp-sessions.sock would exceed it
	// (the #5881 fixture's explicit lesson).
	dir, err := os.MkdirTemp("", "x10512")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	return m, sessionSock
}

// #5881 twin (unprivileged): a helper clear IPC failure is REPORTED
// with (0,0) — nothing confirmed — never a masked success.
func TestClearAllUnprivilegedSurfacesHelperError10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	fake := startScriptedClearFake10512(t, sessionSock,
		[]ControlResponse{{OK: false, Error: "injected clear failure"}})

	v4, v6, err := m.ClearAllSessions()
	if err == nil {
		t.Fatal("ClearAllSessions returned nil despite a helper clear failure")
	}
	if v4 != 0 || v6 != 0 {
		t.Errorf("counts = (%d, %d), want (0, 0) (nothing confirmed)", v4, v6)
	}
	if got := len(fake.requests()); got != 1 {
		t.Fatalf("helper got %d requests, want exactly 1", got)
	}
}

// Success: exactly one bare mirror_clear_chunk; counts are the
// helper-confirmed deleted sessions (#9364 control-2: bare boundary,
// helper-native enumeration).
func TestClearAllUnprivilegedSuccessReportsHelperCounts10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	fake := startScriptedClearFake10512(t, sessionSock, []ControlResponse{
		{OK: true, SessionMirrorV4Count: 7, SessionMirrorV6Count: 5, SessionMirrorComplete: true},
	})

	v4, v6, err := m.ClearAllSessions()
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if v4 != 7 || v6 != 5 {
		t.Errorf("counts = (%d, %d), want (7, 5) (helper-confirmed)", v4, v6)
	}
	reqs := fake.requests()
	if len(reqs) != 1 {
		t.Fatalf("helper got %d requests, want exactly 1 (single-shot)", len(reqs))
	}
	if reqs[0].Operation != "mirror_clear_chunk" {
		t.Errorf("op = %q, want mirror_clear_chunk", reqs[0].Operation)
	}
	if reqs[0].RoutingDomain != 0 {
		t.Errorf("chunk carried routing_domain=%d, want 0 (bare boundary)", reqs[0].RoutingDomain)
	}
}

// Incomplete with no continuation is a stranded clear — error, (0,0).
func TestClearAllUnprivilegedIncompleteWithoutTokenErrors10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	startScriptedClearFake10512(t, sessionSock, []ControlResponse{
		{OK: true, SessionMirrorV4Count: 2},
	})

	v4, v6, err := m.ClearAllSessions()
	if err == nil {
		t.Fatal("ClearAllSessions returned nil for incomplete-without-continuation")
	}
	if v4 != 0 || v6 != 0 {
		t.Errorf("counts = (%d, %d), want (0, 0)", v4, v6)
	}
}

// P10: complete WITH a continuation is contradictory — fail fast,
// never page on (the helper never pages at all).
func TestClearAllUnprivilegedCompleteWithContinuationErrors10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	startScriptedClearFake10512(t, sessionSock, []ControlResponse{
		{OK: true, SessionMirrorComplete: true, SessionMirrorContinuation: "c1"},
	})

	if _, _, err := m.ClearAllSessions(); err == nil {
		t.Fatal("ClearAllSessions accepted complete-with-continuation")
	}
}

// Any continuation at all is a contract breach under single-shot.
func TestClearAllUnprivilegedAnyContinuationErrors10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	fake := startScriptedClearFake10512(t, sessionSock, []ControlResponse{
		{OK: true, SessionMirrorContinuation: "c1", SessionMirrorFenceID: 41},
		{OK: true, SessionMirrorComplete: true},
	})

	if _, _, err := m.ClearAllSessions(); err == nil {
		t.Fatal("ClearAllSessions accepted a continuation (must fail, not page on)")
	}
	if got := len(fake.requests()); got != 1 {
		t.Fatalf("helper got %d requests, want 1 (fail on first continuation)", got)
	}
}

// No helper, no clear: (0,0) + unreachable, no dial attempted.
func TestClearAllUnprivilegedHelperDownErrors10512(t *testing.T) {
	m, _ := newClearOnlyManager10512(t)
	m.proc = nil

	v4, v6, err := m.ClearAllSessions()
	if err == nil {
		t.Fatal("ClearAllSessions with no helper must error")
	}
	if v4 != 0 || v6 != 0 {
		t.Errorf("counts = (%d, %d), want (0, 0)", v4, v6)
	}
}

// P8: a terminal arriving past the absolute deadline fails (even a
// complete one) — the post-RPC recheck fires. The deadline is shrunk
// to negative so any response overruns, deterministically.
func TestClearAllUnprivilegedOverrunTerminalErrors10512(t *testing.T) {
	orig := clearAllDeadline
	clearAllDeadline = -time.Second
	t.Cleanup(func() { clearAllDeadline = orig })

	m, sessionSock := newClearOnlyManager10512(t)
	startScriptedClearFake10512(t, sessionSock, []ControlResponse{
		{OK: true, SessionMirrorV4Count: 7, SessionMirrorV6Count: 5, SessionMirrorComplete: true},
	})

	if _, _, err := m.ClearAllSessions(); err == nil {
		t.Fatal("ClearAllSessions accepted a terminal past the deadline (no post-RPC recheck)")
	}
}
