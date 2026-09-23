package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// scriptedClearFake10512 serves scripted mirror_clear_chunk responses:
// one per request, in order. A nil entry hangs (never responds); a
// fail entry responds OK:false. It records every request for shape pins.
type scriptedClearFake10512 struct {
	mu    sync.Mutex
	ln    net.Listener
	script []ControlResponse
	failAt map[int]bool
	reqs  []SessionSyncRequest
}

func startScriptedClearFake10512(t *testing.T, sockPath string, script []ControlResponse, failAt map[int]bool) *scriptedClearFake10512 {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen clear fake: %v", err)
	}
	f := &scriptedClearFake10512{ln: ln, script: script, failAt: failAt}
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
				resp := ControlResponse{OK: true}
				if idx < len(f.script) {
					resp = f.script[idx]
				}
				if f.failAt[idx] {
					resp = ControlResponse{OK: false, Error: "injected clear-chunk failure"}
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
	dir := t.TempDir()
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	return m, sessionSock
}

// #5881 twin (unprivileged): a helper clear-chunk IPC failure is
// REPORTED, not nil — a nil return with a live helper is the security
// bug (mirror looks revoked while the helper may still forward).
func TestClearAllUnprivilegedSurfacesHelperError10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	fake := startScriptedClearFake10512(t, sessionSock,
		[]ControlResponse{{OK: true}}, map[int]bool{0: true})

	_, _, err := m.ClearAllSessions()
	if err == nil {
		t.Fatal("ClearAllSessions returned nil despite a helper clear-chunk failure")
	}
	if got := len(fake.requests()); got != 1 {
		t.Fatalf("helper got %d requests, want 1 (the failing chunk)", got)
	}
}

// #5304 twin (unprivileged): every chunk is fetched through the
// continuation — a multi-chunk clear drives chunk 2 with chunk 1's
// continuation + fence, and completes only at the terminal chunk.
func TestClearAllUnprivilegedFetchesEveryChunk10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	fake := startScriptedClearFake10512(t, sessionSock, []ControlResponse{
		{OK: true, SessionMirrorV4Count: 2, SessionMirrorContinuation: "c1", SessionMirrorFenceID: 41},
		{OK: true, SessionMirrorV4Count: 3, SessionMirrorComplete: true},
	}, nil)

	v4, _, err := m.ClearAllSessions()
	if err != nil {
		t.Fatalf("multi-chunk clear: %v", err)
	}
	reqs := fake.requests()
	if len(reqs) != 2 {
		t.Fatalf("helper got %d requests, want 2 (both chunks)", len(reqs))
	}
	if reqs[1].ClearContinuation != "c1" || reqs[1].ClearFenceID != 41 {
		t.Errorf("chunk 2 carried continuation=%q fence=%d, want c1/41",
			reqs[1].ClearContinuation, reqs[1].ClearFenceID)
	}
	if v4 != 3 {
		t.Errorf("v4 count = %d, want 3 (terminal chunk's authoritative count)", v4)
	}
}

// #5380 twin (unprivileged): a second-chunk failure fast-fails the
// clear — the error surfaces, the loop exits, no third chunk is
// attempted (no per-chunk deadline stacking behind a wedged helper).
func TestClearAllUnprivilegedFastFailsOnLaterChunk10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	fake := startScriptedClearFake10512(t, sessionSock, []ControlResponse{
		{OK: true, SessionMirrorContinuation: "c1", SessionMirrorFenceID: 41},
		{OK: true},
	}, map[int]bool{1: true})

	_, _, err := m.ClearAllSessions()
	if err == nil {
		t.Fatal("ClearAllSessions returned nil despite a second-chunk failure")
	}
	if got := len(fake.requests()); got != 2 {
		t.Fatalf("helper got %d requests, want 2 (fail fast, no third chunk)", got)
	}
}

// #9364 control-2 twin (unprivileged): ClearAll stays bare at the public
// boundary (no routing domain on the chunk requests) while the helper
// enumerates all domains natively (authoritative counts flow back).
func TestClearAllUnprivilegedStaysBareWithHelperCounts10512(t *testing.T) {
	m, sessionSock := newClearOnlyManager10512(t)
	fake := startScriptedClearFake10512(t, sessionSock, []ControlResponse{
		{OK: true, SessionMirrorV4Count: 7, SessionMirrorV6Count: 5, SessionMirrorComplete: true},
	}, nil)

	v4, v6, err := m.ClearAllSessions()
	if err != nil {
		t.Fatalf("bare clear: %v", err)
	}
	for i, r := range fake.requests() {
		if r.RoutingDomain != 0 {
			t.Errorf("chunk %d carried routing_domain=%d, want 0 (bare boundary)", i, r.RoutingDomain)
		}
		if r.Operation != "mirror_clear_chunk" {
			t.Errorf("chunk %d op = %q, want mirror_clear_chunk", i, r.Operation)
		}
	}
	if v4 != 7 || v6 != 5 {
		t.Errorf("counts = (%d, %d), want (7, 5) (helper-native enumeration)", v4, v6)
	}
}
