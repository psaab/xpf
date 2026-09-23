package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

// fakeHelperDeleteRecorder is a minimal stand-in for the Rust helper's session
// control socket. It records every sync_session request it receives so a test
// can assert the authoritative helper actually saw the delete (#5096).
type fakeHelperDeleteRecorder struct {
	ln   net.Listener
	mu   sync.Mutex
	reqs []SessionSyncRequest
	// clearV4/clearV6 are the authoritative counts the fake reports
	// for a mirror_clear_chunk (single-shot success shape).
	clearV4, clearV6 int
}

func startFakeHelperDeleteRecorder(t *testing.T, sockPath string) *fakeHelperDeleteRecorder {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen helper session socket: %v", err)
	}
	r := &fakeHelperDeleteRecorder{ln: ln}
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
				op := ""
				if err := json.NewDecoder(conn).Decode(&req); err == nil {
					if req.SessionSync != nil {
						op = req.SessionSync.Operation
						r.mu.Lock()
						r.reqs = append(r.reqs, *req.SessionSync)
						r.mu.Unlock()
					}
				}
				// The client blocks on this response, so by the time the
				// adapter call returns the request above is already recorded.
				resp := ControlResponse{OK: true}
				if op == "mirror_clear_chunk" {
					r.mu.Lock()
					v4, v6 := r.clearV4, r.clearV6
					r.mu.Unlock()
					resp = ControlResponse{OK: true,
						SessionMirrorV4Count: uint64(v4), SessionMirrorV6Count: uint64(v6),
						SessionMirrorComplete: true}
				}
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return r
}

// deletedIP reports whether a request with the given operation and src/dst IP
// strings was recorded.
func (r *fakeHelperDeleteRecorder) deletedIP(op, srcIP, dstIP string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, req := range r.reqs {
		if req.Operation == op && req.SrcIP == srcIP && req.DstIP == dstIP {
			return true
		}
	}
	return false
}

func (r *fakeHelperDeleteRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func (r *fakeHelperDeleteRecorder) opCount(op string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, req := range r.reqs {
		if req.Operation == op {
			n++
		}
	}
	return n
}

// TestBatchAndClearRouteToHelper5096 is the fail-on-revert guard for #5096.
//
// The batch/clear session mutations must reach the authoritative Rust helper,
// not just the BPF mirror. Reverting either the LegacyDataPlaneAdapter overrides
// (so Go promotion dispatches to the embedded bpfShim only) OR the Manager's
// helper-delete plumbing leaves the fake helper with zero recorded deletes and
// fails this test RED — the exact partial-apply / clear-all-doesn't-clear
// security bypass the issue describes.
func TestBatchAndClearRouteToHelper5096(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	rec := startFakeHelperDeleteRecorder(t, sessionSock)

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	injectSessionMaps(t, m)

	// The adapter is what dataPlaneSessionStore.s.dp resolves to on the
	// userspace path, so exercising it reproduces the real dispatch that the
	// promotion bug corrupts.
	adapter := NewLegacyDataPlaneAdapter(m)

	// --- BatchDeleteSessions (IPv4) ---
	v4Key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	if err := m.bpfShim.SetSessionV4(v4Key, dataplane.SessionValue{}); err != nil {
		t.Fatalf("seed v4 session: %v", err)
	}
	if _, err := adapter.BatchDeleteSessions([]dataplane.SessionKey{v4Key}); err != nil {
		t.Fatalf("BatchDeleteSessions: %v", err)
	}
	if !rec.deletedIP("delete", "10.0.61.102", "172.16.80.200") {
		t.Fatalf("BatchDeleteSessions did not send helper delete for v4 key; recorded=%d", rec.count())
	}

	// --- BatchDeleteSessionsV6 ---
	var v6Src, v6Dst [16]byte
	copy(v6Src[:], net.ParseIP("2001:559:8585:ef00::100").To16())
	copy(v6Dst[:], net.ParseIP("2001:559:8585:80::200").To16())
	v6Key := dataplane.SessionKeyV6{
		SrcIP:    v6Src,
		DstIP:    v6Dst,
		SrcPort:  hostToNetwork16(40000),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	if err := m.bpfShim.SetSessionV6(v6Key, dataplane.SessionValueV6{}); err != nil {
		t.Fatalf("seed v6 session: %v", err)
	}
	if _, err := adapter.BatchDeleteSessionsV6([]dataplane.SessionKeyV6{v6Key}); err != nil {
		t.Fatalf("BatchDeleteSessionsV6: %v", err)
	}
	if !rec.deletedIP("delete", "2001:559:8585:ef00::100", "2001:559:8585:80::200") {
		t.Fatalf("BatchDeleteSessionsV6 did not send helper delete for v6 key; recorded=%d", rec.count())
	}

	// --- ClearAllSessions (v4 + v6) ---
	clearV4 := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 50},
		DstIP:    [4]byte{172, 16, 80, 201},
		SrcPort:  hostToNetwork16(33333),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	if err := m.bpfShim.SetSessionV4(clearV4, dataplane.SessionValue{}); err != nil {
		t.Fatalf("seed clear v4 session: %v", err)
	}
	var clr6Src, clr6Dst [16]byte
	copy(clr6Src[:], net.ParseIP("2001:559:8585:ef00::200").To16())
	copy(clr6Dst[:], net.ParseIP("2001:559:8585:80::201").To16())
	clearV6 := dataplane.SessionKeyV6{
		SrcIP:    clr6Src,
		DstIP:    clr6Dst,
		SrcPort:  hostToNetwork16(44444),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	if err := m.bpfShim.SetSessionV6(clearV6, dataplane.SessionValueV6{}); err != nil {
		t.Fatalf("seed clear v6 session: %v", err)
	}
	rec.clearV4, rec.clearV6 = 1, 1
	if v4, v6, err := adapter.ClearAllSessions(); err != nil {
		t.Fatalf("ClearAllSessions: %v", err)
	} else if v4 != 1 || v6 != 1 {
		t.Fatalf("ClearAllSessions counts = (%d, %d), want (1, 1) helper-confirmed", v4, v6)
	}
	// Single-shot: one clear op reaches the authoritative helper (no
	// per-key fan-out — the helper enumerates natively). Reverting to a
	// mirror-only clear leaves zero ops and fails RED (#5096 bypass).
	if got := rec.opCount("mirror_clear_chunk"); got != 1 {
		t.Fatalf("ClearAllSessions sent %d helper clear ops, want exactly 1; recorded=%d", got, rec.count())
	}
}
