// #5881: in userspace mode the Rust helper owns AUTHORITATIVE forwarding
// session state; the BPF maps are mirrors. ClearAllSessions clears the mirror
// and issues a per-chunk authoritative "delete" to the helper, but before this
// fix a helper-delete IPC failure was only logged inside the sync path and
// could not affect the returned error — so `clear security flow session all`
// reported SUCCESS while the helper kept forwarding under the supposedly
// revoked sessions. This binds the propagation: a helper-delete failure must
// surface as a non-nil ClearAllSessions error (with the mirror's partial counts
// still returned, matching the #5882 non-atomic clear-all reporting contract),
// and the all-succeed control path must still report clean success.
//
// FAIL-ON-REVERT: neutralizing the propagation in ClearAllSessions (dropping
// the `if helperErr != nil { return ... }` block so the method returns a nil
// error whenever the mirror clear succeeded) makes the injected-failure subtest
// go RED on its "returned nil error despite a helper-delete IPC failure"
// assertion. Reverting deleteHelperSessions*/syncSessionRequestsLocked back to
// their void signatures re-breaks the same assertion.
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

// fakeHelperSessionSocket is a stand-in for the Rust helper's session control
// socket. Unlike fakeHelperDeleteRecorder it can be configured to FAIL every
// sync_session request (respond OK:false) so a test can drive the helper-IPC-
// failure path of ClearAllSessions, or accept them (OK:true) for the control.
type fakeHelperSessionSocket struct {
	ln   net.Listener
	mu   sync.Mutex
	fail bool
	reqs int
	ops  []string
}

func startFakeHelperSessionSocket(t *testing.T, sockPath string, fail bool) *fakeHelperSessionSocket {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen helper session socket: %v", err)
	}
	f := &fakeHelperSessionSocket{ln: ln, fail: fail}
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
				f.reqs++
				if req.SessionSync != nil {
					f.ops = append(f.ops, req.SessionSync.Operation)
				}
				fail := f.fail
				f.mu.Unlock()
				resp := ControlResponse{OK: true}
				if req.SessionSync != nil && fail {
					resp = ControlResponse{OK: false, Error: "injected helper delete failure"}
				} else if req.SessionSync != nil {
					// Single-shot success: the helper cleared and
					// reports its authoritative counts.
					resp = ControlResponse{OK: true, SessionMirrorV4Count: 1,
						SessionMirrorV6Count: 1, SessionMirrorComplete: true}
				}
				// The client blocks on this response, so by the time the
				// adapter call returns the request above is fully handled.
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return f
}

func (f *fakeHelperSessionSocket) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs
}

func (f *fakeHelperSessionSocket) sawOp(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, got := range f.ops {
		if got == op {
			n++
		}
	}
	return n
}

// seedOneSessionPerFamily installs one v4 and one v6 forward session in the
// mirror so the clear has authoritative helper deletes to issue.
func seedOneSessionPerFamily5881(t *testing.T, m *Manager) {
	t.Helper()
	v4 := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 77},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(51000),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	if err := m.bpfShim.SetSessionV4(v4, dataplane.SessionValue{}); err != nil {
		t.Fatalf("seed v4 session: %v", err)
	}
	var s6, d6 [16]byte
	copy(s6[:], net.ParseIP("2001:559:8585:ef00::77").To16())
	copy(d6[:], net.ParseIP("2001:559:8585:80::200").To16())
	v6 := dataplane.SessionKeyV6{
		SrcIP:    s6,
		DstIP:    d6,
		SrcPort:  hostToNetwork16(41000),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	if err := m.bpfShim.SetSessionV6(v6, dataplane.SessionValueV6{}); err != nil {
		t.Fatalf("seed v6 session: %v", err)
	}
}

func newClearManager5881(t *testing.T) (*Manager, *LegacyDataPlaneAdapter, string) {
	t.Helper()
	// A SHORT temp-dir prefix (not t.TempDir(), which embeds the long
	// sub-test name) keeps the AF_UNIX socket path under the 108-byte
	// sun_path limit — the "bind: invalid argument" trap. Respects TMPDIR
	// (run with TMPDIR=/tmp), so a long system TMPDIR does not push us over.
	dir, err := os.MkdirTemp("", "x5881")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	injectSessionMaps(t, m)
	seedOneSessionPerFamily5881(t, m)
	return m, NewLegacyDataPlaneAdapter(m), filepath.Join(dir, "userspace-dp-sessions.sock")
}

func TestClearAllSessionsSurfacesHelperDeleteError5881(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}

	// A helper-delete IPC failure must be REPORTED. A clean nil return here is
	// the security bug: the mirror is empty (looks revoked) while the
	// authoritative helper may still be forwarding under the "cleared" session.
	t.Run("helper_delete_failure_is_reported", func(t *testing.T) {
		m, adapter, sessionSock := newClearManager5881(t)
		fake := startFakeHelperSessionSocket(t, sessionSock, true)

		v4, v6, err := adapter.ClearAllSessions()
		if err == nil {
			t.Fatal("ClearAllSessions returned nil error despite a helper-delete IPC failure — a revoked session may still be forwarding (#5881)")
		}
		if fake.requestCount() == 0 {
			t.Fatal("helper never received a delete request; the test did not exercise the propagation path")
		}
		if got := fake.sawOp("mirror_clear_chunk"); got != 1 {
			t.Fatalf("helper saw %d clear ops, want exactly 1 single-shot", got)
		}
		// Fail-closed atomic (P11, revises #5882): nothing confirmed,
		// so (0,0) — the old "mirror cleared + partial counts" belonged
		// to the Go-driven chunked design, where Go swept the mirror
		// itself. Under single-shot Go sweeps nothing (the mirror is
		// the helper's read model); a failed clear leaves it intact.
		if v4 != 0 || v6 != 0 {
			t.Errorf("counts = (%d, %d), want (0, 0) (nothing confirmed)", v4, v6)
		}
		if mv4, mv6 := m.bpfShim.SessionCount(); mv4 != 1 || mv6 != 1 {
			t.Errorf("mirror count = (%d, %d), want (1, 1) intact — Go must not sweep on helper failure", mv4, mv6)
		}
	})

	// Control: when every authoritative helper delete succeeds, the clear is a
	// clean success — the fix must not turn healthy clears into errors.
	t.Run("all_deletes_succeed_is_success", func(t *testing.T) {
		m, adapter, sessionSock := newClearManager5881(t)
		fake := startFakeHelperSessionSocket(t, sessionSock, false)

		v4, v6, err := adapter.ClearAllSessions()
		if err != nil {
			t.Fatalf("ClearAllSessions returned error on the all-succeed path: %v", err)
		}
		if v4 != 1 || v6 != 1 {
			t.Errorf("counts = (%d, %d), want (1, 1) (helper-confirmed)", v4, v6)
		}
		if got := fake.sawOp("mirror_clear_chunk"); got != 1 {
			t.Errorf("helper saw %d clear ops, want exactly 1", got)
		}
		// The fake cannot clear BPF (no maps behind it); in production
		// the real helper's per-key deletes empty the mirror. What this
		// pins is the Go side: Go itself sweeps nothing (single-shot —
		// a reintroduced Go sweep would empty the mirror and fail here).
		if mv4, mv6 := m.bpfShim.SessionCount(); mv4 != 1 || mv6 != 1 {
			t.Errorf("mirror count = (%d, %d), want (1, 1) (Go sweeps nothing; only a real helper clears BPF)", mv4, mv6)
		}
	})
}
