package userspace

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

// TestClearAllSingleShotWithoutKeyEnumeration5304 guards the bounded-memory
// single-shot clear (#5304): Go sends ONE mirror_clear_chunk and holds no
// key snapshot at all — the helper enumerates natively under its own cap.
// It seeds many distinct v4 + v6 forward sessions, runs the clear through
// the adapter (the real dispatch path), and asserts (a) the helper saw
// exactly one clear op (no per-key fan-out — any reintroduced enumeration
// shows up as 2*n requests), (b) the returned counts are the helper's,
// and (c) Go swept nothing itself (mirror intact — the fake cannot clear
// BPF; only a real helper's per-key deletes empty it in production).
//
// fail-on-revert: reintroduce Go-side key enumeration (per-key deletes
// or chunk callbacks) and the single-op assert goes RED — the #5096
// forward-under-revoked-decision bypass on a bulk clear, now via the
// opposite failure (Go enumerating what the helper owns).
func TestClearAllSingleShotWithoutKeyEnumeration5304(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	// Short prefix: the sun_path limit (see newClearManager5881).
	dir, err := os.MkdirTemp("", "x5304")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	rec := startFakeHelperDeleteRecorder(t, sessionSock)

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	injectSessionMaps(t, m)
	adapter := NewLegacyDataPlaneAdapter(m)

	// Seed distinct v4 + v6 forward sessions in the mirror. injectSessionMaps
	// caps the maps at 1024 entries, so stay well under it.
	const n = 200
	const v4Dst = "172.16.80.200"
	const v6Dst = "2001:559:8585:80::200"
	var v6DstB [16]byte
	copy(v6DstB[:], net.ParseIP(v6Dst).To16())

	for i := 0; i < n; i++ {
		var s4 [4]byte
		binary.BigEndian.PutUint32(s4[:], 0x0a000000|uint32(i+1)) // 10.x.x.x, distinct
		k4 := dataplane.SessionKey{
			SrcIP:    s4,
			DstIP:    [4]byte{172, 16, 80, 200},
			SrcPort:  hostToNetwork16(uint16(20000 + i)),
			DstPort:  hostToNetwork16(443),
			Protocol: 6,
		}
		if err := m.bpfShim.SetSessionV4(k4, dataplane.SessionValue{}); err != nil {
			t.Fatalf("seed v4 %d: %v", i, err)
		}

		var s6 [16]byte
		copy(s6[:], net.ParseIP("2001:559:8585:ef00::").To16())
		binary.BigEndian.PutUint32(s6[12:], uint32(i+1))
		k6 := dataplane.SessionKeyV6{
			SrcIP:    s6,
			DstIP:    v6DstB,
			SrcPort:  hostToNetwork16(uint16(30000 + i)),
			DstPort:  hostToNetwork16(443),
			Protocol: 6,
		}
		if err := m.bpfShim.SetSessionV6(k6, dataplane.SessionValueV6{}); err != nil {
			t.Fatalf("seed v6 %d: %v", i, err)
		}
	}

	if v4, v6 := m.bpfShim.SessionCount(); v4 != n || v6 != n {
		t.Fatalf("pre-clear mirror count = (%d, %d), want (%d, %d)", v4, v6, n, n)
	}
	rec.clearV4, rec.clearV6 = n, n

	v4Deleted, v6Deleted, err := adapter.ClearAllSessions()
	if err != nil {
		t.Fatalf("ClearAllSessions: %v", err)
	}
	if v4Deleted != n || v6Deleted != n {
		t.Errorf("deleted = (%d, %d), want (%d, %d) (helper-confirmed)", v4Deleted, v6Deleted, n, n)
	}

	// (a) exactly one clear op — no per-key fan-out, no enumeration.
	if got := rec.opCount("mirror_clear_chunk"); got != 1 {
		t.Errorf("helper saw %d clear ops, want exactly 1 (single-shot, no key enumeration)", got)
	}
	if got := rec.count(); got != 1 {
		t.Errorf("helper saw %d total requests, want 1", got)
	}

	// (b) Go swept nothing itself (single-shot — the fake cannot clear
	// BPF; a reintroduced Go sweep would empty the mirror and fail here).
	if v4, v6 := m.bpfShim.SessionCount(); v4 != n || v6 != n {
		t.Errorf("post-clear mirror count = (%d, %d), want (%d, %d) intact (Go sweeps nothing)", v4, v6, n, n)
	}
}
