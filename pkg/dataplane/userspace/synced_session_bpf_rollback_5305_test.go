package userspace

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

// newMirrorFailManager5305 builds a Manager whose helper session mirror fails
// because no listener exists on the derived session socket. Real in-memory BPF
// maps are injected to verify Go does not pre-write imported rows (#5305).
func newMirrorFailManager5305(t *testing.T) *Manager {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	// No listener at <dir>/userspace-dp-sessions.sock -> mirror connect fails.
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)
	return m
}

// newMirrorOKManager5305 builds a helper that applies imported rows to the
// shared BPF maps before acknowledging them. Go only sends the RPC; this fake
// performs the helper-owned map effect.
func newMirrorOKManager5305(t *testing.T) *Manager {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	ln, err := net.Listen("unix", sessionSock)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				resp := ControlResponse{OK: false, Error: "invalid helper test request"}
				if err := json.NewDecoder(conn).Decode(&req); err == nil && req.SessionSync != nil {
					syncReq := req.SessionSync
					switch syncReq.AddrFamily {
					case dataplane.AFInet:
						key := rollbackKeyV4()
						if syncReq.Operation != "mirror_upsert" ||
							syncReq.SrcIP != net.IP(key.SrcIP[:]).String() ||
							syncReq.DstIP != net.IP(key.DstIP[:]).String() ||
							syncReq.SrcPort != networkUint16ToHost(key.SrcPort) ||
							syncReq.DstPort != networkUint16ToHost(key.DstPort) ||
							syncReq.Protocol != key.Protocol ||
							syncReq.IsReverse ||
							syncReq.IngressZoneID != 1 || syncReq.EgressZoneID != 2 ||
							syncReq.PolicyID != 42 {
							resp = ControlResponse{OK: false, Error: "unexpected IPv4 helper request"}
						} else if err := m.bpfShim.SetSessionV4(key,
							dataplane.SessionValue{IngressZone: syncReq.IngressZoneID,
								EgressZone: syncReq.EgressZoneID, PolicyID: syncReq.PolicyID}); err != nil {
							resp = ControlResponse{OK: false, Error: err.Error()}
						} else {
							resp = ControlResponse{OK: true}
						}
					case dataplane.AFInet6:
						key := rollbackKeyV6()
						if syncReq.Operation != "mirror_upsert" ||
							syncReq.SrcIP != net.IP(key.SrcIP[:]).String() ||
							syncReq.DstIP != net.IP(key.DstIP[:]).String() ||
							syncReq.SrcPort != networkUint16ToHost(key.SrcPort) ||
							syncReq.DstPort != networkUint16ToHost(key.DstPort) ||
							syncReq.Protocol != key.Protocol ||
							syncReq.IsReverse ||
							syncReq.IngressZoneID != 1 || syncReq.EgressZoneID != 2 ||
							syncReq.PolicyID != 42 {
							resp = ControlResponse{OK: false, Error: "unexpected IPv6 helper request"}
						} else if err := m.bpfShim.SetSessionV6(key,
							dataplane.SessionValueV6{IngressZone: syncReq.IngressZoneID,
								EgressZone: syncReq.EgressZoneID, PolicyID: syncReq.PolicyID}); err != nil {
							resp = ControlResponse{OK: false, Error: err.Error()}
						} else {
							resp = ControlResponse{OK: true}
						}
					default:
						resp = ControlResponse{OK: false, Error: "unexpected address family"}
					}
				}
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return m
}

func rollbackKeyV4() dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
}

func rollbackKeyV6() dataplane.SessionKeyV6 {
	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:db8:61::102").To16())
	copy(dstIP[:], net.ParseIP("2001:db8:80::200").To16())
	return dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
}

// TestSetClusterSyncedSessionV4HelperFailureLeavesMapUnchanged proves that a
// failed helper call leaves the Go-visible map untouched: absent rows remain
// absent and prior rows remain unchanged. The helper owns imported map writes.
func TestSetClusterSyncedSessionV4HelperFailureLeavesMapUnchanged5305(t *testing.T) {
	key := rollbackKeyV4()

	t.Run("absent-key-deleted", func(t *testing.T) {
		m := newMirrorFailManager5305(t)
		val := dataplane.SessionValue{IsReverse: 0, IngressZone: 1, EgressZone: 2}

		err := m.SetClusterSyncedSessionV4(key, val)
		if err == nil {
			t.Fatal("SetClusterSyncedSessionV4() = nil, want mirror failure")
		}
		// A failed helper call must not create a local orphan row.
		if _, getErr := m.bpfShim.GetSessionV4(key); !errors.Is(getErr, ebpf.ErrKeyNotExist) {
			t.Fatalf("BPF entry appeared after a failed helper call: GetSessionV4 err = %v, want ErrKeyNotExist", getErr)
		}
		// Health behavior preserved: takeover stays disarmed.
		if !m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = false, want true")
		}
		if m.sessionMirrorErr == "" {
			t.Fatal("sessionMirrorErr is empty, want non-empty")
		}
	})

	t.Run("prior-value-unchanged", func(t *testing.T) {
		m := newMirrorFailManager5305(t)
		// Seed a distinguishable prior value directly on the BPF mirror.
		prior := dataplane.SessionValue{IsReverse: 0, IngressZone: 7, EgressZone: 9, PolicyID: 111}
		if err := m.bpfShim.SetSessionV4(key, prior); err != nil {
			t.Fatalf("seed prior BPF entry: %v", err)
		}
		want, err := m.bpfShim.GetSessionV4(key) // canonical round-tripped prior
		if err != nil {
			t.Fatalf("read seeded prior: %v", err)
		}

		// A failed helper call must not replace the prior value.
		val := dataplane.SessionValue{IsReverse: 0, IngressZone: 1, EgressZone: 2, PolicyID: 222}
		if err := m.SetClusterSyncedSessionV4(key, val); err == nil {
			t.Fatal("SetClusterSyncedSessionV4() = nil, want mirror failure")
		}

		got, err := m.bpfShim.GetSessionV4(key)
		if err != nil {
			t.Fatalf("prior BPF entry vanished after failed helper call: %v", err)
		}
		if got != want {
			t.Fatalf("failed helper call changed prior BPF entry: got %+v, want %+v", got, want)
		}
	})
}

// TestSetClusterSyncedSessionV6HelperFailureLeavesMapUnchanged is the IPv6
// analogue.
func TestSetClusterSyncedSessionV6HelperFailureLeavesMapUnchanged5305(t *testing.T) {
	key := rollbackKeyV6()

	t.Run("absent-key-stays-absent", func(t *testing.T) {
		m := newMirrorFailManager5305(t)
		val := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 1, EgressZone: 2}

		err := m.SetClusterSyncedSessionV6(key, val)
		if err == nil {
			t.Fatal("SetClusterSyncedSessionV6() = nil, want mirror failure")
		}
		if _, getErr := m.bpfShim.GetSessionV6(key); !errors.Is(getErr, ebpf.ErrKeyNotExist) {
			t.Fatalf("BPF entry appeared after a failed helper call: GetSessionV6 err = %v, want ErrKeyNotExist", getErr)
		}
		if !m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = false, want true")
		}
		if m.sessionMirrorErr == "" {
			t.Fatal("sessionMirrorErr is empty, want non-empty")
		}
	})

	t.Run("prior-value-unchanged", func(t *testing.T) {
		m := newMirrorFailManager5305(t)
		prior := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 7, EgressZone: 9, PolicyID: 111}
		if err := m.bpfShim.SetSessionV6(key, prior); err != nil {
			t.Fatalf("seed prior BPF entry: %v", err)
		}
		want, err := m.bpfShim.GetSessionV6(key)
		if err != nil {
			t.Fatalf("read seeded prior: %v", err)
		}

		val := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 1, EgressZone: 2, PolicyID: 222}
		if err := m.SetClusterSyncedSessionV6(key, val); err == nil {
			t.Fatal("SetClusterSyncedSessionV6() = nil, want mirror failure")
		}

		got, err := m.bpfShim.GetSessionV6(key)
		if err != nil {
			t.Fatalf("prior BPF entry vanished after failed helper call: %v", err)
		}
		if got != want {
			t.Fatalf("failed helper call changed prior BPF entry: got %+v, want %+v", got, want)
		}
	})
}

// TestSetClusterSyncedSessionHelperWriteVisibleAndHealthy proves that a
// successful helper-owned map write is visible and clears the sticky
// mirror-failure flag (#5247), for both address families.
func TestSetClusterSyncedSessionHelperWriteVisibleAndHealthy5305(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		m := newMirrorOKManager5305(t)
		// A prior transient failure latched the sticky flag.
		m.recordSessionMirrorFailureLocked(errors.New("transient control-socket failure"))

		key := rollbackKeyV4()
		val := dataplane.SessionValue{IsReverse: 0, IngressZone: 1, EgressZone: 2, PolicyID: 42}
		if err := m.SetClusterSyncedSessionV4(key, val); err != nil {
			t.Fatalf("SetClusterSyncedSessionV4: %v", err)
		}
		got, err := m.bpfShim.GetSessionV4(key)
		if err != nil {
			t.Fatalf("forward entry not installed on success path: %v", err)
		}
		if got.PolicyID != 42 || got.IngressZone != 1 || got.EgressZone != 2 {
			t.Fatalf("installed value = %+v, want PolicyID=42 zones 1/2", got)
		}
		if m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = true after successful mirror, want false (#5247)")
		}
		if m.sessionMirrorErr != "" {
			t.Fatalf("sessionMirrorErr = %q after successful mirror, want empty", m.sessionMirrorErr)
		}
	})

	t.Run("v6", func(t *testing.T) {
		m := newMirrorOKManager5305(t)
		m.recordSessionMirrorFailureLocked(errors.New("transient control-socket failure"))

		key := rollbackKeyV6()
		val := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 1, EgressZone: 2, PolicyID: 42}
		if err := m.SetClusterSyncedSessionV6(key, val); err != nil {
			t.Fatalf("SetClusterSyncedSessionV6: %v", err)
		}
		got, err := m.bpfShim.GetSessionV6(key)
		if err != nil {
			t.Fatalf("forward entry not installed on success path: %v", err)
		}
		if got.PolicyID != 42 || got.IngressZone != 1 || got.EgressZone != 2 {
			t.Fatalf("installed value = %+v, want PolicyID=42 zones 1/2", got)
		}
		if m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = true after successful mirror, want false (#5247)")
		}
		if m.sessionMirrorErr != "" {
			t.Fatalf("sessionMirrorErr = %q after successful mirror, want empty", m.sessionMirrorErr)
		}
	})
}
