package userspace

import (
	"encoding/json"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

type persistentNATClearHelper10784 struct {
	listener net.Listener
	response ControlResponse
	requests chan ControlRequest
}

func startPersistentNATClearHelper10784(t *testing.T, path string, response ControlResponse) *persistentNATClearHelper10784 {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen helper control socket: %v", err)
	}
	helper := &persistentNATClearHelper10784{
		listener: listener,
		response: response,
		requests: make(chan ControlRequest, 1),
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var request ControlRequest
				if err := json.NewDecoder(conn).Decode(&request); err != nil {
					return
				}
				helper.requests <- request
				_ = json.NewEncoder(conn).Encode(response)
			}()
		}
	}()
	return helper
}

func persistentNATBinding10784() *dataplane.PersistentNATBinding {
	return &dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.10"),
		SrcPort:  40000,
		NatIP:    netip.MustParseAddr("192.0.2.10"),
		NatPort:  50000,
		PoolName: "pool-a",
	}
}

func TestClearPersistentNATLeaseRoutesToHelperAndClearsMirror10784(t *testing.T) {
	m := New()
	m.proc = &exec.Cmd{}
	socket := filepath.Join(t.TempDir(), "control.sock")
	m.cfg.ControlSocket = socket
	helper := startPersistentNATClearHelper10784(t, socket, ControlResponse{
		OK:                      true,
		PersistentNatLeaseCount: 7,
	})
	table := m.bpfShim.GetPersistentNAT()
	table.Save(persistentNATBinding10784())
	adapter := NewLegacyDataPlaneAdapter(m)

	count, err := adapter.ClearPersistentNATLeases()
	if err != nil {
		t.Fatalf("ClearPersistentNATLeases: %v", err)
	}
	if count != 7 {
		t.Fatalf("authoritative cleared count = %d, want 7", count)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("helper verb = %q, want clear_persistent_nat_leases", got)
	}
	if table.Len() != 0 {
		t.Fatalf("SHOW mirror has %d bindings after successful helper clear, want 0", table.Len())
	}
}

func TestClearPersistentNATLeaseKeepsMirrorOnHelperFailure10784(t *testing.T) {
	m := New()
	m.proc = &exec.Cmd{}
	socket := filepath.Join(t.TempDir(), "control.sock")
	m.cfg.ControlSocket = socket
	helper := startPersistentNATClearHelper10784(t, socket, ControlResponse{
		OK:    false,
		Error: "allocator revoke failed",
	})
	table := m.bpfShim.GetPersistentNAT()
	table.Save(persistentNATBinding10784())
	adapter := NewLegacyDataPlaneAdapter(m)

	_, err := adapter.ClearPersistentNATLeases()
	if err == nil || !strings.Contains(err.Error(), "allocator revoke failed") {
		t.Fatalf("ClearPersistentNATLeases error = %v, want helper rejection", err)
	}
	if got := (<-helper.requests).Type; got != "clear_persistent_nat_leases" {
		t.Fatalf("helper verb = %q, want clear_persistent_nat_leases", got)
	}
	if table.Len() != 1 {
		t.Fatalf("SHOW mirror has %d bindings after failed helper clear, want 1", table.Len())
	}
}
