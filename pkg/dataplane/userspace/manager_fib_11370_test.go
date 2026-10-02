package userspace

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDumpFIBRequestsAndDecodesHelperSnapshot11370(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer listener.Close()

	requests := make(chan ControlRequest, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		var req ControlRequest
		if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
			serverErr <- err
			return
		}
		requests <- req
		response := ControlResponse{
			OK:            true,
			FIBGeneration: 9,
			FIBRoutes: []FibRouteWire{{
				Table:       "blue.inet.0",
				Family:      "inet",
				Destination: "203.0.113.0/24",
				Kind:        "route",
				NextHops: []FibNextHopWire{{
					NextHop:          "192.0.2.1",
					Ifindex:          7,
					Interface:        "ge-0/0/0",
					TunnelEndpointID: 2,
					Weight:           3,
				}},
				Preference:   17,
				MTU:          1400,
				RulePriority: 42,
			}},
		}
		if err := json.NewEncoder(conn).Encode(response); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	manager := New()
	manager.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	manager.cfg.ControlSocket = socket
	generation, routes, err := manager.DumpFIB()
	if err != nil {
		t.Fatalf("DumpFIB: %v", err)
	}
	if generation != 9 {
		t.Fatalf("generation = %d, want 9", generation)
	}
	if len(routes) != 1 {
		t.Fatalf("routes = %d rows, want 1", len(routes))
	}
	got := routes[0]
	if got.Table != "blue.inet.0" || got.Family != "inet" || got.Destination != "203.0.113.0/24" ||
		got.Kind != "route" || got.Preference != 17 || got.MTU != 1400 || got.RulePriority != 42 {
		t.Fatalf("decoded route = %+v", got)
	}
	if len(got.NextHops) != 1 || got.NextHops[0] != (FibNextHopWire{
		NextHop: "192.0.2.1", Ifindex: 7, Interface: "ge-0/0/0", TunnelEndpointID: 2, Weight: 3,
	}) {
		t.Fatalf("decoded next hops = %+v", got.NextHops)
	}

	req := <-requests
	if req.Type != "fib_dump" || !req.SuppressStatus {
		t.Fatalf("control request = %+v, want read-only fib_dump with status suppressed", req)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("write helper response: %v", err)
	}
}

func TestDumpFIBHelperBudgetRefusalReturnsErrorWithoutRows11767(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		var request ControlRequest
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			serverErr <- err
			return
		}
		serverErr <- json.NewEncoder(conn).Encode(ControlResponse{
			OK:    false,
			Error: "fib_dump route rows exceed the control response budget",
		})
	}()

	manager := New()
	manager.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	manager.cfg.ControlSocket = socket
	generation, routes, err := manager.DumpFIB()
	if err == nil || !strings.Contains(err.Error(), "fib_dump route rows exceed") {
		t.Fatalf("DumpFIB refusal error = %v, want the helper budget error", err)
	}
	if generation != 0 || len(routes) != 0 {
		t.Fatalf("refused DumpFIB returned generation=%d routes=%d", generation, len(routes))
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("write helper refusal: %v", err)
	}
}

func TestDumpFIBRejectsTruncatedResponseInsteadOfEmptySuccess11767(t *testing.T) {
	oldCap := controlResponseCapBytes
	controlResponseCapBytes = 32
	t.Cleanup(func() { controlResponseCapBytes = oldCap })

	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		var request ControlRequest
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			serverErr <- err
			return
		}
		_, err = conn.Write([]byte(`{"ok":true,"fib_generation":9,"fib_routes":[]}`))
		serverErr <- err
	}()

	manager := New()
	manager.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	manager.cfg.ControlSocket = socket
	generation, routes, err := manager.DumpFIB()
	if err == nil || !strings.Contains(err.Error(), "control-response cap") {
		t.Fatalf("truncated DumpFIB error = %v, want control-response-cap error", err)
	}
	if generation != 0 || len(routes) != 0 {
		t.Fatalf("truncated DumpFIB returned generation=%d routes=%d", generation, len(routes))
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("write truncated helper response: %v", err)
	}
}
