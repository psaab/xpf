package userspace

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// #13093: the 1 Hz status poll held Manager.mu across blocking control RPCs,
// while read-only status queries and HA transitions require that same mutex.
// This behavior-level discriminator blocks a real helper status response and
// requires a concurrent manager operation to proceed before the response is
// released. On pre-fix master, the poll holds m.mu for the complete RPC and
// this times out.
func TestStatusLoopDoesNotHoldManagerLockAcrossStatusRPC13093(t *testing.T) {
	old := statusLoopInterval
	statusLoopInterval = 10 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = old })

	sock := filepath.Join("/var/worktrees/.cache", fmt.Sprintf("c13093-%d.sock", os.Getpid()))
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	requestSeen := make(chan struct{}, 1)
	release := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req ControlRequest
				if json.NewDecoder(c).Decode(&req) != nil {
					return
				}
				if req.Type == "status" {
					select {
					case requestSeen <- struct{}{}:
					default:
					}
					<-release
				}
				status := ProcessStatus{PID: os.Getpid(), Workers: 1}
				_ = json.NewEncoder(c).Encode(ControlResponse{OK: true, Status: &status})
			}(conn)
		}
	}()

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: p}
	m.cfg.ControlSocket = sock
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.statusLoop(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		close(release)
		<-done
		_ = os.Remove(sock)
	})

	select {
	case <-requestSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("status loop never issued a status RPC")
	}

	acquired := make(chan struct{})
	go func() {
		m.mu.Lock()
		close(acquired)
		m.mu.Unlock()
	}()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("statusLoop held Manager.mu across a blocked control-socket status RPC; " +
			"HA and manager readers cannot make progress (#13093)")
	}
}

// TestStatusReadAPIsDoNotWaitForManagerLock13093 pins the lock-free
// publication used by Status, CachedStatus, and ForwardingSupported. It also
// ensures these read-only calls do not initiate a duplicate RPC.
func TestStatusReadAPIsDoNotWaitForManagerLock13093(t *testing.T) {
	m := New()
	m.mu.Lock()
	m.setLastStatusLocked(ProcessStatus{PID: 4242, Workers: 3, Capabilities: UserspaceCapabilities{ForwardingSupported: true}})
	m.mu.Unlock()

	m.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		st, err := m.Status()
		if err != nil || st.PID != 4242 || st.Workers != 3 {
			t.Errorf("Status() = %+v, %v; want published PID=4242 Workers=3", st, err)
		}
		if st, ok := m.CachedStatus(); !ok || st.PID != 4242 {
			t.Errorf("CachedStatus() = %+v ok=%v; want published", st, ok)
		}
		if !m.ForwardingSupported() {
			t.Error("ForwardingSupported() = false; want published true")
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		m.mu.Unlock()
		t.Fatal("read-only status APIs blocked on Manager.mu (#13093)")
	}
	m.mu.Unlock()
}
