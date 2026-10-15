package userspace

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
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

// TestStatusPollDoesNotRearmWorkersAfterLinkCycleStarts13093 covers the race
// opened when the status poll releases m.mu for its helper RPC: a link cycle
// may acquire the lease and stop workers before that response comes back. The
// old helper response must not publish a worker-arm snapshot into the cycle.
func TestStatusPollDoesNotRearmWorkersAfterLinkCycleStarts13093(t *testing.T) {
	oldInterval := statusLoopInterval
	statusLoopInterval = 5 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	m := New()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	m.proc = &exec.Cmd{Process: proc}
	m.lastSnapshot = &ConfigSnapshot{Generation: 5, DeferWorkers: true}
	m.pendingWorkerArm = true

	statusEntered := make(chan struct{})
	statusRelease := make(chan struct{})
	stoppedWorkers := make(chan struct{}, 1)
	appliedSnapshot := make(chan struct{}, 1)
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		switch req.Type {
		case "status":
			select {
			case statusEntered <- struct{}{}:
			default:
			}
			<-statusRelease
			if status != nil {
				*status = ProcessStatus{
					PID:                              os.Getpid(),
					Workers:                          1,
					ConfigSnapshotProtocolVersion:    ProtocolVersion,
					InjectPacketTupleProtocolVersion: InjectPacketTupleProtocolVersion,
				}
			}
		case "stop_workers":
			select {
			case stoppedWorkers <- struct{}{}:
			default:
			}
		case "apply_snapshot":
			select {
			case appliedSnapshot <- struct{}{}:
			default:
			}
		}
		return nil
	}

	var releaseOnce sync.Once
	releaseStatus := func() { releaseOnce.Do(func() { close(statusRelease) }) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.statusLoop(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		releaseStatus()
		<-done
		m.releaseLinkCycleLease()
	})

	select {
	case <-statusEntered:
	case <-time.After(time.Second):
		t.Fatal("status loop did not enter the blocked helper poll")
	}

	prepared := make(chan error, 1)
	go func() { prepared <- m.PrepareLinkCycle() }()
	select {
	case <-stoppedWorkers:
	case <-time.After(time.Second):
		t.Fatal("PrepareLinkCycle did not stop workers while status poll was blocked")
	}
	if !m.linkCycleInFlight() {
		t.Fatal("PrepareLinkCycle returned from stop_workers without an active link-cycle lease")
	}
	select {
	case err := <-prepared:
		if err != nil {
			t.Fatalf("PrepareLinkCycle: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("PrepareLinkCycle did not finish after stop_workers")
	}

	releaseStatus()
	select {
	case <-appliedSnapshot:
		t.Fatal("status poll published apply_snapshot after link-cycle workers were stopped")
	case <-time.After(50 * time.Millisecond):
	}
}
