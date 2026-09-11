package cluster

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// #9751: a RestartHeartbeat that exhausted its bind retries left the sender and
// receiver nil. Every later RestartHeartbeat then saw "not running" and returned
// at once, so the heartbeat stayed dead across later applies until comms
// restarted. The failed restart now records a debt that the next restart
// retries. A deliberate StopHeartbeat clears the debt and is never resurrected.
//
// The cells make the control-link address unbindable by pointing the
// remembered hbLocalAddr at TEST-NET-1 for the failing restart, then restoring
// it. That stands in for the address being absent after a VRF rebind, which is
// what the issue's probe did.

// unbindableAddr9751 returns an address this host cannot bind, or skips.
func unbindableAddr9751(t *testing.T) string {
	t.Helper()
	const addr = "192.0.2.1" // TEST-NET-1, not assigned to this host
	if c, err := net.ListenPacket("udp4", net.JoinHostPort(addr, "0")); err == nil {
		c.Close()
		t.Skipf("%s is bindable on this host (ip_nonlocal_bind?); the cell needs an unbindable address", addr)
	}
	return addr
}

func fastRestartRetries9751(t *testing.T) {
	t.Helper()
	old := heartbeatRestartRetryDelay
	heartbeatRestartRetryDelay = time.Millisecond
	t.Cleanup(func() { heartbeatRestartRetryDelay = old })
}

func setLocalAddr9751(m *Manager, addr string) {
	m.mu.Lock()
	m.hbLocalAddr = addr
	m.mu.Unlock()
}

func startedManager9751(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat: %v", err)
	}
	t.Cleanup(m.StopHeartbeat)
	return m
}

func TestFailedHeartbeatRestartIsRetriedByTheNextRestart_9751(t *testing.T) {
	fastRestartRetries9751(t)
	bad := unbindableAddr9751(t)
	m := startedManager9751(t)
	m.mu.RLock()
	r0 := m.hbReceiver
	m.mu.RUnlock()
	seed := MonotonicNanos() - (10 * time.Second).Nanoseconds()
	r0.lastSeen.Store(seed)

	// The control address is gone for longer than the restart's retries.
	setLocalAddr9751(m, bad)
	if m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat succeeded on an unbindable address")
	}
	if m.HeartbeatRunning() {
		t.Fatal("heartbeat reported running after a failed restart")
	}
	if !m.HeartbeatRestartOwed() {
		t.Fatal("a failed restart recorded no debt, so the next RestartHeartbeat sees 'not running' and the heartbeat stays dead")
	}

	// The address is back: the next restart must start the heartbeat.
	setLocalAddr9751(m, "127.0.0.1")
	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat returned false with the address restored: the failed restart latched the heartbeat dead")
	}
	if !m.HeartbeatRunning() {
		t.Error("heartbeat not running after the retry reported success")
	}
	if m.HeartbeatRestartOwed() {
		t.Error("the debt is still recorded after the retry started the heartbeat")
	}
	m.mu.RLock()
	r1 := m.hbReceiver
	m.mu.RUnlock()
	if r1 == nil || r1.lastSeen.Load() != seed || r1.seenGrace != heartbeatRestartGrace {
		var got int64
		var grace time.Duration
		if r1 != nil {
			got, grace = r1.lastSeen.Load(), r1.seenGrace
		}
		t.Errorf("the retry's receiver lost the pre-failure liveness (lastSeen=%d want %d, seenGrace=%v want %v); "+
			"a peer that died while the heartbeat was down would never be detected", got, seed, grace, heartbeatRestartGrace)
	}
}

func TestDeliberateStopClearsARestartDebt_9751(t *testing.T) {
	fastRestartRetries9751(t)
	bad := unbindableAddr9751(t)
	m := startedManager9751(t)
	setLocalAddr9751(m, bad)
	if m.RestartHeartbeat() || !m.HeartbeatRestartOwed() {
		t.Fatal("setup: want a failed restart that recorded a debt")
	}

	m.StopHeartbeat() // a comms teardown: stopped on purpose
	if m.HeartbeatRestartOwed() {
		t.Error("StopHeartbeat left the restart debt set")
	}
	setLocalAddr9751(m, "127.0.0.1")
	if m.RestartHeartbeat() {
		t.Error("RestartHeartbeat resurrected a heartbeat that StopHeartbeat had stopped on purpose")
	}
}

func TestStopDuringTheRetryWindowRecordsNoDebt_9751(t *testing.T) {
	fastRestartRetries9751(t)
	bad := unbindableAddr9751(t)
	m := startedManager9751(t)
	setLocalAddr9751(m, bad)

	// A comms teardown lands while the restart is retrying: inside the first
	// retry's start window.
	var fired atomic.Bool
	m.mu.Lock()
	m.hbStartInWindowHook = func() {
		if fired.CompareAndSwap(false, true) {
			m.StopHeartbeat()
		}
	}
	m.mu.Unlock()

	if m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat succeeded on an unbindable address")
	}
	if !fired.Load() {
		t.Fatal("setup: the teardown hook never ran")
	}
	if m.HeartbeatRestartOwed() {
		t.Error("a restart overtaken by a deliberate StopHeartbeat recorded a debt; the next apply would " +
			"resurrect a heartbeat that was stopped on purpose")
	}
}
