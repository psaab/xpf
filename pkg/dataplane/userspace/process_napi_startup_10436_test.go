package userspace

// #10436: the startup NAPI bootstrap must be process-generation scoped.
//
// The startup bootstrap used to be a timer armed at helper spawn that fired
// 3s later; since #18707 it is armed by the status path the first time a
// generation reports every binding bound (ensureXSKBoundNAPIBootstrapLocked).
// Either way its callback runs on its own goroutine and acquires m.mu
// independently, so the #10436 hazard is unchanged: a G1 callback that wakes
// after G1 exited and G2 started would see G2 in m.proc and submit
// load-bearing probes against the wrong generation. The arm captures procGen +
// proc/procSup identity under m.mu and the callback re-checks all three before
// submitting; a stale callback no-ops.
//
// The lifecycle cells wait for the completion channel the arm returns, so they
// cannot pass because a goroutine never ran. No netlink/probe I/O runs because
// the tests leave m.lastSnapshot nil.
// FAIL-ON-REVERT: drop the captured generation fence back to `m.proc == nil`
// and the stale callback cell goes RED.

import (
	"os/exec"
	"testing"
	"time"
)

func TestStartupNAPIBootstrapStaleGenerationNoops10436(t *testing.T) {
	m := New()
	g1Cmd := exec.Command("true")
	g1Sup := &helperGeneration{gen: 1, cmd: g1Cmd, exited: make(chan struct{})}
	g2Cmd := exec.Command("true")
	g2Sup := &helperGeneration{gen: 2, cmd: g2Cmd, exited: make(chan struct{})}

	m.mu.Lock()
	m.proc = g1Cmd
	m.procGen = 1
	m.procSup = g1Sup
	m.lastNAPIBootstrap = time.Time{}
	m.lastSnapshot = nil
	// Arm for G1 while m.mu is held, then replace G1 with G2 before releasing
	// it. The callback is blocked at its lock hop and must reject the
	// replacement generation before recording a bootstrap.
	done := m.ensureXSKBoundNAPIBootstrapLocked()

	// The crash path clears m.proc but deliberately leaves procGen at 1. The
	// restart then publishes G2 as procGen 2.
	m.proc = nil
	m.procSup = nil
	m.proc = g2Cmd
	m.procSup = g2Sup
	m.procGen = 2
	m.mu.Unlock()

	<-done
	assertNAPIBootstrapNeverFired10436(t, m)
}

func assertNAPIBootstrapNeverFired10436(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastNAPIBootstrap.IsZero() {
		t.Fatalf("stale startup bootstrap fired against G2 (lastNAPIBootstrap=%v); "+
			"the callback is not generation-scoped (#10436)", m.lastNAPIBootstrap)
	}
}

func TestStartupNAPIBootstrapSameGenerationFires10436(t *testing.T) {
	m := New()
	cmd := exec.Command("true")
	sup := &helperGeneration{gen: 1, cmd: cmd, exited: make(chan struct{})}
	m.mu.Lock()
	m.proc = cmd
	m.procGen = 1
	m.procSup = sup
	m.lastNAPIBootstrap = time.Time{}
	m.lastSnapshot = nil
	done := m.ensureXSKBoundNAPIBootstrapLocked()
	m.mu.Unlock()

	<-done
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastNAPIBootstrap.IsZero() {
		t.Fatal("same-generation startup bootstrap never fired; normal startup broken (#10436)")
	}
}
