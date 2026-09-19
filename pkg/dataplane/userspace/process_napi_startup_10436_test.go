package userspace

// #10436: delayed NAPI bootstrap must be process-generation scoped.
//
// The "startup" bootstrap is scheduled at helper spawn and fires 3s later. The
// pre-fix callback checked only `m.proc != nil`, so a G1 callback that woke
// after G1 exited and G2 started saw G2 in m.proc and submitted load-bearing
// probes against the wrong generation. The schedule helper below captures
// procGen + proc/procSup identity under m.mu and both callback layers re-check
// all three before submitting; a stale callback no-ops.
//
// The lifecycle cells wait for completion channels returned by both callback
// layers, so they cannot pass because a goroutine never ran. No netlink/probe
// I/O runs because the tests leave m.lastSnapshot nil.
// FAIL-ON-REVERT: drop the captured generation fences back to `m.proc == nil`
// and the stale callback cells go RED.

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
	done := m.scheduleStartupNAPIBootstrapAfterLocked(20 * time.Millisecond)

	// The crash path clears m.proc but deliberately leaves procGen at 1. The
	// restart then publishes G2 as procGen 2. Hold m.mu across both transitions
	// so the delayed callback must wake, acquire the lock, and inspect G2.
	m.proc = nil
	m.procSup = nil
	m.proc = g2Cmd
	m.procSup = g2Sup
	m.procGen = 2
	m.mu.Unlock()

	<-done
	assertNAPIBootstrapNeverFired10436(t, m)
}

func TestStartupNAPIBootstrapInnerStaleGenerationNoops10436(t *testing.T) {
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
	// Launch the inner callback while m.mu is held, then replace G1 with G2
	// before releasing it. The callback is blocked at its lock hop and must
	// reject the replacement generation before recording a bootstrap.
	done := m.bootstrapNAPIQueuesAsyncForGenerationLocked("startup", 1, g1Cmd, g1Sup)
	m.proc = nil
	m.procSup = nil
	// This is the crash gap: the dead G1 remains procGen 1 until restart.
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
			"the delayed callback is not generation-scoped (#10436)", m.lastNAPIBootstrap)
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
	done := m.scheduleStartupNAPIBootstrapAfterLocked(20 * time.Millisecond)
	m.mu.Unlock()

	<-done
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastNAPIBootstrap.IsZero() {
		t.Fatal("same-generation startup bootstrap never fired; normal startup broken (#10436)")
	}
}
