// #5838 follow-up: an intentional teardown must CANCEL a crash restart that is
// still pending, not let it resurrect the helper.
//
// The supervisor added in #7228 arms a bounded-backoff restart after an
// unexpected helper exit and fences the attempt on
// `(m.procGen != gen || m.proc != nil || !m.helperCrash.LastExitWasCrash)`. An
// intentional stop satisfied none of those: `stopLocked` clears `m.proc` and
// `m.procSup` but never advances `m.procGen` and never clears `m.helperCrash`.
// And the stop that FOLLOWS a crash takes `stopLocked`'s `m.proc == nil` early
// return — the crash path already nil'd `m.proc` — so it never reached any of
// the teardown below it either. A crash whose backoff was still pending when
// the daemon shut down therefore spawned a helper for a torn-down Manager, and
// the restart chain kept re-arming afterwards. After `Close()` that child
// outlives xpfd holding the NIC queues: the EBUSY-on-zero-copy-queues collision
// the next start hits.
//
// FAIL-ON-REVERT: drop the `m.procGen++` from the top of `stopLocked` and the
// marker assertion below goes RED — the pending timer spawns the helper again.
package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestHelperCrashRestartCancelledByIntentionalStop_5838(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), "u5838stop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// The stand-in helper records that it ran. A marker file is the observable
	// that matters: `m.proc` ends nil in BOTH the buggy and the fixed case (the
	// resurrected generation fails its readiness wait and tears itself down),
	// so asserting on `m.proc` would pass either way.
	marker := filepath.Join(dir, "spawned")
	bin := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch "+marker+"\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var armed []func()
	m := New()
	m.restartTimerFn = func(_ time.Duration, fn func()) {
		mu.Lock()
		defer mu.Unlock()
		armed = append(armed, fn)
	}
	m.cfg = config.UserspaceConfig{
		Binary:        bin,
		ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile:     filepath.Join(dir, "state.json"),
		EventSocket:   filepath.Join(dir, "e.sock"),
	}

	// A supervised generation in the state a helper that reached readiness
	// leaves behind.
	child := exec.Command("sleep", "300")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.proc = child
	m.startHelperSupervisorLocked(child)
	m.mu.Unlock()

	// Crash it and let the supervisor reap and arm the restart.
	_ = child.Process.Kill()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !m.HelperCrashState().LastExitWasCrash {
		time.Sleep(10 * time.Millisecond)
	}
	if !m.HelperCrashState().LastExitWasCrash {
		t.Fatal("supervisor never recorded the crash — the rest of this test would be vacuous")
	}
	mu.Lock()
	pending := len(armed)
	mu.Unlock()
	if pending != 1 {
		t.Fatalf("armed restarts = %d, want exactly 1", pending)
	}

	// Intentional teardown: the path Close() and Teardown() both funnel through.
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()

	// NOTE: `HelperCrashState().LastExitWasCrash` deliberately survives the stop. The
	// record is the retry debt `ensureProcessLocked`'s own failure path depends
	// on (it calls stopLocked when a spawn misses its readiness wait), so
	// clearing it here would make a failed restart forget it was retrying. What
	// must not survive is the ARMED ATTEMPT, and the generation bump is what
	// retires that. The residual — a deliberate stop leaves a stale "crash
	// pending" record with a past NextRestart — is for the operator-surface
	// follow-up that renders these fields.

	// The armed timer now fires, exactly as it would after a real backoff.
	mu.Lock()
	fire := armed[0]
	mu.Unlock()
	fire()

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a pending crash restart spawned a helper AFTER an intentional stop — " +
			"after Close() that child outlives xpfd holding the NIC queues")
	}
	mu.Lock()
	total := len(armed)
	mu.Unlock()
	if total != 1 {
		t.Fatalf("armed restarts = %d after the stop, want 1 — the restart chain kept re-arming", total)
	}
}

// Anti-over-reject: the fence must not break the ordinary crash->restart path.
// A crash with NO intervening stop still arms, and firing the timer still
// attempts the restart (it spawns the stand-in helper).
func TestHelperCrashRestartStillRunsWithoutAStop_5838(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), "u5838run")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	marker := filepath.Join(dir, "spawned")
	bin := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntouch "+marker+"\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var armed []func()
	m := New()
	m.restartTimerFn = func(_ time.Duration, fn func()) {
		mu.Lock()
		defer mu.Unlock()
		armed = append(armed, fn)
	}
	m.cfg = config.UserspaceConfig{
		Binary:        bin,
		ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile:     filepath.Join(dir, "state.json"),
		EventSocket:   filepath.Join(dir, "e.sock"),
	}

	child := exec.Command("sleep", "300")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.proc = child
	m.startHelperSupervisorLocked(child)
	m.mu.Unlock()

	_ = child.Process.Kill()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !m.HelperCrashState().LastExitWasCrash {
		time.Sleep(10 * time.Millisecond)
	}
	if !m.HelperCrashState().LastExitWasCrash {
		t.Fatal("supervisor never recorded the crash")
	}

	mu.Lock()
	fire := armed[0]
	mu.Unlock()
	fire()

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the ordinary crash->restart path did not spawn a replacement helper: %v", err)
	}

	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
}
