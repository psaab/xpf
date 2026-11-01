package userspace

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// MAJOR-3a: a Compile-path bring-up that retires the generation carrying a
// pending retry must rearm it without changing its counted attempt.
func TestCompileFailureRearmsCrashRetry12159(t *testing.T) {
	for _, tc := range []struct {
		name  string
		prime func(int) int
		want  bool
	}{
		{"after-cap", func(cap int) int { return cap - 1 }, true},
		{"before-cap", func(int) int { return 1 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, cmd, _ := spawnSupervisedChild(t)
			var mu sync.Mutex
			var retries []func()
			var delays []time.Duration
			m.restartTimerFn = func(d time.Duration, fn func()) {
				mu.Lock()
				retries = append(retries, fn)
				delays = append(delays, d)
				mu.Unlock()
			}
			capAttempt := helperCrashLoopAttempt()
			m.mu.Lock()
			m.helperCrash.Restarts = tc.prime(capAttempt)
			exited := m.procSup.exited
			m.mu.Unlock()
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			awaitSupervisor(t, m, exited)
			if _, looping := m.HelperSupervisorState(); looping != tc.want {
				t.Fatalf("crash verdict before Compile = %v, want %v", looping, tc.want)
			}

			dir := t.TempDir()
			binary := filepath.Join(dir, "helper")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cfg := config.UserspaceConfig{
				Binary: binary, ControlSocket: filepath.Join(dir, "c.sock"),
				StateFile: filepath.Join(dir, "s.json"), EventSocket: filepath.Join(dir, "e.sock"),
			}
			m.mu.Lock()
			err := m.ensureProcessLocked(cfg)
			m.mu.Unlock()
			if err == nil {
				t.Fatal("Compile-path helper that exits before readiness unexpectedly started")
			}
			rec := m.HelperCrashState()
			_, looping := m.HelperSupervisorState()
			mu.Lock()
			armed := len(retries)
			mu.Unlock()
			if looping != tc.want || !rec.RestartPending || armed != 2 ||
				rec.Restarts != tc.prime(capAttempt)+1 || delays[1] != helperRestartDelay(rec.Restarts) {
				t.Fatalf("Compile failure lost retry state: looping=%v pending=%v restarts=%d armed=%d delays=%v",
					looping, rec.RestartPending, rec.Restarts, armed, delays)
			}

			m.mu.Lock()
			gen := m.procGen
			m.mu.Unlock()
			retries[0]() // consumed timer is stale after Compile advanced procGen
			m.mu.Lock()
			gotGen := m.procGen
			m.mu.Unlock()
			mu.Lock()
			gotTimers := len(retries)
			mu.Unlock()
			if gotGen != gen || gotTimers != 2 {
				t.Fatalf("stale retry escaped its fence: generation %d->%d timers=%d", gen, gotGen, gotTimers)
			}
		})
	}
}

func TestCompileFailureBeforeSpawnPreservesCrashRetry12159(t *testing.T) {
	m, cmd, _ := spawnSupervisedChild(t)
	var mu sync.Mutex
	var retries []func()
	m.restartTimerFn = func(_ time.Duration, fn func()) {
		mu.Lock()
		retries = append(retries, fn)
		mu.Unlock()
	}
	m.mu.Lock()
	m.helperCrash.Restarts = helperCrashLoopAttempt() - 1
	exited := m.procSup.exited
	m.mu.Unlock()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	awaitSupervisor(t, m, exited)

	dir := t.TempDir()
	cfg := config.UserspaceConfig{
		Binary: filepath.Join(dir, "missing-helper"), ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile: filepath.Join(dir, "s.json"),
	}
	m.mu.Lock()
	err := m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	if err == nil {
		t.Fatal("Compile with a missing helper binary unexpectedly succeeded")
	}
	rec := m.HelperCrashState()
	_, looping := m.HelperSupervisorState()
	mu.Lock()
	armed := len(retries)
	mu.Unlock()
	if !looping || !rec.RestartPending || armed != 1 || rec.Restarts != helperCrashLoopAttempt() {
		t.Fatalf("pre-spawn Compile failure changed crash retry state: looping=%v pending=%v restarts=%d armed=%d",
			looping, rec.RestartPending, rec.Restarts, armed)
	}
}

const major3bReadyHelper12159 = `#!/usr/bin/python3
import socket, sys, time
args = sys.argv[1:]
path = args[args.index("--control-socket") + 1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(4)
while True:
    time.sleep(300)
`

// MAJOR-3b: a generation-advancing successful Compile ends the previous
// episode, so one later real child crash starts at the base delay.
func TestCompileRecoveryStartsFreshCrashEpisode12159(t *testing.T) {
	m, cmd, rec := spawnSupervisedChild(t)
	m.mu.Lock()
	m.helperCrash.Restarts = helperCrashLoopAttempt() - 1
	exited := m.procSup.exited
	m.mu.Unlock()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	awaitSupervisor(t, m, exited)
	if _, looping := m.HelperSupervisorState(); !looping {
		t.Fatal("precondition: crash did not reach the backoff cap")
	}

	dir := t.TempDir()
	binary := filepath.Join(dir, "helper")
	if err := os.WriteFile(binary, []byte(major3bReadyHelper12159), 0o755); err != nil {
		t.Fatal(err)
	}
	m.controlRequestHook = func(_ ControlRequest, status *ProcessStatus) error {
		if status != nil {
			status.PID = 4242
		}
		return nil
	}
	cfg := config.UserspaceConfig{
		Binary: binary, ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile: filepath.Join(dir, "s.json"), EventSocket: filepath.Join(dir, "e.sock"),
	}
	m.mu.Lock()
	err := m.ensureProcessLocked(cfg)
	newProc := m.proc
	exited2 := m.procSup.exited
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("generation-advancing Compile bring-up: %v", err)
	}
	if got := m.HelperCrashState(); got.LastExitWasCrash || got.Restarts != 0 {
		t.Fatalf("healthy Compile did not end the prior episode: %+v", got)
	}

	// A ping-only Compile on the same generation is not episode recovery.
	m.mu.Lock()
	m.helperCrash = HelperCrashRecord{LastExitWasCrash: true, Restarts: 3}
	gen := m.procGen
	err = m.ensureProcessLocked(cfg)
	preserved := m.helperCrash.LastExitWasCrash && m.helperCrash.Restarts == 3
	m.helperCrash = HelperCrashRecord{}
	gotGen := m.procGen
	m.mu.Unlock()
	if err != nil || gotGen != gen || !preserved {
		t.Fatalf("same-generation ping changed crash record: err=%v generation=%d->%d preserved=%v",
			err, gen, gotGen, preserved)
	}

	before := len(rec.snapshot())
	if err := newProc.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	awaitSupervisor(t, m, exited2)
	_, looping := m.HelperSupervisorState()
	delays := rec.snapshot()[before:]
	// #18707: attempt 1 of a fresh episode is the immediate retry, so the
	// fresh-episode delay is helperRestartDelay(1). The premise keeps the
	// cell discriminating: an inherited Restarts:3 episode would schedule
	// attempt 4, whose delay must differ from attempt 1's.
	if helperRestartDelay(1) == helperRestartDelay(4) {
		t.Fatalf("premise: attempt 1 and attempt 4 share delay %v, so a fresh and an inherited episode are indistinguishable",
			helperRestartDelay(1))
	}
	if looping || len(delays) != 1 || delays[0] != helperRestartDelay(1) {
		t.Fatalf("first crash after successful Compile inherited old episode: looping=%v delays=%v",
			looping, delays)
	}
}
