package userspace

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #18394 review folds (Rev18395Kimi F1, Rev18395Opus F1/F2):
//
//   - A supervisor retry whose child exits before proving ready is a real
//     crash-loop data point: its published exit must increment the
//     unexpected-exit counter (the #8397 metric source) exactly once, keep
//     exactly one restart timer, and leave bringUpGen cleared.
//   - A helper spawned through ensureProcessLocked that DID prove ready
//     (bringUpGen cleared at ready-proof) and is then reaped while m.mu is
//     held before stopLocked must still count exactly one unexpected exit
//     (#18242 boundary) — suppression must never match a ready helper.

// failingHelper18394 writes a helper that exits immediately with status 3.
func failingHelper18394(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "helper-fail")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestFailedSupervisorRetryCountsPreReadyExit18394(t *testing.T) {
	m, cmd, _ := spawnSupervisedChild(t)

	var retries []func()
	m.mu.Lock()
	m.restartTimerFn = func(_ time.Duration, fn func()) { retries = append(retries, fn) }
	exited := m.procSup.exited
	m.mu.Unlock()

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	awaitSupervisor(t, m, exited)
	exitsAfterReadyCrash := m.HelperCrashExitCount()
	if exitsAfterReadyCrash != 1 {
		t.Fatalf("ready-helper crash counted %d exits, want 1", exitsAfterReadyCrash)
	}
	if len(retries) != 1 {
		t.Fatalf("ready-helper crash armed %d timers, want 1", len(retries))
	}

	// Point the pending retry at a helper that dies before readiness.
	dir := t.TempDir()
	m.mu.Lock()
	m.cfg = config.UserspaceConfig{
		Binary:        failingHelper18394(t, dir),
		ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile:     filepath.Join(dir, "s.json"),
		EventSocket:   filepath.Join(dir, "e.sock"),
	}
	m.mu.Unlock()

	retries[0]() // production restartHelperAfterCrash

	if got := m.HelperCrashExitCount(); got != exitsAfterReadyCrash+1 {
		t.Fatalf("failed supervisor retry exit not counted: exits %d -> %d, want exactly +1 (#18394)", exitsAfterReadyCrash, got)
	}
	rec := m.HelperCrashState()
	if rec.Restarts != 2 {
		t.Fatalf("Restarts = %d after one ready crash + one failed retry, want 2 (single charge)", rec.Restarts)
	}
	if len(retries) != 2 {
		t.Fatalf("timers = %d, want 2 (one per charged attempt, no dual-arm)", len(retries))
	}
	m.mu.Lock()
	bringUpGen := m.bringUpGen
	m.mu.Unlock()
	if bringUpGen != 0 {
		t.Fatalf("failed supervisor retry left bringUpGen=%d, want 0 (no bring-up in progress)", bringUpGen)
	}
}

func TestEnsureSpawnedReadyHelperReapedBeforeStopCounts18394(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "helper-ready")
	script := "#!/usr/bin/python3\n" +
		"import socket, sys, time\n" +
		"args = sys.argv[1:]\n" +
		"path = args[args.index('--control-socket') + 1]\n" +
		"s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n" +
		"s.bind(path)\n" +
		"s.listen(4)\n" +
		"time.sleep(300)\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.UserspaceConfig{
		Binary:        bin,
		ControlSocket: filepath.Join(dir, "c.sock"),
		StateFile:     filepath.Join(dir, "s.json"),
		EventSocket:   filepath.Join(dir, "e.sock"),
	}
	m := New()
	m.mode = ModeUserspaceCompat
	m.restartTimerFn = func(time.Duration, func()) {}
	m.controlRequestHook = func(_ ControlRequest, status *ProcessStatus) error {
		if status != nil {
			status.PID = 4242
		}
		return nil
	}
	m.mu.Lock()
	err := m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("ensure-spawned helper bring-up failed: %v", err)
	}
	m.mu.Lock()
	if m.bringUpGen != 0 {
		t.Fatalf("ready-proof left bringUpGen=%d, want 0", m.bringUpGen)
	}
	exitsBefore := m.helperCrashUnexpectedExitsTotal
	exited := m.procSup.exited
	proc := m.proc
	// Hold m.mu across the kill AND the reap, then stop: the #18242
	// reaped-while-held interleaving through the production spawn path.
	if err := proc.Process.Kill(); err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		m.mu.Unlock()
		t.Fatal("supervisor never reaped the ensure-spawned helper")
	}
	m.stopLocked()
	m.mu.Unlock()

	if got := m.HelperCrashExitCount(); got != exitsBefore+1 {
		t.Fatalf("ready helper reaped before stop counted %d exits, want exactly 1 (#18242/#18394)", got-exitsBefore)
	}
}
