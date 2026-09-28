package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// RED on revert: without a spawn-time guard, a tolerant-smuggled
// reserved state-file has the helper overwrite a gate or identity file
// during NORMAL operation (the helper saves unconditionally, including
// on loop exit) — before any wipe runs. The preflight must refuse with
// an actionable error while a legit path passes through.
func TestPreflightHelperPathsRefusesReservedStateFile10769(t *testing.T) {
	reserved := config.UserspaceConfig{
		ControlSocket: filepath.Join(t.TempDir(), "control.sock"),
		StateFile:     filepath.Join(t.TempDir(), ".reset-handoff"),
	}
	if err := preflightHelperPaths(reserved); err == nil {
		t.Fatal("preflight with a reserved state-file = nil, want refusal")
	} else if !strings.Contains(err.Error(), "aliases reserved") || !strings.Contains(err.Error(), reserved.StateFile) {
		t.Fatalf("preflight error must name the reserved alias, got %v", err)
	} else if !strings.Contains(err.Error(), "non-reserved path") {
		t.Fatalf("preflight error must document the fix, got %v", err)
	}

	dir := t.TempDir()
	legit := config.UserspaceConfig{
		ControlSocket: filepath.Join(dir, "control.sock"),
		StateFile:     filepath.Join(dir, "state.json"),
	}
	if err := preflightHelperPaths(legit); err != nil {
		t.Fatalf("preflight with a legit state-file = %v, want nil", err)
	}
}

// RED on revert: first bring-up skips the restart preflight, so the
// spawn funnel itself must refuse a reserved state-file before the
// runtime-dir MkdirAll and the spawn — no helper, no directories.
func TestEnsureProcessLockedRefusesReservedStateFile10769(t *testing.T) {
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	m := New()
	cfg := config.UserspaceConfig{
		Binary:        testBinary,
		ControlSocket: filepath.Join(dir, "run", "control.sock"),
		StateFile:     filepath.Join(dir, "nostate", ".reset-handoff"),
		EventSocket:   filepath.Join(dir, "run", "events.sock"),
	}
	m.mu.Lock()
	err = m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	if err == nil {
		t.Fatal("ensureProcessLocked with a reserved state-file = nil, want refusal")
	}
	if !strings.Contains(err.Error(), "aliases reserved") {
		t.Fatalf("spawn error must name the reserved alias, got %v", err)
	}
	if m.proc != nil {
		t.Fatalf("helper spawned despite the refusal: %+v", m.proc)
	}
	if _, serr := os.Lstat(filepath.Join(dir, "nostate")); !os.IsNotExist(serr) {
		t.Fatalf("refused spawn must not create the state directory: %v", serr)
	}
	if _, serr := os.Lstat(filepath.Join(dir, "run")); !os.IsNotExist(serr) {
		t.Fatalf("refused spawn must not create the runtime directory: %v", serr)
	}
}

// The restart path refuses through the preflight with the previous
// generation left running: a reserved value must cost no forwarding.
func TestStopForNewGenerationRefusesReservedStateFile10769(t *testing.T) {
	m := New()
	cfg := config.UserspaceConfig{
		ControlSocket: filepath.Join(t.TempDir(), "control.sock"),
		StateFile:     filepath.Join(t.TempDir(), ".day0-config-applied"),
	}
	m.mu.Lock()
	err := m.stopForNewGenerationLocked(cfg)
	m.mu.Unlock()
	if err == nil {
		t.Fatal("restart with a reserved state-file = nil, want refusal")
	}
	if !strings.Contains(err.Error(), "previous generation left running") {
		t.Fatalf("restart error must spare the running generation, got %v", err)
	}
	if !strings.Contains(err.Error(), "aliases reserved") {
		t.Fatalf("restart error must name the reserved alias, got %v", err)
	}
}
