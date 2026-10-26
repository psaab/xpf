package userspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const helperScript17881 = `#!/usr/bin/python3
import socket, sys, time
args = sys.argv[1:]
control = args[args.index("--control-socket") + 1]
open(%q, "w").write(%q)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(control)
s.listen(4)
while True:
    time.sleep(300)
`

func writeHelper17881(t *testing.T, path, markerPath, marker string) os.FileInfo {
	t.Helper()
	if err := os.WriteFile(path, []byte(fmt.Sprintf(helperScript17881, markerPath, marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func tempDir17881(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "xpf17881-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func startHelper17881(t *testing.T, binary, dir string) (*Manager, error) {
	t.Helper()
	m := New()
	m.mode = ModeUserspaceCompat
	m.controlRequestHook = func(_ ControlRequest, status *ProcessStatus) error {
		if status != nil {
			status.PID = 4242
		}
		return nil
	}
	cfg := config.UserspaceConfig{
		Binary:        binary,
		ControlSocket: filepath.Join(dir, "control.sock"),
		StateFile:     filepath.Join(dir, "state.json"),
		EventSocket:   filepath.Join(dir, "events.sock"),
	}
	m.mu.Lock()
	err := m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	if m.proc != nil {
		t.Cleanup(func() {
			m.mu.Lock()
			m.stopLocked()
			m.mu.Unlock()
		})
	}
	return m, err
}

func TestEnsureProcessDoesNotExecuteReplacedHelper17881(t *testing.T) {
	// Unswapped control: a trusted helper still starts and becomes ready.
	controlDir := tempDir17881(t)
	controlMarker := filepath.Join(controlDir, "started")
	controlBinary := filepath.Join(controlDir, "helper")
	writeHelper17881(t, controlBinary, controlMarker, "CONTROL")
	controlManager, err := startHelper17881(t, controlBinary, controlDir)
	if err != nil {
		t.Fatalf("start unswapped helper: %v", err)
	}
	if got, err := os.ReadFile(controlMarker); err != nil || strings.TrimSpace(string(got)) != "CONTROL" {
		t.Fatalf("unswapped helper marker = %q, err=%v; want CONTROL", got, err)
	}
	controlManager.mu.Lock()
	controlManager.stopLocked()
	controlManager.mu.Unlock()

	// The root seams make the initial helper appear trusted while keeping a
	// replacement owned by this test user untrusted. The final directory-chain
	// check in findBinary atomically replaces the pathname after the original
	// file has passed validation but before findBinary returns to the spawn path.
	dir := tempDir17881(t)
	binaryPath := filepath.Join(dir, "helper")
	replacementPath := filepath.Join(dir, "replacement")
	originalMarker := filepath.Join(dir, "original-started")
	replacementMarker := filepath.Join(dir, "replacement-started")
	originalInfo := writeHelper17881(t, binaryPath, originalMarker, "VALIDATED")
	writeHelper17881(t, replacementPath, replacementMarker, "REPLACEMENT")

	oldEUID := helperProcessEuid
	oldOwnerUID := helperFileOwnerUID
	oldDirUID := helperDirTrustUID
	t.Cleanup(func() {
		helperProcessEuid = oldEUID
		helperFileOwnerUID = oldOwnerUID
		helperDirTrustUID = oldDirUID
	})
	helperProcessEuid = func() int { return 0 }
	helperFileOwnerUID = func(info os.FileInfo) (uint32, bool) {
		if os.SameFile(info, originalInfo) {
			return 0, true
		}
		return 1, true
	}
	dirChecks := 0
	dirCount := 0
	for current := filepath.Dir(binaryPath); ; current = filepath.Dir(current) {
		dirCount++
		if filepath.Dir(current) == current {
			break
		}
	}
	var swapErr error
	helperDirTrustUID = func(uid uint32) uint32 {
		dirChecks++
		if dirChecks == 2*dirCount {
			swapErr = os.Rename(replacementPath, binaryPath)
		}
		return 0
	}

	m, err := startHelper17881(t, binaryPath, dir)
	if swapErr != nil {
		t.Fatalf("replace helper after validation: %v", swapErr)
	}
	if err == nil {
		if got, readErr := os.ReadFile(replacementMarker); readErr == nil {
			t.Fatalf("ensureProcessLocked started the replaced helper (%q); want fail-closed refusal", strings.TrimSpace(string(got)))
		}
		t.Fatalf("ensureProcessLocked started helper after the validated pathname was replaced; manager=%+v", m)
	}
	if !strings.Contains(err.Error(), "not trusted") && !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("ensureProcessLocked error = %q, want fail-closed identity/trust refusal", err)
	}
	if _, statErr := os.Stat(replacementMarker); !os.IsNotExist(statErr) {
		t.Fatalf("replacement helper ran despite refusal: stat marker err=%v", statErr)
	}
}
