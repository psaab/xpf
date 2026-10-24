package daemon

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestCleanupGuardRefusesLiveDaemon16430 is the #16430 acceptance: while
// a lease holds the singleton (a live daemon), the guard refuses with
// ErrDaemonAlreadyRunning naming `systemctl stop xpfd`; with no holder
// it acquires, reports held, and releases cleanly.
func TestCleanupGuardRefusesLiveDaemon16430(t *testing.T) {
	origLockPath := DaemonLockPath
	t.Cleanup(func() { DaemonLockPath = origLockPath })
	DaemonLockPath = filepath.Join(t.TempDir(), "xpfd.lock")

	// No holder: the guard acquires and cleanup may proceed.
	lease, err := GuardDaemonLockForCleanup()
	if err != nil {
		t.Fatalf("guard with no live daemon: %v", err)
	}
	if !DaemonLockHeldByLiveProcess() {
		t.Fatal("held cleanup lease must report live-held")
	}
	if !daemonLockHeldByLiveProcess() {
		t.Fatal("held cleanup lease must report live-held (unexported probe)")
	}
	lease.Release()
	lease.Release() // idempotent
	if DaemonLockHeldByLiveProcess() {
		t.Fatal("released cleanup lease must not report held")
	}

	// Live daemon holds the singleton: the guard must refuse.
	live, err := acquireDaemonLock()
	if err != nil {
		t.Fatalf("stage live daemon lock: %v", err)
	}
	defer live.release()
	if _, err := GuardDaemonLockForCleanup(); err == nil {
		t.Fatal("guard beside a live daemon must refuse")
	} else {
		if !errors.Is(err, ErrDaemonAlreadyRunning) {
			t.Fatalf("guard err = %v, want ErrDaemonAlreadyRunning", err)
		}
		if !strings.Contains(err.Error(), "systemctl stop xpfd") {
			t.Fatalf("guard err = %q, want it to name 'systemctl stop xpfd'", err)
		}
		if !strings.Contains(err.Error(), "cleanup refused") {
			t.Fatalf("guard err = %q, want cleanup-refused framing", err)
		}
	}
	// The refusal must not have disturbed the live holder.
	if !DaemonLockHeldByLiveProcess() {
		t.Fatal("live daemon lock must still report held after a refused cleanup")
	}
}
