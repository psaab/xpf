package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// mustTestDaemonLockLease15085 acquires a throwaway singleton lease under
// the test's temp dir so a struct-literal Daemon can drive the real Run
// gate without touching the package-global production lock path.
func mustTestDaemonLockLease15085(t *testing.T) *daemonLockLease {
	t.Helper()
	lease, err := acquireDaemonLockAt(filepath.Join(t.TempDir(), "xpfd.lock"))
	if err != nil {
		t.Fatalf("acquire test daemon lock: %v", err)
	}
	t.Cleanup(lease.release)
	return lease
}

// TestAcquireDaemonLockRejectsSecondOwner15085 is the A54-02 regression:
// while one daemon holds the singleton lock, a second Run must be refused
// before it can delete the live first owner's first-apply marker.
func TestAcquireDaemonLockRejectsSecondOwner15085(t *testing.T) {
	origLockPath := DaemonLockPath
	t.Cleanup(func() { DaemonLockPath = origLockPath })
	dir := t.TempDir()
	DaemonLockPath = filepath.Join(dir, "xpfd.lock")

	first, err := acquireDaemonLock()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	firstOwned := true
	t.Cleanup(func() {
		if firstOwned {
			first.release()
		}
	})

	second, err := acquireDaemonLock()
	if err == nil {
		second.release()
		t.Fatal("second acquire while first daemon is live must fail")
	}
	if !errors.Is(err, ErrDaemonAlreadyRunning) {
		t.Fatalf("second acquire err = %v, want ErrDaemonAlreadyRunning", err)
	}
	if !strings.Contains(err.Error(), "xpfd already running") ||
		!strings.Contains(err.Error(), "use the 'cli' binary") ||
		!strings.Contains(err.Error(), "systemctl restart xpfd") {
		t.Fatalf("second acquire err = %q, want running pid and safe alternatives", err)
	}
	if !daemonLockHeldByLiveProcess() {
		t.Fatal("live first owner must report held")
	}

	first.release()
	firstOwned = false
	if daemonLockHeldByLiveProcess() {
		t.Fatal("released lock must not report held")
	}
	third, err := acquireDaemonLock()
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	third.release()
}

// TestDaemonLockTightensPermissiveModes16050 is the #16050 regression for
// the singleton lock: a pre-existing 0755 parent (shell first-creator
// shape) must be tightened to 0750 on acquire and the lock file must land
// 0600. RED-on-revert: restoring MkdirAll(0o755) without the chmod leaves
// the seeded 0755 in place.
func TestDaemonLockTightensPermissiveModes16050(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "xpf")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lease, err := acquireDaemonLockAt(filepath.Join(dir, "xpfd.lock"))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer lease.release()
	if fi, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o750 {
		t.Fatalf("daemon lock dir mode = %04o, want 0750 (#16050)", got)
	}
	if fi, err := os.Stat(filepath.Join(dir, "xpfd.lock")); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("daemon lock file mode = %04o, want 0600 (#16050)", got)
	}
}

// TestUnitRuntimeDirectoryHardened16050 pins the shipped unit's #16050
// directives, parsing test/incus/xpfd.service (the source debian/rules
// stages) as in TestUnitRestartForceExitStatus15084: RuntimeDirectory=xpf
// at 0750 plus UMask=0027, so no file created under /run/xpf by the
// daemon or a shell first-creator it spawns lands world-readable.
// RED-on-revert: deleting any of the three directives fails here.
func TestUnitRuntimeDirectoryHardened16050(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "incus", "xpfd.service"))
	if err != nil {
		t.Fatalf("read shipped unit: %v", err)
	}
	var runtimeDir, runtimeMode, umask string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "RuntimeDirectory="); ok {
			runtimeDir = v
		}
		if v, ok := strings.CutPrefix(line, "RuntimeDirectoryMode="); ok {
			runtimeMode = v
		}
		if v, ok := strings.CutPrefix(line, "UMask="); ok {
			umask = v
		}
	}
	if runtimeDir != "xpf" {
		t.Errorf("RuntimeDirectory = %q, want %q (#16050)", runtimeDir, "xpf")
	}
	if m, err := strconv.ParseUint(runtimeMode, 8, 32); err != nil || m != 0o750 {
		t.Errorf("RuntimeDirectoryMode = %q, want 0750 (#16050)", runtimeMode)
	}
	if m, err := strconv.ParseUint(umask, 8, 32); err != nil || m != 0o027 {
		t.Errorf("UMask = %q, want 0027 (#16050)", umask)
	}
}

// TestDaemonRunRefusesSecondProcessBeforeMarkerClear15085 drives the real
// Run entry point as the second process. The first process is represented by
// an independently opened flock plus its live first-apply marker; Run must
// reject before clearHostInboundFirstApplyMarker can remove that marker.
func TestDaemonRunRefusesSecondProcessBeforeMarkerClear15085(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "xpfd.lock")
	markerPath := filepath.Join(dir, "host-inbound-applied.done")
	configPath := filepath.Join(dir, "xpf.conf")

	origLockPath := DaemonLockPath
	origMarkerPath := HostInboundFirstApplyMarkerPath
	t.Cleanup(func() {
		DaemonLockPath = origLockPath
		HostInboundFirstApplyMarkerPath = origMarkerPath
		clearHostInboundFirstApplyMarker()
	})
	DaemonLockPath = lockPath
	HostInboundFirstApplyMarkerPath = markerPath

	owner, err := acquireDaemonLockAt(lockPath)
	if err != nil {
		t.Fatalf("stage live owner: %v", err)
	}
	t.Cleanup(owner.release)
	noteHostInboundInstalled()
	if !HostInboundFirstApplyLive() {
		t.Fatal("staged first owner marker is not live")
	}
	// The staging helper uses this process's marker slot; release only that
	// representation while preserving both the marker and the singleton lock
	// that model the separate live daemon.
	releaseMarkerLock(&hostInboundFirstApplyLockFile)

	d := &Daemon{opts: Options{ConfigFile: configPath, NoDataplane: true}}
	err = d.Run(context.Background())
	if !errors.Is(err, ErrDaemonAlreadyRunning) {
		t.Fatalf("second Daemon.Run err = %v, want ErrDaemonAlreadyRunning", err)
	}
	if _, statErr := os.Stat(markerPath); statErr != nil {
		t.Fatalf("second Daemon.Run removed live owner's marker: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".configdb")); !os.IsNotExist(statErr) {
		t.Fatalf("second Daemon.Run mutated config state, stat err = %v", statErr)
	}
}
