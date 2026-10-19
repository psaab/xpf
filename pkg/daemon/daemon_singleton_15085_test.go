package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
