package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// DaemonLockPath is the host-wide singleton lock for a full xpfd process.
// /run is tmpfs, so the path disappears on reboot just like the process it
// names. A package var so tests can redirect it away from the live host.
var DaemonLockPath = "/run/xpf/xpfd.lock"

// ErrDaemonAlreadyRunning reports the singleton-lock refusal. The lock file
// carries the owner's pid so the operator can identify that other daemon.
var ErrDaemonAlreadyRunning = errors.New("xpfd already running")

// daemonLockLease is one held daemon singleton lock. Its file must remain
// open for the daemon's lifetime; closing it releases the flock.
type daemonLockLease struct {
	file *os.File
}

// acquireDaemonLock takes the production singleton lock.
func acquireDaemonLock() (*daemonLockLease, error) {
	return acquireDaemonLockAt(DaemonLockPath)
}

// acquireDaemonLockAt opens path, takes a non-blocking exclusive flock, and
// then publishes this process's pid. Publication happens after the flock so
// a busy caller can only ever read the current owner's pid (or, briefly, an
// empty file while the holder is publishing; that window only degrades the
// error text to the pid-less form).
func acquireDaemonLockAt(path string) (*daemonLockLease, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("daemon lock: create %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("daemon lock: open %s: %w", path, err)
	}
	if err := flockFn(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		ownerPID := readDaemonLockPID(f)
		_ = f.Close()
		if isFlockContended(err) {
			if ownerPID > 0 {
				return nil, fmt.Errorf("%w (pid %d); use the 'cli' binary for remote commands, or 'systemctl restart xpfd' to restart the daemon", ErrDaemonAlreadyRunning, ownerPID)
			}
			return nil, fmt.Errorf("%w; use the 'cli' binary for remote commands, or 'systemctl restart xpfd' to restart the daemon", ErrDaemonAlreadyRunning)
		}
		return nil, fmt.Errorf("daemon lock: flock %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		lease := &daemonLockLease{file: f}
		lease.release()
		return nil, fmt.Errorf("daemon lock: tighten %s to 0600: %w", path, err)
	}
	if err := writeDaemonLockPID(f); err != nil {
		lease := &daemonLockLease{file: f}
		lease.release()
		return nil, fmt.Errorf("daemon lock: record owner in %s: %w", path, err)
	}
	return &daemonLockLease{file: f}, nil
}

// writeDaemonLockPID records the process that now owns the held flock.
func writeDaemonLockPID(f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteString(strconv.Itoa(os.Getpid()) + "\n"); err != nil {
		return err
	}
	return f.Sync()
}

func readDaemonLockPID(f *os.File) int {
	buf := make([]byte, 32)
	n, err := f.ReadAt(buf, 0)
	if err != nil && n == 0 {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// daemonLockHeldByLiveProcess reports whether another open file description
// currently holds the production lock. Missing or unreadable state is not
// live ownership; callers that need exclusion must Acquire, not merely probe.
func daemonLockHeldByLiveProcess() bool {
	return daemonLockHeldByLiveProcessAt(DaemonLockPath)
}

func daemonLockHeldByLiveProcessAt(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := flockFn(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		_ = flockFn(int(f.Fd()), unix.LOCK_UN)
		return false
	} else {
		return isFlockContended(err)
	}
}

// release drops the flock and closes the owner file. It is idempotent. The
// path intentionally remains on tmpfs: deleting it while another descriptor
// awaited the old inode would split the singleton into two inodes.
func (l *daemonLockLease) release() {
	if l == nil || l.file == nil {
		return
	}
	// Clear the pid while the flock is held, so the next owner's brief
	// publish window starts empty rather than briefly naming this process
	// after it has already stopped. Best-effort for the same reason as the
	// upgrade lock's release truncate.
	_ = l.file.Truncate(0)
	_ = flockFn(int(l.file.Fd()), unix.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}
