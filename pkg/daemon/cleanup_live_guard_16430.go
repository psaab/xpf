// #16430: the `xpfd cleanup` live-daemon interlock.
//
// CloseKernelTransitForCleanup (transit_cleanup_9725.go) documents its
// precondition — "cleanup runs in a short-lived process after the daemon
// has exited" — but until now nothing enforced it. Run beside a live
// daemon, `xpfd cleanup` closed kernel transit, unpinned every dataplane
// link, deleted the fabric IPVLANs and rewrote frr.conf without the
// managed section while the daemon kept reporting healthy; the durable
// damage (FRR routing withdrawal until the next commit, deleted fabric
// overlay) was invisible to the daemon.
//
// GuardDaemonLockForCleanup enforces the precondition by ACQUIRING the
// #15085 singleton for the duration of cleanup, rather than merely
// probing it: a check-then-cleanup probe leaves a TOCTOU window in which
// a daemon starting between the probe and the first mutation would be
// torn down mid-startup. Holding the lock means a daemon cannot start
// during cleanup (daemon.New refuses with ErrDaemonAlreadyRunning) and
// cleanup cannot start while a daemon holds it. The caller MUST release
// the returned lease when cleanup is done; a nil lease with a nil error
// never occurs.
package daemon

import "fmt"

// CleanupLease is the held singleton lease that proves no live daemon
// exists for the duration of `xpfd cleanup`. Release it (idempotently)
// when cleanup finishes.
type CleanupLease struct {
	lease *daemonLockLease
}

// Release drops the singleton flock held for cleanup. It is safe to call
// on a nil or already-released lease.
func (l *CleanupLease) Release() {
	if l == nil {
		return
	}
	l.lease.release()
	l.lease = nil
}

// GuardDaemonLockForCleanup acquires the daemon singleton so cleanup
// cannot race a live — or starting — daemon. While a daemon holds the
// lock it returns an error wrapping ErrDaemonAlreadyRunning that names
// the remediation (`systemctl stop xpfd`); the caller must refuse before
// any transit/pin/fabric/FRR mutation.
func GuardDaemonLockForCleanup() (*CleanupLease, error) {
	lease, err := acquireDaemonLock()
	if err != nil {
		return nil, fmt.Errorf("cleanup refused: %w; stop the daemon first ('systemctl stop xpfd') and retry", err)
	}
	return &CleanupLease{lease: lease}, nil
}

// DaemonLockHeldByLiveProcess reports whether a live process currently
// holds the daemon singleton lock. It is the exported probe form of
// daemonLockHeldByLiveProcess (#15085) for one-shot verbs that only need
// to refuse beside a live daemon. Callers that mutate daemon-owned state
// should prefer GuardDaemonLockForCleanup, which holds the lock and so
// also excludes a daemon starting concurrently.
func DaemonLockHeldByLiveProcess() bool {
	return daemonLockHeldByLiveProcess()
}
