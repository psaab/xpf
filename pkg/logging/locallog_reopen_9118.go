package logging

import (
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// #9118: the recovery leg #3478 deliberately did not ship.
//
// THE WEDGE. rotate() closes the active file and sets lw.file = nil BEFORE
// reopening. If openHardenedAuditLog then fails -- EMFILE, ENFILE, ENOSPC,
// EROFS, EACCES -- it bumps failedRotations and returns with the handle still
// nil. Every subsequent Send / SendBinary / WriteRecord takes the `file == nil`
// arm and drops.
//
// AND NOTHING RE-FIRES. rotate() is called only from `if lw.written >=
// lw.maxSize`, i.e. after a SUCCESSFUL write. Once wedged, `written` never
// advances, so the only caller of the only reopen in the file can never run
// again. One transient error at a rotation boundary silences the local audit
// and trace channel -- the channel an operator uses to reconstruct an incident
// -- until the next config commit or a daemon restart.
//
// #3478 made this state OBSERVABLE (counters, a rate-limited WARN, rotate
// returning an error) and said so; pkg/logging/README.md names the state in as
// many words. Observability is not recovery, and on an unattended appliance in
// steady state "until the next commit" is unbounded.
//
// WHY A `closed` FLAG IS REQUIRED AND NOT DEFENSIVE CLUTTER. Close() also sets
// lw.file = nil, so a nil handle means EITHER "wedged" OR "shut down on
// purpose". Reopening on the second reading is worse than the bug: it would
// recreate an audit file after the writer was deliberately closed, and on the
// ReplaceLocalWriters path it would resurrect a writer the daemon has just
// retired. The two states are indistinguishable from the handle alone, so they
// are distinguished explicitly.
//
// RATE-LIMITED, because the failure is usually not transient in the instant.
// Under ENOSPC every write would otherwise issue an openat, turning a full disk
// into a syscall storm on the logging path. One attempt per interval bounds
// that, and the interval is short enough that recovery is measured in seconds.

// reopenBackoff9118 is the minimum spacing between reopen attempts on a wedged
// writer. A var only so a test can shorten it; production never writes it.
var reopenBackoff9118 = time.Second

// wedgeState9118 carries the recovery bookkeeping. Embedded rather than added
// as loose fields so the whole mechanism is greppable from one name.
type wedgeState9118 struct {
	closed      bool      // Close() was called: never reopen
	lastAttempt time.Time // last reopen attempt, for the backoff
	recovered   atomic.Uint64
}

// ensureOpenForWriter is the single implementation behind both writers'
// ensureOpenLocked methods (#16181, dedup of #9118). It attempts to recover
// a wedged writer and reports whether the handle is usable afterwards.
//
// Only cheap scalars and field references cross into the helper: logPath is
// the writer's path as logged (lw.path / tw.path), openArg is the argument
// for the writer-specific open (lw.path for openHardenedAuditLog, tw.name
// for openTraceFile), and trace selects between those two open paths and
// the recovery log message. The open call and the recovery log attributes
// are constructed only inside the reopen branch below, so the healthy
// path (file != nil, taken on every ordinary write) performs no callback
// or slice construction and allocates nothing -- verified by an
// AllocsPerRun probe in locallog_reopen_dedup_16181_test.go.
//
// file and written are pointer parameters because the two writer structs
// store them in distinct field sets that cannot share a base type without
// restructuring both writers; passing them explicitly keeps this helper
// free of writer-specific knowledge beyond the supplied scalars. wedge is
// shared because both writers already embed wedgeState9118.
//
// The caller must hold the owning writer's mutex.
//
// Returns false without touching the filesystem when the writer was closed
// deliberately, or when the last attempt was too recent -- so a caller can
// use the result directly as "may I write?" and the existing drop-and-count
// arm stays exactly where it was for the cases that genuinely cannot write.
func ensureOpenForWriter(wedge *wedgeState9118, file **os.File, written *int64, dropped, failed *atomic.Uint64, logPath, openArg string, trace bool) bool {
	if *file != nil {
		return true
	}
	if wedge.closed {
		return false
	}
	now := time.Now()
	if !wedge.lastAttempt.IsZero() && now.Sub(wedge.lastAttempt) < reopenBackoff9118 {
		return false
	}
	wedge.lastAttempt = now

	// Reopen branch only (slow path): select the writer-specific open and,
	// on success, build the recovery log record. Keeping both out of the
	// wrappers above the healthy check is what keeps a healthy write at
	// zero allocations.
	var f *os.File
	var err error
	if trace {
		f, err = openTraceFile(openArg)
	} else {
		f, err = openHardenedAuditLog(openArg, os.O_APPEND)
	}
	if err != nil {
		// Deliberately NOT counted as a failed rotation: no rotation was
		// attempted. It is counted by the caller's existing drop path, which is
		// the honest accounting -- one dropped line, one drop.
		return false
	}
	*file = f
	// Re-sync the byte count to the file that actually exists. The wedge may
	// have begun mid-rotation, so *written describes a file that was already
	// renamed aside; carrying it forward would make the next rotation fire
	// against the wrong size.
	if info, statErr := f.Stat(); statErr == nil {
		*written = info.Size()
	} else {
		*written = 0
	}
	wedge.recovered.Add(1)
	logMsg := "local security-log writer recovered after a failed rotation reopen (#9118)"
	if trace {
		logMsg = "flow-trace writer recovered after a failed rotation reopen (#9118)"
	}
	slog.Warn(logMsg,
		"path", logPath,
		"dropped_writes", dropped.Load(),
		"failed_rotations", failed.Load(),
		"recoveries", wedge.recovered.Load())
	return true
}

// ensureOpenLocked attempts to recover a wedged writer, and reports whether
// the handle is usable afterwards. The caller must hold lw.mu.
//
// Thin wrapper over ensureOpenForWriter (#16181): the local writer opens a
// raw path via openHardenedAuditLog, which is deliberately NOT unified with
// the trace writer's open path (openTraceFile resolves under the trace dir
// and takes a sanitised basename). Only cheap scalars are passed, so a
// healthy write allocates nothing.
func (lw *LocalLogWriter) ensureOpenLocked() bool {
	return ensureOpenForWriter(&lw.wedge, &lw.file, &lw.written, &lw.droppedWrites, &lw.failedRotations, lw.path, lw.path, false)
}

// RecoveredWrites reports how many times a wedged writer was reopened (#9118).
// Exported for the same reason DroppedWrites is: an operator must be able to
// distinguish "the audit channel never broke" from "it broke and healed", and
// those two look identical if only the drop counter is visible.
func (lw *LocalLogWriter) RecoveredWrites() uint64 { return lw.wedge.recovered.Load() }

// ensureOpenLocked is the TraceWriter wrapper over ensureOpenForWriter
// (#16181). It exists as a separate method only because the trace writer
// opens a different path: openTraceFile resolves under traceLogDir and
// sanitises the basename, which openHardenedAuditLog on a raw path would
// not. The recovery logic itself is the shared helper above, and only
// cheap scalars are passed so a healthy write allocates nothing.
func (tw *TraceWriter) ensureOpenLocked() bool {
	return ensureOpenForWriter(&tw.wedge, &tw.file, &tw.written, &tw.droppedWrites, &tw.failedRotations, tw.path, tw.name, true)
}

// RecoveredWrites reports how many times a wedged trace writer was reopened.
func (tw *TraceWriter) RecoveredWrites() uint64 { return tw.wedge.recovered.Load() }

// wedgeAttemptForTest9118 exposes the last reopen attempt time so a cell can
// assert the backoff actually suppresses a retry, rather than asserting it by
// counting syscalls it cannot see.
func (lw *LocalLogWriter) wedgeAttemptForTest9118() time.Time {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.wedge.lastAttempt
}
