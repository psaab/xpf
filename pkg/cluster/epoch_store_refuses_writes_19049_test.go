package cluster

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// refuseDurableWritesInto19049 makes every fsatomic write whose target lies in
// dir fail at its rename — the last PRE-rename stage, so the write returns an
// ordinary error (not a *PostRenameSyncError) and the old content, or no file
// at all, stays in place. That is the store the #6669 and #6724 epoch cells
// need: one that READS but cannot WRITE, the way a full or read-only /var
// refuses the epoch persist. The epoch file and its #7501 owner sidecar both
// live in dir and are both refused, as they are on such a store; the .lock is
// opened in place, not renamed, so it is untouched.
//
// THESE CELLS USED TO chmod THE DIRECTORY 0555 INSTEAD (#19049). A directory's
// write bit does not refuse uid 0: CAP_DAC_OVERRIDE bypasses it, and the Go
// suite runs as uid 0 — scripts/testguard-run.sh enters `unshare -Urp` (uid 0
// in a user namespace that owns the test's files) or, on a test-runner VM's
// root leg, is real root. There the "failing" write LANDED. Every cell built on
// it either failed its own premise check ("the persist was supposed to FAIL")
// or, had it lacked one, would have passed proving nothing. And as a non-root
// user the chmod reached the wrong branch in three of the #6724 cells: no
// .lock existed yet, so withEpochFileLock's O_CREATE open failed first and
// refineBootEpochReporting reported the owed persist from its `!ran` arm,
// never from the write-failure arm those cells name. The rename seam reaches
// the write-failure arm whoever runs the suite.
//
// clear is "the fault clears" (the operator frees space, remounts rw): writes
// started after it land normally. The process-global seam is installed once
// here and restored only at cleanup, so a worker running across clear never
// reads a seam that is being swapped under it.
func refuseDurableWritesInto19049(t *testing.T, dir string) (clear func()) {
	t.Helper()
	dirs := map[string]bool{filepath.Clean(dir): true}
	// fsatomic may hand the seam a symlink-resolved target; match either
	// spelling of the directory.
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dirs[filepath.Clean(resolved)] = true
	}
	var refusing atomic.Bool
	refusing.Store(true)
	restore := fsatomic.SetRenameFileForTesting(func(oldpath, newpath string) error {
		if refusing.Load() && dirs[filepath.Dir(newpath)] {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EROFS}
		}
		return os.Rename(oldpath, newpath)
	})
	t.Cleanup(restore)
	return func() { refusing.Store(false) }
}
