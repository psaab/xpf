package fsatomic

// Test-only export hooks for fsatomic. They live in the production package
// (not an _test.go file) so tests in DEPENDENT packages (e.g. configstore,
// upgrade), which cannot reach the package-private seams, can drive REAL
// rename and post-rename directory-fsync failures end-to-end. Not for
// production callers. Mirrors the pkg/configstore/test_seams.go convention.

// SetAfterRenameSyncDirForTesting overrides the post-rename
// directory-fsync seam (afterRenameSyncDir) and returns a func that
// restores the previous value. It exists SOLELY so a cross-package test can
// force the durability-sync failure that occurs strictly AFTER a successful
// rename — the *PostRenameSyncError path — through a real WriteFileDurable
// call it does not control directly (#5234).
//
// The motivating consumer is pkg/configstore: its converge-to-C tests
// inject failures via the Store's writeActiveFn seam, which BYPASSES the DB
// layer's fmt.Errorf("persist %s: %w", …) wrap, so nothing proved the
// *PostRenameSyncError classification (errors.As in
// isPostRenameDurabilityFailure) still survives that %w boundary. With this
// hook a configstore test can drive db.WriteActive → writeTreeMarked →
// WriteFileDurable and fail the real dir-fsync, exercising the whole chain.
//
// Passing nil is a no-op that still returns a working restore func.
// Production code must NEVER call this; it mutates a process-global seam and
// is not safe under t.Parallel with concurrent WriteFileDurable callers.
func SetAfterRenameSyncDirForTesting(fn func(dir string) error) (restore func()) {
	prev := afterRenameSyncDir
	if fn != nil {
		afterRenameSyncDir = fn
	}
	return func() { afterRenameSyncDir = prev }
}

// SetRenameFileForTesting overrides the rename seam (renameFile) that
// WriteFileAtomic and WriteFileDurable use to publish the temp file, and
// returns a func that restores the previous value. It exists SOLELY so a
// cross-package test can make the rename ITSELF fail — the last PRE-rename
// stage, whose error is NOT a *PostRenameSyncError and leaves the OLD content
// in place — through a real write it does not control directly (#12549).
//
// It is the converse of SetAfterRenameSyncDirForTesting. The motivating
// consumer is pkg/upgrade: armCandidate treats a *PostRenameSyncError from its
// ARMED journal write as landed, so its tests must also prove that a rename
// which never landed still refuses the arm and leaves the journal at ARMING.
//
// Passing nil is a no-op that still returns a working restore func.
// Production code must NEVER call this; it mutates a process-global seam and
// is not safe under t.Parallel with concurrent WriteFileAtomic or
// WriteFileDurable callers.
func SetRenameFileForTesting(fn func(oldpath, newpath string) error) (restore func()) {
	prev := renameFile
	if fn != nil {
		renameFile = fn
	}
	return func() { renameFile = prev }
}
