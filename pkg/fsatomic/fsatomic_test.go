package fsatomic

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// resetSeams restores every test seam after a test mutates one.
func resetSeams(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		createTemp = os.CreateTemp
		renameFile = os.Rename
		statFile = os.Stat
		openDir = os.Open
		writeTemp = func(f *os.File, b []byte) (int, error) { return f.Write(b) }
		chmodTemp = func(f *os.File, m os.FileMode) error { return f.Chmod(m) }
		chownTemp = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
		syncFile = func(f *os.File) error { return f.Sync() }
		closeTemp = func(f *os.File) error { return f.Close() }
		afterRenameSyncDir = SyncDir
	})
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// assertNoTemps fails when a writer leaked its temp file.
func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("leaked temp files: %v", matches)
	}
}

func TestWriteFileAtomicHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := WriteFileAtomic(path, []byte("v1"), 0640); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	if got := mustRead(t, path); got != "v1" {
		t.Fatalf("content = %q, want v1", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("mode = %v, want 0640", fi.Mode().Perm())
	}
	assertNoTemps(t, dir)
}

func TestWriteFileDurableHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := WriteFileDurable(path, []byte("v1"), 0600); err != nil {
		t.Fatalf("WriteFileDurable: %v", err)
	}
	if got := mustRead(t, path); got != "v1" {
		t.Fatalf("content = %q, want v1", got)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	assertNoTemps(t, dir)
}

// TestModeEnforcedOverExisting pins the deliberate divergence from
// os.WriteFile: the caller's perm wins over an existing target's mode.
func TestModeEnforcedOverExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0644 {
		t.Fatalf("mode = %v, want enforced 0644", fi.Mode().Perm())
	}
}

func TestPreserveExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileDurable(path, []byte("new"), 0644, WithPreserveExisting()); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("mode = %v, want preserved 0640", fi.Mode().Perm())
	}
	if got := mustRead(t, path); got != "new" {
		t.Fatalf("content = %q, want new", got)
	}
}

// TestPreserveExistingNeverWidensBeyondCallerPerm pins #16046: a
// pre-existing mode WIDER than the caller's perm is capped, not lifted
// wholesale (legacy 0644 under a 0640 request lands 0640). A stricter
// existing mode is kept as-is (0600 under 0640 stays 0600). RED-on-revert:
// restoring mode = fi.Mode().Perm() makes the 0644 row land 0644.
func TestPreserveExistingNeverWidensBeyondCallerPerm(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing os.FileMode
		perm     os.FileMode
		want     os.FileMode
	}{
		{"wider-existing-capped", 0o644, 0o640, 0o640},
		{"stricter-existing-kept", 0o600, 0o640, 0o600},
		{"equal-existing-kept", 0o640, 0o640, 0o640},
		{"world-writable-capped", 0o777, 0o600, 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "out.conf")
			if err := os.WriteFile(path, []byte("old"), tc.existing); err != nil {
				t.Fatal(err)
			}
			// os.WriteFile is subject to umask; force the exact seed mode.
			if err := os.Chmod(path, tc.existing); err != nil {
				t.Fatal(err)
			}
			if err := WriteFileDurable(path, []byte("new"), tc.perm, WithPreserveExisting()); err != nil {
				t.Fatal(err)
			}
			fi, _ := os.Stat(path)
			if fi.Mode().Perm() != tc.want {
				t.Fatalf("mode = %04o, want %04o (existing %04o & perm %04o, #16046 never-widen)",
					fi.Mode().Perm(), tc.want, tc.existing, tc.perm)
			}
			if got := mustRead(t, path); got != "new" {
				t.Fatalf("content = %q, want new", got)
			}
		})
	}
}

// TestWithOwnerChownsTempBeforeRename asserts WithOwner fchowns the temp
// fd (not a post-rename path chown) and that the chown happens before the
// rename — the invariant that prevents a crash-window root-owned keys file.
func TestWithOwnerChownsTempBeforeRename(t *testing.T) {
	resetSeams(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")

	var (
		chownedUID, chownedGID int
		chownCalled, renamed   bool
		chownBeforeRename      bool
	)
	chownTemp = func(f *os.File, uid, gid int) error {
		chownCalled = true
		chownedUID, chownedGID = uid, gid
		if !renamed {
			chownBeforeRename = true
		}
		return nil // cannot actually chown to arbitrary uid as non-root
	}
	renameFile = func(oldp, newp string) error {
		renamed = true
		return os.Rename(oldp, newp)
	}

	if err := WriteFileDurable(path, []byte("new"), 0600, WithOwner(4242, 4343)); err != nil {
		t.Fatalf("WriteFileDurable: %v", err)
	}
	if !chownCalled {
		t.Fatal("WithOwner did not chown the temp fd")
	}
	if chownedUID != 4242 || chownedGID != 4343 {
		t.Fatalf("chown(%d,%d), want (4242,4343)", chownedUID, chownedGID)
	}
	if !chownBeforeRename {
		t.Fatal("chown ran after rename — temp must be owned before install")
	}
	if got := mustRead(t, path); got != "new" {
		t.Fatalf("content = %q, want new", got)
	}
	assertNoTemps(t, dir)
}

// TestWithOwnerPrecedenceOverPreserveExisting pins the settled precedence:
// when both options are set, WithOwner WINS ownership and
// WithPreserveExisting keeps the existing target's MODE.
func TestWithOwnerPrecedenceOverPreserveExisting(t *testing.T) {
	resetSeams(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	// Existing target reports owner 12345:12345 via the stat seam.
	statFile = func(name string) (os.FileInfo, error) {
		fi, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		return fakeFileInfo{FileInfo: fi, st: &syscall.Stat_t{Uid: 12345, Gid: 12345, Mode: uint32(fi.Mode().Perm())}}, nil
	}
	var chownedUID, chownedGID int
	chownTemp = func(f *os.File, uid, gid int) error {
		chownedUID, chownedGID = uid, gid
		return nil
	}

	if err := WriteFileDurable(path, []byte("new"), 0644,
		WithPreserveExisting(), WithOwner(7000, 7001)); err != nil {
		t.Fatalf("WriteFileDurable: %v", err)
	}
	// Ownership comes from WithOwner, not the preserved 12345:12345.
	if chownedUID != 7000 || chownedGID != 7001 {
		t.Fatalf("chown(%d,%d), want WithOwner (7000,7001)", chownedUID, chownedGID)
	}
	// Mode comes from WithPreserveExisting capped at perm (0640 & 0644 =
	// 0640), not the raw perm arg alone in general — here both agree.
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("mode = %v, want preserved-capped 0640", fi.Mode().Perm())
	}
}

func TestResolveSymlinksWritesThrough(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.conf")
	link := filepath.Join(dir, "link.conf")
	if err := os.WriteFile(real, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileDurable(link, []byte("new"), 0644, WithResolveSymlinks()); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link should remain a symlink, lstat: %v %v", fi, err)
	}
	if got := mustRead(t, real); got != "new" {
		t.Fatalf("resolved target content = %q, want new", got)
	}
}

func TestDanglingSymlinkResolvesToDestination(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.conf")
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink("dest.conf", link); err != nil { // relative, dangling
		t.Fatal(err)
	}
	if err := WriteFileAtomic(link, []byte("v"), 0644, WithResolveSymlinks()); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, dest); got != "v" {
		t.Fatalf("dangling-link destination content = %q, want v", got)
	}
}

func TestWithoutResolveSymlinksReplacesLink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.conf")
	link := filepath.Join(dir, "link.conf")
	if err := os.WriteFile(real, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(link, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("link should have been replaced by a regular file")
	}
	if got := mustRead(t, real); got != "old" {
		t.Fatalf("original target mutated to %q, want old", got)
	}
}

// fakeFileInfo lets the preserve-owner path observe a target owned by a
// different uid/gid without requiring root.
type fakeFileInfo struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (f fakeFileInfo) Sys() any { return f.st }

func TestChownFailureSurfaced(t *testing.T) {
	resetSeams(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	statFile = func(name string) (os.FileInfo, error) {
		fi, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		return fakeFileInfo{FileInfo: fi, st: &syscall.Stat_t{Uid: 12345, Gid: 12345, Mode: uint32(fi.Mode().Perm())}}, nil
	}
	injected := errors.New("injected chown failure")
	chownTemp = func(f *os.File, uid, gid int) error { return injected }

	err := WriteFileDurable(path, []byte("new"), 0644, WithPreserveExisting())
	if !errors.Is(err, injected) {
		t.Fatalf("err = %v, want injected chown failure", err)
	}
	if got := mustRead(t, path); got != "old" {
		t.Fatalf("target mutated to %q on chown failure, want old", got)
	}
	assertNoTemps(t, dir)
}

// TestInjectedStageFailures drives one failure per writer stage and
// asserts the three writer invariants: the error names the stage, the
// existing target is untouched, and the temp file is cleaned up.
func TestInjectedStageFailures(t *testing.T) {
	injected := errors.New("injected failure")
	stages := []struct {
		name    string
		inject  func()
		errFrag string
	}{
		{"create-temp", func() {
			createTemp = func(dir, pattern string) (*os.File, error) { return nil, injected }
		}, "create temp file"},
		{"write", func() {
			writeTemp = func(f *os.File, b []byte) (int, error) { return 0, injected }
		}, "write temp file"},
		{"chmod", func() {
			chmodTemp = func(f *os.File, m os.FileMode) error { return injected }
		}, "chmod temp file"},
		{"sync", func() {
			syncFile = func(f *os.File) error { return injected }
		}, "sync temp file"},
		{"close", func() {
			closeTemp = func(f *os.File) error { _ = f.Close(); return injected }
		}, "close temp file"},
		{"rename", func() {
			renameFile = func(o, n string) error { return injected }
		}, "rename"},
	}

	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			resetSeams(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "out.conf")
			if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
				t.Fatal(err)
			}
			st.inject()
			err := WriteFileDurable(path, []byte("new"), 0644)
			if !errors.Is(err, injected) {
				t.Fatalf("err = %v, want injected failure", err)
			}
			if !strings.Contains(err.Error(), st.errFrag) {
				t.Errorf("err %q should name stage %q", err, st.errFrag)
			}
			if got := mustRead(t, path); got != "old" {
				t.Fatalf("target mutated to %q on %s failure, want old", got, st.name)
			}
			assertNoTemps(t, dir)
		})
	}
}

// TestDirFsyncFailureSurfacedAfterRename pins the documented post-rename
// failure shape: the new content IS visible (rename already happened)
// but the durable writer still reports the dir-fsync error.
func TestDirFsyncFailureSurfacedAfterRename(t *testing.T) {
	resetSeams(t)
	injected := errors.New("injected dir fsync failure")
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	openDir = func(name string) (*os.File, error) { return nil, injected }

	err := WriteFileDurable(path, []byte("new"), 0644)
	if !errors.Is(err, injected) {
		t.Fatalf("err = %v, want injected dir fsync failure", err)
	}
	if got := mustRead(t, path); got != "new" {
		t.Fatalf("content = %q — rename precedes dir fsync, new content must be visible", got)
	}
	assertNoTemps(t, dir)
}

// TestAtomicSkipsFsyncs proves WriteFileAtomic never reaches the sync
// stages — the whole point of the AtomicGeneratedConfig class.
func TestAtomicSkipsFsyncs(t *testing.T) {
	resetSeams(t)
	syncCalls := 0
	syncFile = func(f *os.File) error { syncCalls++; return f.Sync() }
	openCalls := 0
	openDir = func(name string) (*os.File, error) { openCalls++; return os.Open(name) }

	dir := t.TempDir()
	if err := WriteFileAtomic(filepath.Join(dir, "out.conf"), []byte("v"), 0644); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 0 || openCalls != 0 {
		t.Fatalf("atomic writer fsynced (file syncs=%d, dir opens=%d), want 0/0", syncCalls, openCalls)
	}
}

// TestDurableFsyncsFileAndDir counts both fsync stages on the durable path.
func TestDurableFsyncsFileAndDir(t *testing.T) {
	resetSeams(t)
	syncCalls := 0
	syncFile = func(f *os.File) error { syncCalls++; return f.Sync() }

	dir := t.TempDir()
	if err := WriteFileDurable(filepath.Join(dir, "out.conf"), []byte("v"), 0644); err != nil {
		t.Fatal(err)
	}
	// One temp-file fsync + one dir fsync (SyncDir routes through syncFile).
	if syncCalls != 2 {
		t.Fatalf("durable writer made %d fsyncs, want 2 (temp + dir)", syncCalls)
	}
}

func TestMkdirAllDurable(t *testing.T) {
	resetSeams(t)
	syncCalls := 0
	syncFile = func(f *os.File) error { syncCalls++; return f.Sync() }

	root := t.TempDir()
	target := filepath.Join(root, "a", "b", "c")
	if err := MkdirAllDurable(target, 0755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil || !fi.IsDir() {
		t.Fatalf("target not a dir: %v", err)
	}
	// Three created levels (a, b, c) + the pre-existing root = 4 fsyncs.
	if syncCalls != 4 {
		t.Fatalf("creation made %d fsyncs, want 4 (3 new levels + parent)", syncCalls)
	}

	// Existing path: plain MkdirAll, zero fsyncs.
	syncCalls = 0
	if err := MkdirAllDurable(target, 0755); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 0 {
		t.Fatalf("existing path made %d fsyncs, want 0", syncCalls)
	}

	// Regular file in the way: the MkdirAll error is surfaced.
	blocked := filepath.Join(root, "file")
	if err := os.WriteFile(blocked, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAllDurable(filepath.Join(blocked, "x"), 0755); err == nil {
		t.Fatal("MkdirAllDurable through a regular file should error")
	}
}

func TestSyncDir(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
	if err := SyncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("SyncDir on missing dir should error")
	}
}

func TestEmptyData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.conf")
	if err := WriteFileDurable(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, path); got != "" {
		t.Fatalf("content = %q, want empty", got)
	}
}

func TestConcurrentWritersLastOneWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			done <- WriteFileDurable(path, []byte(fmt.Sprintf("writer-%d", i)), 0644)
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}
	got := mustRead(t, path)
	if !strings.HasPrefix(got, "writer-") {
		t.Fatalf("content = %q, want a complete writer-N payload (no tearing)", got)
	}
	assertNoTemps(t, dir)
}

// TestWriteFileDurable_PostRenameSyncErrorClassified pins the #5185
// pre/post-rename distinction. A directory-fsync failure that happens
// AFTER a successful rename must be returned as *PostRenameSyncError, and
// the NEW content must be visible on disk — a restart would load it. The
// test fails RED if the wrapping is dropped (a caller could then report a
// clean rejection while the new content is durable, the reported-rejected-
// but-durable divergence).
func TestWriteFileDurable_PostRenameSyncErrorClassified(t *testing.T) {
	resetSeams(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("OLD"), 0600); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected dir fsync failure")
	afterRenameSyncDir = func(string) error { return injected }

	err := WriteFileDurable(path, []byte("NEW"), 0600)
	if err == nil {
		t.Fatal("expected an error from the post-rename dir fsync")
	}
	var pre *PostRenameSyncError
	if !errors.As(err, &pre) {
		t.Fatalf("post-rename failure must be *PostRenameSyncError, got %T: %v", err, err)
	}
	if !errors.Is(err, injected) {
		t.Fatalf("PostRenameSyncError must wrap the underlying fsync error: %v", err)
	}
	if pre.Path != path {
		t.Errorf("PostRenameSyncError.Path = %q, want %q", pre.Path, path)
	}
	// The rename already happened: the new content is visible on disk.
	if got := mustRead(t, path); got != "NEW" {
		t.Errorf("post-rename content = %q, want NEW (rename succeeded before the fsync)", got)
	}
	assertNoTemps(t, dir)
}

// TestWriteFileDurable_PreRenameNotClassifiedPostRename proves the
// converse: any PRE-rename failure (here the rename syscall itself) must
// NOT be classified as *PostRenameSyncError, and the OLD content must
// remain intact — a clean rejection is correct there.
func TestWriteFileDurable_PreRenameNotClassifiedPostRename(t *testing.T) {
	resetSeams(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("OLD"), 0600); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected rename failure")
	renameFile = func(o, n string) error { return injected }

	err := WriteFileDurable(path, []byte("NEW"), 0600)
	if err == nil {
		t.Fatal("expected an error from the rename")
	}
	var pre *PostRenameSyncError
	if errors.As(err, &pre) {
		t.Fatalf("a pre-rename (rename) failure must NOT be *PostRenameSyncError: %v", err)
	}
	if got := mustRead(t, path); got != "OLD" {
		t.Errorf("pre-rename failure content = %q, want OLD intact", got)
	}
	assertNoTemps(t, dir)
}

// TestWriteFileDurable_TempFsyncIsPreRename guards the seam split: the
// pre-rename temp-file fsync (syncFile) failing must stay a pre-rename
// error, NOT a post-rename one, even though both stages fsync.
func TestWriteFileDurable_TempFsyncIsPreRename(t *testing.T) {
	resetSeams(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "out.conf")
	if err := os.WriteFile(path, []byte("OLD"), 0600); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected temp fsync failure")
	syncFile = func(*os.File) error { return injected }

	err := WriteFileDurable(path, []byte("NEW"), 0600)
	var pre *PostRenameSyncError
	if errors.As(err, &pre) {
		t.Fatalf("a temp-file fsync failure is pre-rename, must NOT be *PostRenameSyncError: %v", err)
	}
	if got := mustRead(t, path); got != "OLD" {
		t.Errorf("temp-fsync failure content = %q, want OLD intact", got)
	}
	assertNoTemps(t, dir)
}
