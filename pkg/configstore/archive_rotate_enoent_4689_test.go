package configstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// #4689: archive rotation must tolerate a benign ENOENT. rotateArchives is
// spawned per commit and picks the oldest archive after an un-locked ReadDir,
// so two rapid back-to-back commits can race to remove the same file — the
// loser's os.Remove fails with ENOENT, which is an already-gone, not a real
// cleanup failure.
//
// RED-on-revert: dropping the `&& !os.IsNotExist(err)` guard in
// archiveRemoveErr (i.e. `return os.Remove(path)`) makes the missing-file case
// return a non-nil error and this test goes RED.
func TestArchiveRemoveErr_ENOENTTolerant(t *testing.T) {
	dir := t.TempDir()

	// Missing file — the concurrent-rotation race outcome — is benign.
	if err := archiveRemoveErr(filepath.Join(dir, "config-gone.conf")); err != nil {
		t.Fatalf("missing archive must be tolerated (benign ENOENT), got %v", err)
	}

	// A present archive is removed and reports no error.
	p := filepath.Join(dir, "config-1.conf")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed archive: %v", err)
	}
	if err := archiveRemoveErr(p); err != nil {
		t.Fatalf("removing a present archive must succeed, got %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("archive %s must be gone after removal (stat err=%v)", p, err)
	}
}

// TestRotateArchivesConcurrentNoError exercises the real rotateArchives under a
// back-to-back concurrent rotation over a shared directory: the loser of a
// remove race must not error out. With the ENOENT guard in place all extra
// archives end up removed regardless of how the two rotations interleave.
func TestRotateArchivesConcurrentNoError(t *testing.T) {
	dir := t.TempDir()
	const total = 40
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	for i := range total {
		ts := base.Add(time.Duration(i) * time.Second)
		if err := writeArchive(dir, 0, "x", ts, uint64(i+1)); err != nil {
			t.Fatalf("seed archive %d: %v", i, err)
		}
	}

	done := make(chan struct{}, 2)
	for range 2 {
		go func() {
			rotateArchives(dir, 1)
			done <- struct{}{}
		}()
	}
	<-done
	<-done

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	kept := 0
	for _, e := range entries {
		if !e.IsDir() {
			kept++
		}
	}
	if kept != 1 {
		t.Fatalf("rotation must keep exactly maxArchives=1 file, kept %d", kept)
	}
}
