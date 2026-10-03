package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// TestDeleteRescueConfigDirSynced pins #5197 A4-b1-F10: deleting rescue.conf
// must be a DURABLE transition. SaveRescueConfig writes rescue.conf via
// fsatomic.WriteFileDurable (dir-synced), so the delete must fsync the parent
// directory too — a bare os.Remove is not durable, and a crash/power-loss in
// the window before the directory entry removal flushes can replay the
// deleted, secret-bearing rescue.conf on reboot.
//
// RED on revert: dropping the fsatomic.SyncDir call after the unlink leaves
// syncedDir empty, tripping the assertion below.
func TestDeleteRescueConfigDirSynced(t *testing.T) {
	restoreRollbackSeams(t)

	var removedPaths []string
	var syncedDir string
	rbRemove = func(path string) error {
		removedPaths = append(removedPaths, path)
		return os.Remove(path)
	}
	rbSyncDir = func(dir string) error {
		syncedDir = dir
		return fsatomic.SyncDir(dir)
	}

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if _, err := s.SyncApply("system { host-name rescue-delete; }", nil); err != nil {
		t.Fatalf("SyncApply rescue fixture: %v", err)
	}
	// Materialize a real rescue.conf through the production save path.
	if err := s.SaveRescueConfig(); err != nil {
		t.Fatalf("SaveRescueConfig: %v", err)
	}
	rescuePath := s.rescuePath()
	if _, err := os.Stat(rescuePath); err != nil {
		t.Fatalf("rescue.conf must exist after SaveRescueConfig: %v", err)
	}

	if err := s.DeleteRescueConfig(); err != nil {
		t.Fatalf("DeleteRescueConfig: %v", err)
	}

	// The file must be gone.
	if _, err := os.Stat(rescuePath); !os.IsNotExist(err) {
		t.Fatalf("rescue.conf still present after DeleteRescueConfig: err=%v", err)
	}
	// The unlink must have gone through the seam.
	if !containsPath(removedPaths, rescuePath) {
		t.Errorf("rescue.conf unlink not recorded; removed=%v", removedPaths)
	}
	// The parent directory MUST have been fsynced so the unlink is durable.
	wantDir := filepath.Dir(rescuePath)
	if syncedDir != wantDir {
		t.Errorf("rescue-config directory %q was not fsync'd after delete (SyncDir called on %q)",
			wantDir, syncedDir)
	}
}

// TestDeleteRescueConfigAbsentNoDirSync confirms the absent path: deleting a
// rescue config that does not exist returns the existing "no rescue
// configuration exists" error and does NOT fsync the directory (nothing was
// unlinked, so there is nothing to make durable).
func TestDeleteRescueConfigAbsentNoDirSync(t *testing.T) {
	restoreRollbackSeams(t)

	var syncedDir string
	rbSyncDir = func(dir string) error {
		syncedDir = dir
		return fsatomic.SyncDir(dir)
	}

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	// No rescue.conf written.
	err := s.DeleteRescueConfig()
	if err == nil || !strings.Contains(err.Error(), "no rescue configuration exists") {
		t.Fatalf("DeleteRescueConfig on absent file should report absence, got %v", err)
	}
	if syncedDir != "" {
		t.Errorf("absent-file delete must not fsync the directory, synced %q", syncedDir)
	}
}
