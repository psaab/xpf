package factoryreset

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// TestZeroizeConfigDirDurableOrdering pins #5197 A4-b1-F5 on the gRPC
// factory-reset path (the mirror of pkg/configstore FactoryResetConfigDir):
// the wipe must fsync .configdb AFTER the master.key unlink and BEFORE the
// ciphertext RemoveAll, then fsync configDir at the end so every unlink is
// durable. Without the mid barrier the key-first cryptographic-erasure
// guarantee is not durably enforced; without the final fsync a wipe whose
// namespace changes never reached stable storage is reported as a clean
// zeroize.
//
// RED on revert: dropping either fsatomic.SyncDir call changes the recorded
// seam order and trips the exact match below.
func TestZeroizeConfigDirDurableOrdering(t *testing.T) {
	orig := wipeSyncDir
	t.Cleanup(func() { wipeSyncDir = orig })

	var syncedDirs []string
	wipeSyncDir = func(dir string) error {
		syncedDirs = append(syncedDirs, dir)
		return fsatomic.SyncDir(dir)
	}

	dir := t.TempDir()
	dbDir := filepath.Join(dir, ".configdb")
	mustWriteFile(t, filepath.Join(dbDir, "master.key"), make([]byte, 32))
	mustWriteFile(t, filepath.Join(dbDir, "active.json"), []byte("cipher"))

	if err := wipeConfigDir(dir, "xpf.conf"); err != nil {
		t.Fatalf("wipeConfigDir: %v", err)
	}

	// .configdb fsynced first (key-first durability barrier), configDir last.
	// #9897: the wipe records RESOLVED paths, so normalize the want side for a
	// symlinked TMPDIR (macOS /var -> /private/var); identity on Linux.
	wantDir, werr := filepath.EvalSymlinks(dir)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, werr)
	}
	want := []string{filepath.Join(wantDir, ".configdb"), wantDir}
	if !reflect.DeepEqual(syncedDirs, want) {
		t.Errorf("durable-erase fsync order mismatch:\n got  %v\n want %v", syncedDirs, want)
	}
	if _, err := os.Stat(dbDir); !os.IsNotExist(err) {
		t.Errorf(".configdb should be gone after zeroize, stat err=%v", err)
	}
}

// TestZeroizeConfigDirPropagatesDirSyncError pins the second half of #5197
// A4-b1-F5 on the gRPC path: a final directory-fsync failure must be surfaced,
// not swallowed (the pre-fix wipeConfigDir performed no dir fsync at all, so
// a non-durable wipe was always reported as clean).
//
// RED on revert: removing the final wipeSyncDir(configDir) call makes
// wipeConfigDir return nil here.
func TestZeroizeConfigDirPropagatesDirSyncError(t *testing.T) {
	orig := wipeSyncDir
	t.Cleanup(func() { wipeSyncDir = orig })

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, ".configdb", "master.key"), make([]byte, 32))

	// #9897: the wipe invokes the seam with the RESOLVED root; compare
	// against the resolved want or the sentinel never fires under a
	// symlinked TMPDIR (macOS /var -> /private/var).
	wantDir, werr := filepath.EvalSymlinks(dir)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, werr)
	}
	sentinel := errors.New("injected final dir fsync failure")
	wipeSyncDir = func(d string) error {
		if filepath.Clean(d) == wantDir {
			return sentinel // fail ONLY the final configDir barrier
		}
		return fsatomic.SyncDir(d)
	}

	err := wipeConfigDir(dir, "xpf.conf")
	if err == nil {
		t.Fatalf("wipeConfigDir must surface a final dir-fsync failure, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("returned error = %v, want it to wrap the injected fsync failure", err)
	}
}
