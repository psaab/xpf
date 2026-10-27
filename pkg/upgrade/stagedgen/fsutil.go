package stagedgen

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// atomicRelSymlink atomically points link at a RELATIVE target (a basename in
// the same dir, e.g. current-gen -> <genid>) via temp+rename, then fsyncs the
// dir. NOT `ln -sf`, which unlink-then-creates and leaves a window where the
// link is absent (plan B-P2 / AGY r2-#1a).
func atomicRelSymlink(link, relTarget string) error {
	dir := filepath.Dir(link)
	tmp := filepath.Join(dir, "."+filepath.Base(link)+".tmp")
	// RemoveAll, not Remove: a stale directory at the temp path (manual
	// intervention / a previous failed run) would make os.Remove fail and the
	// subsequent Symlink fail EEXIST.
	_ = os.RemoveAll(tmp)
	if err := os.Symlink(relTarget, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync symlink dir: %w", err)
	}
	return nil
}
