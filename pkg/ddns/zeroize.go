package ddns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// DefaultSurfaceAStatePath returns the production interface-address (Surface
// A) DDNS ownership-store path. Exported so factory reset can erase the same
// file its manager owns rather than a duplicated literal.
func DefaultSurfaceAStatePath() string { return defaultSurfaceAStatePath }

// CheckStateEmpty proves a DDNS ownership store has no outstanding DNS cleanup
// authority before factory reset erases it. Corrupt/degraded state, unknown
// ownership, symlinks, and quarantined records all fail closed.
func CheckStateEmpty(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return checkNoStateResidue(path)
		}
		return fmt.Errorf("ddns: inspect ownership state %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("ddns: ownership state %s is not a regular file", path)
	}
	if err := checkNoStateResidue(path); err != nil {
		return err
	}
	state, err := loadDDNSState(path)
	if err != nil {
		return fmt.Errorf("ddns: cannot prove ownership state %s is empty: %w", path, err)
	}
	if records := state.all(); len(records) != 0 {
		return fmt.Errorf("ddns: ownership state %s still has %d record(s); published DNS records must be withdrawn before factory reset", path, len(records))
	}
	return nil
}

// EraseStateIfEmpty removes an empty, trusted DDNS ownership store and durably
// syncs its parent. It never erases delete authority for a published DNS RR.
func EraseStateIfEmpty(path string) error {
	if err := CheckStateEmpty(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ddns: remove empty ownership state %s: %w", path, err)
	}
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ddns: sync ownership-state directory for %s: %w", path, err)
	}
	return nil
}

func checkNoStateResidue(path string) error {
	if _, err := os.Lstat(degradedMarkerPath(path)); err == nil {
		return fmt.Errorf("ddns: ownership state %s has a degraded marker; published records cannot be proven withdrawn", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ddns: inspect degraded marker for %s: %w", path, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("ddns: inspect ownership-state directory for %s: %w", path, err)
	}
	prefix := filepath.Base(path) + ".corrupt-"
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			return fmt.Errorf("ddns: ownership state %s has quarantined records in %s", path, entry.Name())
		}
	}
	return nil
}
