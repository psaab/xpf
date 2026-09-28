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
// Crash-leaked fsatomic write temps for the store are removed with it: every
// durable save stages full state JSON in a .<base>.tmp-* file first, so a
// temp orphaned by a crash during reconcile holds tenant FQDNs/addresses a
// canonical-only erase would hand to the next tenant. Hardlink residual
// (F2): no nlink census on the canonical or its temps — a hardlinked
// store is unlinked by name while a sibling retains the bytes silently.
func EraseStateIfEmpty(path string) error {
	if err := CheckStateEmpty(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ddns: remove empty ownership state %s: %w", path, err)
	}
	if err := sweepCrashTemps(path); err != nil {
		return err
	}
	if temps, err := ListCrashTemps(path); err != nil {
		return err
	} else if len(temps) != 0 {
		return fmt.Errorf("ddns: crash temps reappeared for %s after sweep: %v", path, temps)
	}
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ddns: sync ownership-state directory for %s: %w", path, err)
	}
	return nil
}

// ListCrashTemps returns the crash-leaked fsatomic write temps staged for
// path but never renamed over it by a crashed save, without removing
// anything. Backs both the erase sweep and post-sweep verification so the
// match rule has one definition.
func ListCrashTemps(path string) ([]string, error) {
	dir := filepath.Dir(path)
	prefix := "." + filepath.Base(path) + ".tmp-"
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ddns: inspect ownership-state directory for %s: %w", path, err)
	}
	var out []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			out = append(out, filepath.Join(dir, entry.Name()))
		}
	}
	return out, nil
}

// sweepCrashTemps removes crash-leaked fsatomic write temps (".<base>.tmp-*")
// staged for path but never renamed over it by a crashed save. Scoped to
// this store's base name so another writer's temps in the shared directory
// are untouched. A symlinked temp fails closed for operator inspection.
func sweepCrashTemps(path string) error {
	temps, err := ListCrashTemps(path)
	if err != nil {
		return err
	}
	var errs []error
	for _, full := range temps {
		info, err := os.Lstat(full)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("ddns: inspect crash temp %s: %w", full, err))
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			errs = append(errs, fmt.Errorf("ddns: crash temp %s is a symlink; NOT erasing it", full))
			continue
		}
		if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("ddns: remove crash temp %s: %w", full, err))
		}
	}
	return errors.Join(errs...)
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
