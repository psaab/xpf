package ipsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// CheckConnStateEmpty proves the durable connection/deletion-debt store has no
// remaining teardown, staged-candidate, or deferred-start work before factory
// reset erases the credentials it may need.
func CheckConnStateEmpty(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("ipsec: inspect connection state %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("ipsec: connection state %s is not a regular file", path)
	}
	st, err := loadConnState(path)
	if err != nil {
		return fmt.Errorf("ipsec: cannot prove connection state %s is empty: %w", path, err)
	}
	if len(st.Loaded) != 0 || len(st.Pending) != 0 || len(st.PendingChanged) != 0 ||
		len(st.PendingReinitiate) != 0 || len(st.PendingCandidate) != 0 || len(st.Fingerprints) != 0 {
		return fmt.Errorf("ipsec: connection state %s still contains loaded connections or pending IPsec work", path)
	}
	return nil
}

// EraseConnStateIfEmpty removes only a trusted-empty state file after its
// manager has successfully cleared loaded connections and termination or
// deferred-initiation debt.
// Crash-leaked fsatomic write temps for the store are removed with it: every
// durable save stages full state JSON in a .<base>.tmp-* file first, so a
// temp orphaned by a crash holds tenant connection names a canonical-only
// erase would hand to the next tenant. Hardlinked canonicals and temps are
// refused before unlinking (FactoryResetHardlinkError with the inode
// scan), so a retry cannot succeed over bytes a sibling holds.
func EraseConnStateIfEmpty(path string) error {
	if err := CheckConnStateEmpty(path); err != nil {
		return err
	}
	if err := configstore.EraseFileForReset(path); err != nil {
		return fmt.Errorf("ipsec: %w", err)
	}
	if err := sweepCrashTemps(path); err != nil {
		return err
	}
	if temps, err := ListCrashTemps(path); err != nil {
		return err
	} else if len(temps) != 0 {
		return fmt.Errorf("ipsec: crash temps reappeared for %s after sweep: %v", path, temps)
	}
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ipsec: sync connection-state directory for %s: %w", path, err)
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
		return nil, fmt.Errorf("ipsec: inspect connection-state directory for %s: %w", path, err)
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
	if err := configstore.SweepCrashTemps(func() ([]string, error) { return ListCrashTemps(path) }); err != nil {
		return fmt.Errorf("ipsec: %w", err)
	}
	return nil
}
