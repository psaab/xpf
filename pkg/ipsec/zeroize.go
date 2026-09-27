package ipsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// CheckConnStateEmpty proves the durable connection/deletion-debt store has no
// remaining work before factory reset erases the credentials it may need.
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
	if len(st.Loaded) != 0 || len(st.Pending) != 0 || len(st.PendingChanged) != 0 || len(st.Fingerprints) != 0 {
		return fmt.Errorf("ipsec: connection state %s still contains loaded connections or teardown debt", path)
	}
	return nil
}

// EraseConnStateIfEmpty removes only a trusted-empty state file after its
// manager has successfully cleared the loaded connections and termination debt.
func EraseConnStateIfEmpty(path string) error {
	if err := CheckConnStateEmpty(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ipsec: remove empty connection state %s: %w", path, err)
	}
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ipsec: sync connection-state directory for %s: %w", path, err)
	}
	return nil
}
