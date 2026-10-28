package daemon

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// CloseKernelTransitForCleanup closes and verifies both transit legs before the
// standalone xpfd cleanup command destroys pinned XDP links. Cleanup runs in a
// short-lived process after the daemon has exited, so no daemon tick can observe
// the final link destruction. Failure is returned so callers MUST NOT destroy
// the pins while forwarding may still be open.
func CloseKernelTransitForCleanup() error {
	var errs []error
	if nftInstaller != nil {
		if err := nftInstaller.InstallTransitBarrier(); err != nil {
			errs = append(errs, fmt.Errorf("install transit barrier: %w", err))
		}
	}
	for _, path := range transitForwardSysctlPaths() {
		if _, err := fsatomic.WriteKernelKnobVerified(path, "0"); err != nil {
			errs = append(errs, fmt.Errorf("write/verify %s=0: %w", path, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		slog.Error("cleanup: could not verify kernel transit closure; pinned XDP state was not removed", "err", err)
		return err
	}
	slog.Info("cleanup: kernel transit closed and verified before pinned XDP state removal")
	return nil
}
