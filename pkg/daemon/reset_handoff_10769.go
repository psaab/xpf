package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// sweepHelperStateVerified removes the helper state file at path plus
// dead-writer temp siblings (including exact pre-#2957 legacy orphans:
// this runs post-stop/pre-start with no live writer, so they are verified
// orphans), syncs the parent, and verifies absence. Live writers' temps,
// removal/durability failures, or anything still present afterwards is an
// error: the caller marks the reset handoff dirty rather than reporting
// clean.
func sweepHelperStateVerified(path string) error {
	// A missing state directory means no helper state was ever written
	// here: nothing to remove, verify, or sync.
	if _, err := os.Lstat(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var errs []error
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove helper state file %s: %w", path, err))
	}
	live, serr := dpuserspace.SweepStaleStateTempsIncludingLegacy(path)
	if serr != nil {
		errs = append(errs, serr)
	}
	if len(live) != 0 {
		errs = append(errs, fmt.Errorf("live helper writer temps present for %s: %v", path, live))
	}
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil {
		errs = append(errs, fmt.Errorf("sync helper state directory %s: %w", filepath.Dir(path), err))
	}
	if _, err := os.Lstat(path); err == nil {
		errs = append(errs, fmt.Errorf("helper state %s still present after sweep", path))
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("inspect helper state %s: %w", path, err))
	}
	if dead, live, verr := dpuserspace.ListStaleStateTempsIncludingLegacy(path); verr != nil {
		errs = append(errs, verr)
	} else if len(dead) != 0 || len(live) != 0 {
		errs = append(errs, fmt.Errorf("helper state temps remain for %s: dead=%v live=%v", path, dead, live))
	}
	return errors.Join(errs...)
}

// reconcileResetHandoffAtBoot converges the reset handoff flag before the
// dataplane (and helper) starts. Clean + rebooted clears silently; same
// boot keeps the reboot requirement; dirty attempts a repair sweep while
// no live writer exists yet (verified repair downgrades to the plain
// reboot requirement, or clears outright post-reboot). Never fails boot:
// enforcement happens at provisioning time, and bricking boot on a flag
// read would strand remote boxes.
func (d *Daemon) reconcileResetHandoffAtBoot() {
	bootID, dirty, present, err := configstore.ReadResetHandoff()
	if err != nil {
		slog.Warn("reset handoff: cannot read flag; provisioning gate stays fail-closed", "err", err)
		return
	}
	if !present {
		return
	}
	current, cerr := configstore.CurrentBootID()
	if cerr != nil {
		slog.Warn("reset handoff: cannot read boot id; leaving flag for the provisioning gate", "err", cerr)
		return
	}
	if dirty == "" {
		if bootID != current {
			if cerr := configstore.ClearResetHandoff(); cerr != nil {
				slog.Warn("reset handoff: cannot clear converged flag", "err", cerr)
				return
			}
			slog.Info("reset handoff: reboot observed, N+1 provisioning open")
		}
		return
	}
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	if rerr := sweepHelperStateVerified(dpuserspace.StateFilePathForConfig(cfg)); rerr != nil {
		slog.Error("reset handoff: dirty flag repair failed; provisioning stays refused until a clean reset",
			"reason", dirty, "err", rerr)
		return
	}
	if bootID != current {
		if cerr := configstore.ClearResetHandoff(); cerr != nil {
			slog.Warn("reset handoff: cannot clear repaired flag", "err", cerr)
			return
		}
		slog.Info("reset handoff: dirty residue repaired post-reboot, N+1 provisioning open")
		return
	}
	if werr := configstore.WriteResetHandoff(current, ""); werr != nil {
		slog.Warn("reset handoff: cannot rewrite repaired flag", "err", werr)
		return
	}
	slog.Info("reset handoff: dirty residue repaired, reboot still required")
}
