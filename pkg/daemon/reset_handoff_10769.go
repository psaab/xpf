package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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

// effectiveHelperStatePath resolves the helper state file boot repair must
// sweep: the pre-wipe path recorded in the flag. Re-deriving from the
// current config is wrong post-wipe — the config is erased, so derivation
// yields the default while the residue sits at the prior custom path. The
// derived path is only a fallback for flags that predate path recording.
func effectiveHelperStatePath(recorded string, cfg *config.Config) string {
	if recorded != "" {
		return recorded
	}
	return dpuserspace.StateFilePathForConfig(cfg)
}

// verifyHelperStateErased checks the helper residue class without removing
// anything: the state file plus dead/live temp siblings (legacy included).
func verifyHelperStateErased(path string) error {
	var errs []error
	if _, err := os.Lstat(path); err == nil {
		errs = append(errs, fmt.Errorf("helper state %s present", path))
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("inspect helper state %s: %w", path, err))
	}
	if dead, live, verr := dpuserspace.ListStaleStateTempsIncludingLegacy(path); verr != nil {
		errs = append(errs, verr)
	} else if len(dead) != 0 || len(live) != 0 {
		errs = append(errs, fmt.Errorf("helper state temps present for %s: dead=%v live=%v", path, dead, live))
	}
	return errors.Join(errs...)
}

// handoffRepairClasses maps a dirty reason to the residue classes it
// records. Unknown or unprefixed reasons (stop failures, the pending
// sentinel, pre-class flags) repair every class: a later failure
// overwrites an earlier reason, so the recorded class is a hint and only
// universal verification grounds clearing.
func handoffRepairClasses(dirty string) (helper, kea, temps bool) {
	switch {
	case strings.HasPrefix(dirty, configstore.ResetHandoffReasonHelper+":"):
		return true, false, false
	case strings.HasPrefix(dirty, configstore.ResetHandoffReasonKea+":"):
		return false, true, false
	case strings.HasPrefix(dirty, configstore.ResetHandoffReasonTemps+":"):
		return false, false, true
	default:
		return true, true, true
	}
}

// repairHandoffKea re-runs the idempotent Kea lease erasure and re-verifies.
func repairHandoffKea() error {
	if err := eraseKeaLeasesForReset(); err != nil {
		return err
	}
	return verifyKeaLeasesErasedForReset()
}

// repairHandoffTemps re-runs the idempotent DDNS/IPsec state erasures and
// re-verifies. A reappeared RECORD (not just a temp) fails loudly: that is
// a fence breach, not a repairable race.
func repairHandoffTemps() error {
	if err := eraseStateTempsForReset(); err != nil {
		return err
	}
	return verifyStateTempsErasedForReset()
}

// handoffFailureReason tags per-class repair/verify failures for re-marking.
// A single failing class keeps its dispatch prefix; multiple failures use
// an unprefixed aggregate so the next repair covers every class.
func handoffFailureReason(helperErr, keaErr, tempsErr error) string {
	type classErr struct {
		class string
		err   error
	}
	var failed []classErr
	for _, ce := range []classErr{
		{configstore.ResetHandoffReasonHelper, helperErr},
		{configstore.ResetHandoffReasonKea, keaErr},
		{configstore.ResetHandoffReasonTemps, tempsErr},
	} {
		if ce.err != nil {
			failed = append(failed, ce)
		}
	}
	if len(failed) == 1 {
		return failed[0].class + ": " + failed[0].err.Error()
	}
	var parts []string
	for _, ce := range failed {
		parts = append(parts, ce.class+": "+ce.err.Error())
	}
	return "multiple residue classes failed repair: " + strings.Join(parts, "; ")
}

// reconcileResetHandoffAtBoot converges the reset handoff flag before the
// dataplane (and helper) starts. Clean + rebooted clears silently; same
// boot keeps the reboot requirement; dirty repairs the recorded residue
// class while no live writer exists yet, then verifies EVERY class before
// the flag may downgrade (verified repair downgrades to the plain reboot
// requirement, or clears outright post-reboot). Unrepaired residue
// re-marks the flag dirty, never clears. Never fails boot: enforcement
// happens at provisioning time, and bricking boot on a flag read would
// strand remote boxes.
func (d *Daemon) reconcileResetHandoffAtBoot() {
	bootID, dirty, helperPath, present, err := configstore.ReadResetHandoff()
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
	helperFile := effectiveHelperStatePath(helperPath, cfg)
	doHelper, doKea, doTemps := handoffRepairClasses(dirty)
	var helperErr, keaErr, tempsErr error
	if doHelper {
		helperErr = sweepHelperStateVerified(helperFile)
	}
	if doKea {
		keaErr = repairHandoffKea()
	}
	if doTemps {
		tempsErr = repairHandoffTemps()
	}
	// Verify every class regardless of dispatch: the recorded reason may
	// under-report (a later Mark overwrites an earlier one).
	if verr := verifyHelperStateErased(helperFile); verr != nil {
		helperErr = errors.Join(helperErr, verr)
	}
	if verr := verifyKeaLeasesErasedForReset(); verr != nil {
		keaErr = errors.Join(keaErr, verr)
	}
	if verr := verifyStateTempsErasedForReset(); verr != nil {
		tempsErr = errors.Join(tempsErr, verr)
	}
	if helperErr != nil || keaErr != nil || tempsErr != nil {
		reason := handoffFailureReason(helperErr, keaErr, tempsErr)
		slog.Error("reset handoff: dirty flag repair failed; provisioning stays refused until a clean reset",
			"reason", dirty, "repair", reason)
		if merr := configstore.MarkResetHandoffDirty(reason); merr != nil {
			slog.Warn("reset handoff: cannot re-mark failed repair", "err", merr)
		}
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
	if werr := configstore.WriteResetHandoff(current, "", helperPath); werr != nil {
		slog.Warn("reset handoff: cannot rewrite repaired flag", "err", werr)
		return
	}
	slog.Info("reset handoff: dirty residue repaired, reboot still required")
}
