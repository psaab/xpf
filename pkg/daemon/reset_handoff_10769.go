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
// clean. A canonical aliasing reserved reset-gate/identity state is never
// unlinked (unlinking it would delete a gate or identity file, the
// original bypass), but the sweep FAILS CLOSED: exact-shape temps beside
// it are still swept, then an error naming the reserved alias fails the
// wipe and keeps the handoff dirty. Recovery is operator-side (in-band
// commit is refused while dirty): verify the reserved file holds its
// correct contents with no helper temps beside it, delete
// /etc/xpf/.reset-handoff, commit a non-reserved system dataplane
// state-file, and rerun the reset (the rerun records the fixed path);
// then reboot as the clean flag requires.
// Symlinked or hardlinked canonicals fail closed before unlinking
// (FactoryResetHardlinkError with the inode scan), retry-persistent.
func sweepHelperStateVerified(path string) error {
	// Reserved alias FIRST: a smuggled config named a gate or identity
	// file. The missing-parent fast path below must not report clean
	// over it — the daemon post-verify flips the handoff clean on a
	// nil sweep alone, so the reserved failure surfaces here even
	// when there is no directory to sweep beside it. Never unlink the
	// reserved file; the exact-shape temps beside it are still swept
	// below when the parent exists.
	skipCanonical := config.HelperStatePathTouchesReserved(path)
	if skipCanonical {
		slog.Warn("reset handoff: helper path aliases reserved state; skipping canonical removal, sweeping temps only", "path", path)
	}
	var errs []error
	if skipCanonical {
		errs = append(errs, fmt.Errorf("reset handoff: helper state path %s aliases reserved reset-gate/identity state and was NOT erased (the reserved file was left untouched); recovery: verify that file holds its correct contents with no helper temps beside it, delete /etc/xpf/.reset-handoff, commit a non-reserved system dataplane state-file, and rerun the reset", path))
	}
	// A missing state directory means no helper state was ever written
	// here: nothing to remove, verify, or sync. A reserved alias still
	// fails via the error above (joined, not nil).
	if _, err := os.Lstat(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
		return errors.Join(errs...)
	}
	var canonicalErr error
	if !skipCanonical {
		info, lerr := os.Lstat(path)
		switch {
		case lerr == nil && info.Mode()&os.ModeSymlink != 0:
			canonicalErr = fmt.Errorf("refusing to sweep symlinked helper state %s: link target is out of erase scope", path)
		case lerr != nil && !os.IsNotExist(lerr):
			canonicalErr = fmt.Errorf("inspect helper state %s: %w", path, lerr)
		case lerr == nil:
			hardlinks, herr := configstore.CollectHardlinkedFiles(path, "")
			switch {
			case herr != nil:
				canonicalErr = fmt.Errorf("inspect hard links for helper state %s: %w", path, herr)
			case len(hardlinks) != 0:
				canonicalErr = fmt.Errorf("refusing to erase hard-linked helper state %s: %w", path, &configstore.FactoryResetHardlinkError{Paths: hardlinks})
			default:
				if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
					canonicalErr = fmt.Errorf("remove helper state file %s: %w", path, rerr)
				}
			}
		}
		if canonicalErr != nil {
			errs = append(errs, canonicalErr)
		}
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
	if !skipCanonical && canonicalErr == nil {
		if _, err := os.Lstat(path); err == nil {
			errs = append(errs, fmt.Errorf("helper state %s still present after sweep", path))
		} else if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("inspect helper state %s: %w", path, err))
		}
	}
	if dead, live, verr := dpuserspace.ListStaleStateTempsIncludingLegacy(path); verr != nil {
		errs = append(errs, verr)
	} else if len(dead) != 0 || len(live) != 0 {
		errs = append(errs, fmt.Errorf("helper state temps remain for %s: dead=%v live=%v", path, dead, live))
	}
	return errors.Join(errs...)
}

// legacyHelperPathRecovery tells the operator how to recover from a
// pathless handoff flag. Every NORMAL-path writer records a path (the
// flag file itself is new in this PR); only the concurrent-shutdown
// race can persist a pathless flag - a shutdown drain timeout while a
// wipe holds applySem, with a helper-sweep failure landing before
// completion records PENDING, takes the shutdown branch's mark-if-absent
// with no flag to preserve a path from. Anything else pathless is
// hand-crafted or corrupt input. Boot repair never infers from the
// default path or the new-tenant config; the operator verifies residue
// manually (default plus any formerly-custom helper state paths),
// removes it, then deletes the flag to reopen provisioning.
const legacyHelperPathRecovery = "reset handoff flag records no helper path (normal reset writers record one; only a concurrent-shutdown mark records none): " +
	"manually verify no helper state remains at the default or any formerly-custom state-file path, " +
	"remove any residue found, then delete the flag file to reopen provisioning"

// verifyHelperStateErased checks the helper residue class without removing
// anything: the state file plus dead/live temp siblings (legacy included).
// A reserved canonical FAILS verification: the sweep never unlinks gates
// or identity, so erasure of that class is unprovable and the handoff
// must stay dirty until the operator verifies the reserved file, deletes
// the flag file, commits a non-reserved state-file, and reruns the
// reset (in-band commit is refused while dirty). Temp siblings are
// still checked and joined below.
func verifyHelperStateErased(path string) error {
	var errs []error
	if config.HelperStatePathTouchesReserved(path) {
		errs = append(errs, fmt.Errorf("helper state path %s aliases reserved reset-gate/identity state: helper-state erasure cannot be verified (the reserved file is never unlinked); recovery: verify that file holds its correct contents with no helper temps beside it, delete /etc/xpf/.reset-handoff, commit a non-reserved system dataplane state-file, and rerun the reset", path))
	} else if _, err := os.Lstat(path); err == nil {
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

// verifyAllResetResidue returns the per-class residue errors (nil per clean
// class): helper state at helperFile, Kea leases, DDNS/IPsec temps.
func verifyAllResetResidue(helperFile string) (helperErr, keaErr, tempsErr error) {
	helperErr = verifyHelperStateErased(helperFile)
	keaErr = verifyKeaLeasesErasedForReset()
	tempsErr = verifyStateTempsErasedForReset()
	return helperErr, keaErr, tempsErr
}

// repairAllResetResidue runs every class repair (all idempotent). Repair
// errors join the caller's verdict alongside the post-repair verification:
// a repair can fail durability (sync) while the residue is already absent.
func repairAllResetResidue(helperFile string) (helperErr, keaErr, tempsErr error) {
	helperErr = sweepHelperStateVerified(helperFile)
	keaErr = repairHandoffKea()
	tempsErr = repairHandoffTemps()
	return helperErr, keaErr, tempsErr
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
// dataplane (and helper) starts. Clean re-verifies every residue class
// before the reboot gate may open (a crash between verification and the
// reboot — the shutdown helper's final write, a fence escaper — can
// strand residue under a clean claim); same boot keeps the reboot
// requirement; dirty repairs the recorded residue class while no live
// writer exists yet, then verifies EVERY class before the flag may
// downgrade (verified repair downgrades to the plain reboot requirement,
// or clears outright post-reboot). Unrepaired residue re-marks the flag
// dirty, never clears. A flag with no recorded helper path is
// unverifiable (only the concurrent-shutdown race or hand-crafted input
// produces one) and fails closed with recovery instructions rather than
// inferring a path. Never fails boot:
// enforcement happens at provisioning time, and bricking boot on a flag
// read would strand remote boxes.
func (d *Daemon) reconcileResetHandoffAtBoot() {
	bootID, dirty, helperPath, present, err := configstore.ReadResetHandoff()
	if err != nil {
		slog.Warn("reset handoff: cannot read flag; provisioning gate stays fail-closed", "err", err)
		return
	}
	if !present {
		return
	}
	if helperPath == "" {
		// Pathless flags come only from the concurrent-shutdown race
		// (shutdown-branch mark landing before completion records
		// PENDING) or from hand-crafted/corrupt input: every
		// normal-path writer records a path. Never
		// infer from the default path or the new-tenant config: the
		// gate stays shut with recovery instructions.
		slog.Error("reset handoff: pathless flag cannot be verified; provisioning stays refused", "reason", dirty)
		if merr := configstore.MarkResetHandoffDirty(legacyHelperPathRecovery); merr != nil {
			slog.Warn("reset handoff: cannot mark pathless flag dirty", "err", merr)
		}
		return
	}
	current, cerr := configstore.CurrentBootID()
	if cerr != nil {
		slog.Warn("reset handoff: cannot read boot id; leaving flag for the provisioning gate", "err", cerr)
		return
	}
	helperFile := helperPath
	if dirty == "" {
		helperErr, keaErr, tempsErr := verifyAllResetResidue(helperFile)
		if helperErr != nil || keaErr != nil || tempsErr != nil {
			slog.Warn("reset handoff: clean flag but residue present; attempting repair before refusing",
				"helperErr", helperErr, "keaErr", keaErr, "tempsErr", tempsErr)
			rHelper, rKea, rTemps := repairAllResetResidue(helperFile)
			vHelper, vKea, vTemps := verifyAllResetResidue(helperFile)
			helperErr = errors.Join(rHelper, vHelper)
			keaErr = errors.Join(rKea, vKea)
			tempsErr = errors.Join(rTemps, vTemps)
		}
		if helperErr != nil || keaErr != nil || tempsErr != nil {
			reason := handoffFailureReason(helperErr, keaErr, tempsErr)
			slog.Error("reset handoff: clean flag with unrepaired residue; re-marking dirty, provisioning refused",
				"repair", reason)
			if merr := configstore.MarkResetHandoffDirty(reason); merr != nil {
				// Accepted double-fault residual: a TRANSIENT write failure
				// here leaves the clean flag clearable post-reboot. Requires
				// clean+residue (itself crash/hand-craft/plant) AND a timed
				// I/O blip; persistent failure stays fail-closed (the later
				// Clear fails too). Same class as bind-mount/#9013.
				slog.Warn("reset handoff: cannot re-mark failed repair", "err", merr)
			}
			return
		}
		if bootID != current {
			if cerr := configstore.ClearResetHandoff(); cerr != nil {
				slog.Warn("reset handoff: cannot clear converged flag", "err", cerr)
				return
			}
			slog.Info("reset handoff: reboot observed, N+1 provisioning open")
		}
		return
	}
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
	vHelper, vKea, vTemps := verifyAllResetResidue(helperFile)
	helperErr = errors.Join(helperErr, vHelper)
	keaErr = errors.Join(keaErr, vKea)
	tempsErr = errors.Join(tempsErr, vTemps)
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
