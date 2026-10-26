package upgrade

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// maxPromoteAttempts bounds the number of revert-reboots for a single armed
// candidate. Beyond this, the promotion gate stops requesting reboots and
// leaves the box up (on the firmware-preferred known-good default) so a
// pathological loop (e.g. read-only root that cannot clear the journal) cannot
// brick the node out of operator reach (r1 AGY catastrophic).
const maxPromoteAttempts = 3

// loadKernelJournal reads the persisted kernel-channel journal, or a zero
// journal if none exists.
func (r *KernelRunner) loadKernelJournal() (*KernelJournal, error) {
	data, err := os.ReadFile(r.cfg.JournalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &KernelJournal{State: KernelStateInit}, nil
		}
		return nil, fmt.Errorf("read kernel-upgrade journal: %w", err)
	}
	j := &KernelJournal{}
	if err := json.Unmarshal(data, j); err != nil {
		return nil, fmt.Errorf("parse kernel-upgrade journal: %w", err)
	}
	return j, nil
}

// saveKernelJournal persists j durably (temp+fsync+rename via fsatomic).
func (r *KernelRunner) saveKernelJournal(j *KernelJournal) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal kernel-upgrade journal: %w", err)
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(r.cfg.JournalPath), 0755); err != nil {
		return fmt.Errorf("create kernel journal dir: %w", err)
	}
	if err := fsatomic.WriteFileDurable(r.cfg.JournalPath, data, 0644); err != nil {
		return fmt.Errorf("persist kernel-upgrade journal: %w", err)
	}
	return nil
}

// clearKernelJournal removes the journal on a terminal state.
func (r *KernelRunner) clearKernelJournal() error {
	if err := os.Remove(r.cfg.JournalPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove kernel-upgrade journal: %w", err)
	}
	// Keep "nothing armed" and "no arm record" the SAME statement. The boot
	// gate treats an absent record as a definitive "nothing to promote", so a
	// record surviving a cleared journal would make it refuse on every
	// subsequent ordinary boot (#6601 r6).
	// Same lifetime as the arm record (#6622): a refusal describes a specific
	// armed candidate, so one that outlived its journal would accuse the next
	// boot of a decline that happened to a candidate no longer in flight.
	// Best-effort, and deliberately not fatal: failing to remove a DIAGNOSTIC
	// must not fail the terminal transition that clears the journal.
	_ = r.clearRefusalRecord()
	if err := r.clearArmRecord(); err != nil {
		return err
	}
	return nil
}

func (r *KernelRunner) ktransition(j *KernelJournal, s KernelState) error {
	j.State = s
	r.logf("kernel-upgrade: -> %s (candidate=%s known-good=%s active=%s)",
		s, j.CandidateVersion, j.KnownGoodVersion, j.ActiveSlot)
	return r.saveKernelJournal(j)
}

// UnconfirmedTrial reports whether the CURRENT boot is a genuine candidate
// trial whose journal never reached the verified ARMED state (#16809).
//
// The two-phase arm records ARMING before SetBootNext and ARMED only after a
// positive readback, so ARMING alone is prepared intent. But two paths reach
// a boot with BootNext actually queued while the journal still says ARMING:
// (a) process death between SetBootNext and the ARMED rename, and (b) a
// SetBootNext error after the write landed whose clear could not run (or
// itself failed). On such a boot the firmware booted the candidate WITHOUT
// verify-dataplane or the beacon ever running, yet Promote, the daemon
// election hold and self-recovery all classified ARMING as an ordinary boot.
//
// The discriminator is boot EVIDENCE, not the journal state alone: the
// firmware booted the INACTIVE slot (BootCurrent == entries[InactiveSlot])
// AND the running kernel IS the candidate (uname -r == CandidateVersion).
// Both are required — BootCurrent alone could be a stale slot whose selector
// no longer points at the candidate, and uname -r alone cannot tie the boot
// to the armed slot.
//
// Fail-closed: any read failure (journal, boot entries, BootCurrent, running
// kernel), a missing candidate slot, or an empty candidate version returns
// an ERROR, never a bare "not a trial" — a caller that cannot prove the boot
// is off the candidate must not classify it as an ordinary boot. A journal
// at ARMED (or beyond) is not "unconfirmed": it is the verified trial the
// existing predicates already handle, so it reports (false, nil). Any other
// state, and ARMING with positive non-candidate evidence, reports
// (false, nil).
func (r *KernelRunner) UnconfirmedTrial() (bool, *KernelJournal, error) {
	j, err := r.loadKernelJournal()
	if err != nil {
		return false, nil, err
	}
	if j.State != KernelStateArming {
		return false, j, nil
	}
	if j.CandidateVersion == "" || j.InactiveSlot == "" {
		return false, j, fmt.Errorf("kernel-upgrade: ARMING journal has empty candidate/slot "+
			"(candidate=%q inactive=%q); cannot classify the boot", j.CandidateVersion, j.InactiveSlot)
	}
	sys := r.cfg.Sys
	entries, err := sys.BootEntries()
	if err != nil {
		return false, j, fmt.Errorf("kernel-upgrade: ARMING boot classification: read boot entries: %w", err)
	}
	candID, ok := entries[j.InactiveSlot]
	if !ok {
		return false, j, fmt.Errorf("kernel-upgrade: ARMING boot classification: candidate slot %s "+
			"not in boot entries", j.InactiveSlot)
	}
	cur, err := sys.BootCurrent()
	if err != nil {
		return false, j, fmt.Errorf("kernel-upgrade: ARMING boot classification: read BootCurrent: %w", err)
	}
	if cur != candID {
		return false, j, nil
	}
	running, err := sys.RunningKernel()
	if err != nil {
		return false, j, fmt.Errorf("kernel-upgrade: ARMING boot classification: running kernel: %w", err)
	}
	return running == j.CandidateVersion, j, nil
}

// Arm runs the PRE-REBOOT half of the LANE-1 channel for a candidate kernel
// version: preflight -> install -> arm one-shot -> reboot. On success it does
// NOT return (the host reboots into the candidate); the Promote half then runs
// from the candidate boot. Every phase is journaled so a crash before the
// reboot resumes idempotently.
//
// A pre-assert failure returns ErrKernelChannelUnavailable (the running kernel
// + active slot are untouched). The arm is loop-safe by construction: even if
// the process dies right after SetBootNext, the firmware clears BootNext on the
// next boot, so at worst the candidate is tried once and falls back.
func (r *KernelRunner) Arm(candidateVersion string) error {
	journalPath := r.cfg.JournalPath
	// FIRST, before the candidate is even looked at (#6631). A journal the boot
	// gate does not read makes this arm unpromotable no matter what is armed,
	// so it outranks every per-invocation complaint below: telling an operator
	// their version string is malformed, when the command could not have worked
	// with a perfect one, sends them to fix the wrong thing.
	if err := r.checkArmJournalPromotable(); err != nil {
		return fmt.Errorf("kernel-upgrade arm: %w", err)
	}
	if candidateVersion == "" {
		return fmt.Errorf("kernel-upgrade: candidate version is required")
	}
	// Fail CLOSED on an unsafe candidate segment before ANY mutation (#5452).
	// The version flows raw into a /boot glob + os.RemoveAll, a /lib/modules
	// os.RemoveAll, `apt-get purge linux-image-<ver>`, and the GRUB
	// slot-selector script — so a "*" would glob every dashed /boot file into
	// RemoveAll (arbitrary /boot deletion -> unbootable host), a ".." would
	// traverse the modules delete, and a quote/newline would inject GRUB
	// directives. Reject anything outside the kernel-version charset here so an
	// invalid segment never reaches those sites.
	if err := ValidateKernelSegment("kernel candidate version", candidateVersion); err != nil {
		return fmt.Errorf("kernel-upgrade: %w", err)
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		return err
	}
	if j.State.atLeast(KernelStateArmed) {
		return fmt.Errorf("kernel-upgrade: a candidate is already armed "+
			"(journal state=%s candidate=%s); reboot to trial it or clear %s",
			j.State, j.CandidateVersion, r.cfg.JournalPath)
	}
	// Resume-version guard (r1 Copilot): if a PRIOR Arm() got past PREFLIGHT
	// (so the journal records a candidate) and this call requests a DIFFERENT
	// version, the journaled candidate is authoritative — refuse rather than
	// install version B against a journal that preflighted/installed version A.
	// The operator must clear the journal to switch candidates mid-flight.
	if j.State.atLeast(KernelStatePreflight) && j.CandidateVersion != "" &&
		j.CandidateVersion != candidateVersion {
		return fmt.Errorf("kernel-upgrade: an in-progress run targets candidate %s "+
			"(journal state=%s); refusing to resume with a different candidate %s — "+
			"clear %s to start over", j.CandidateVersion, j.State, candidateVersion, r.cfg.JournalPath)
	}
	candidatePackageVersion := j.CandidatePackageVersion
	if candidatePackageVersion == "" {
		if j.State.atLeast(KernelStateInstalled) {
			candidatePackageVersion, err = r.cfg.Sys.InstalledKernelPackageVersion(candidateVersion)
		} else {
			candidatePackageVersion, err = r.cfg.Sys.CandidateKernelPackageVersion(candidateVersion)
		}
		if err != nil {
			return fmt.Errorf("kernel-upgrade preflight: read Debian package version for candidate %s: %w",
				candidateVersion, err)
		}
	}
	if err := ValidateDebianPackageVersion(candidatePackageVersion); err != nil {
		return fmt.Errorf("kernel-upgrade preflight: candidate %s package version %q is not orderable: %w",
			candidateVersion, candidatePackageVersion, err)
	}
	floor, err := loadHighWaterFloor(r.cfg.KernelFloorPath)
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: read anti-rollback floor: %w", err)
	}
	if err := floor.checkForward("kernel candidate", candidatePackageVersion, "apt"); err != nil {
		return err
	}
	j.CandidatePackageVersion = candidatePackageVersion


	// A FRESH arm of the SAME version a prune-owed record names supersedes
	// that record (#16811): the re-armed trial re-installs and re-tests the
	// candidate, so the deferred "un-promoted candidate" debt is void — if
	// this trial also fails, its own revert writes a fresh record. A record
	// for a DIFFERENT version is preserved: it must never be pruned from
	// here (pruning rewrites a slot selector an in-flight arm may depend
	// on), and the next ordinary boot settles it. FATAL on a read failure,
	// like the stale-marker clear below: an unreadable record means the
	// debt's state is unknown, and arming over it could strand it.
	if !j.State.atLeast(KernelStatePreflight) {
		if rec, rerr := r.readPruneOwed(); rerr != nil {
			return fmt.Errorf("kernel-upgrade arm: read prune-owed record (refusing "+
				"to arm over an unknown prune debt): %w", rerr)
		} else if rec.CandidateVersion == candidateVersion {
			if cerr := r.clearPruneOwed(); cerr != nil {
				return fmt.Errorf("kernel-upgrade arm: clear superseded prune-owed "+
					"record for %s: %w", candidateVersion, cerr)
			}
			r.logf("kernel-upgrade: re-arming %s supersedes its deferred prune; prune-owed record cleared", candidateVersion)
		}
	}

	// Clear any STALE promotion marker from a PRIOR roll BEFORE arming a fresh
	// one (r1 Codex High): otherwise the external orchestrator's post-reboot
	// `promoted==<ver>` check could be satisfied by a previous successful roll
	// to the SAME version, masking a revert of THIS roll. This is FATAL on
	// failure (r2 Codex): if we cannot guarantee the marker is gone, we must NOT
	// arm — proceeding would leave a stale marker that could false-confirm.
	if !j.State.atLeast(KernelStatePreflight) {
		if err := r.cfg.Sys.ClearPromotionMarker(); err != nil {
			return fmt.Errorf("kernel-upgrade arm: clear stale promotion marker (refusing "+
				"to arm with a possibly-stale marker): %w", err)
		}
	}

	// ---- PREFLIGHT (fail-closed; no mutation) ----
	if !j.State.atLeast(KernelStatePreflight) {
		if err := r.preflight(j, candidateVersion); err != nil {
			return err
		}
	}

	// ---- INSTALL (candidate kernel into /boot; default must not move) ----
	if !j.State.atLeast(KernelStateInstalled) {
		if err := r.installCandidate(j, candidateVersion); err != nil {
			return err
		}
	}

	// ---- ARM (point inactive slot selector + BootNext + watchdog) ----
	watchdogArmed, err := r.armCandidate(j)
	if err != nil {
		return err
	}

	// ---- REBOOT into the candidate (one-shot, firmware-cleared) ----
	r.logf("kernel-upgrade: armed candidate %s in slot %s; rebooting (one-shot)",
		j.CandidateVersion, j.InactiveSlot)
	if err := r.cfg.Sys.Reboot(); err != nil {
		armedBootID := j.BootID
		j.BootID = ""
		backstepErr := r.ktransition(j, KernelStateArming)
		if backstepErr != nil && !isPostRenameJournalError(backstepErr) {
			j.State = KernelStateArmed
			j.BootID = armedBootID
			watchdogStatus := "the watchdog was not confirmed armed, so do not rely on an automatic reset"
			if watchdogArmed {
				watchdogStatus = "the watchdog is armed and will reset the host into the candidate trial within the watchdog timeout"
			}
			return fmt.Errorf("%w; journal step back to ARMING failed (%w): "+
				"the journal remains ARMED with BootID %s and BootNext %s; %s. "+
				"Clear BootNext and resolve the journal before rebooting",
				err, backstepErr, armedBootID, armedBootID, watchdogStatus)
		}
		cause := err
		if backstepErr != nil {
			cause = fmt.Errorf("%w; the ARMING journal rename landed but its directory sync failed (%w)",
				err, backstepErr)
		}

		// ARMING is now visible. Clear BootNext before disarming the watchdog.
		// If clearing fails, restore the verified ARMED trial instead.
		bootNextCleared, cause := disarmAfterFailedReboot(r.cfg.Sys, cause)
		if !bootNextCleared {
			j.BootID = armedBootID
			restoreErr := r.ktransition(j, KernelStateArmed)
			if restoreErr != nil && !isPostRenameJournalError(restoreErr) {
				j.State = KernelStateArming
				j.BootID = ""
				disarmErr := r.cfg.Sys.DisarmWatchdog()
				recordErr := clearArmRecordForJournal(journalPath)
				if disarmErr != nil {
					watchdogStatus := "watchdog arming was not confirmed, so an automatic watchdog reset is not guaranteed"
					if watchdogArmed {
						watchdogStatus = "the watchdog may still be armed and will force a reboot into the candidate within the watchdog timeout"
					}
					branchErr := fmt.Errorf("%w; could not restore the ARMED journal (%w): "+
						"BootNext %s may still be queued and the journal remains ARMING; "+
						"watchdog disarm also failed (%w); %s. Clear BootNext before then: "+
						"efibootmgr --delete-bootnext",
						cause, restoreErr, armedBootID, disarmErr, watchdogStatus)
					if recordErr != nil {
						return fmt.Errorf("%w; stale arm record could not be removed: %w",
							branchErr, recordErr)
					}
					return branchErr
				}
				branchErr := fmt.Errorf("%w; could not restore the ARMED journal (%w): "+
					"BootNext %s may still be queued and the journal remains ARMING; "+
					"the watchdog was disarmed, so clear BootNext before rebooting: "+
					"efibootmgr --delete-bootnext",
					cause, restoreErr, armedBootID)
				if recordErr != nil {
					return fmt.Errorf("%w; stale arm record could not be removed: %w",
						branchErr, recordErr)
				}
				return branchErr
			}
			if restoreErr != nil {
				cause = fmt.Errorf("%w; the ARMED journal rename landed but its directory sync failed (%w)",
					cause, restoreErr)
			}
			watchdogStatus := "the watchdog was not confirmed armed, so do not rely on an automatic reset"
			if watchdogArmed {
				watchdogStatus = "the watchdog remains armed and will reset the host into the candidate trial within the watchdog timeout"
			}
			return fmt.Errorf("%w; journal remains ARMED with BootID %s and the queued BootNext; %s. "+
				"Clear BootNext before rebooting: efibootmgr --delete-bootnext",
				cause, armedBootID, watchdogStatus)
		}
		if recordErr := clearArmRecordForJournal(journalPath); recordErr != nil {
			return fmt.Errorf("%w; BootNext was cleared and watchdog disarm was attempted, "+
				"but the stale arm record could not be removed: %w", cause, recordErr)
		}
		return cause
	}
	return nil
}

func (r *KernelRunner) preflight(j *KernelJournal, candidateVersion string) error {
	sys := r.cfg.Sys

	if !sys.IsUEFI() {
		return fmt.Errorf("%w: not booted via UEFI (A4 needs efibootmgr/BootNext)", ErrKernelChannelUnavailable)
	}
	if !sys.EfibootmgrOK() {
		return fmt.Errorf("%w: efibootmgr cannot read NVRAM", ErrKernelChannelUnavailable)
	}

	entries, err := sys.BootEntries()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: read boot entries: %w", err)
	}
	aID, okA := entries[SlotA]
	bID, okB := entries[SlotB]
	if !okA || !okB {
		return fmt.Errorf("%w: A/B slots not both registered (found A=%v B=%v) — "+
			"the first-boot registration oneshot must run first", ErrKernelChannelUnavailable, okA, okB)
	}

	order, err := sys.BootOrder()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: read BootOrder: %w", err)
	}
	if len(order) == 0 {
		return fmt.Errorf("%w: empty BootOrder", ErrKernelChannelUnavailable)
	}
	// The active slot is whichever of A/B is first in BootOrder.
	var activeSlot, inactiveSlot string
	switch order[0] {
	case aID:
		activeSlot, inactiveSlot = SlotA, SlotB
	case bID:
		activeSlot, inactiveSlot = SlotB, SlotA
	default:
		return fmt.Errorf("%w: BootOrder front (%s) is neither A/B slot (A=%s B=%s) — "+
			"a non-xpf default is registered; refusing to arm", ErrKernelChannelUnavailable, order[0], aID, bID)
	}

	submenuOK, err := sys.GrubSubmenuDisabled()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: grub submenu check: %w", err)
	}
	if !submenuOK {
		return fmt.Errorf("%w: GRUB_DISABLE_SUBMENU not set or /etc/grub.d/09_xpf missing", ErrKernelChannelUnavailable)
	}

	wdPresent, wdPersistent := sys.WatchdogStatus()
	if r.cfg.StrictWatchdog && !(wdPresent && wdPersistent) {
		return fmt.Errorf("%w: strict-watchdog policy (D1) requires a verified-persistent "+
			"watchdog (present=%v persistent=%v)", ErrKernelChannelUnavailable, wdPresent, wdPersistent)
	}
	if !wdPersistent {
		r.logf("kernel-upgrade: WARNING (Path-D2): no verified-persistent watchdog "+
			"(present=%v); the BootNext one-shot still closes the boot-LOOP, but an "+
			"EARLY-boot hang would need one external/console reset to recover", wdPresent)
	}

	if err := r.assertFree(r.cfg.BootMountpoint, r.cfg.BootFreeMargin, "/boot"); err != nil {
		return err
	}
	if err := r.assertFree(r.cfg.ESPMountpoint, r.cfg.ESPFreeMargin, "ESP"); err != nil {
		return err
	}

	known, err := sys.RunningKernel()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: uname -r: %w", err)
	}
	if known == candidateVersion {
		return fmt.Errorf("kernel-upgrade preflight: candidate %s is already the running kernel", candidateVersion)
	}

	// Fail BEFORE any mutation if the installed kernel set is not fully
	// held (#16812): previously such a box installed the candidate, ran
	// update-initramfs/update-grub, and only then failed the fatal rehold,
	// leaving a PREFLIGHT journal that blocks any other version. The fake
	// defaults held=true, so existing preflight tests are unaffected; a
	// KernelHeld error (e.g. apt-mark unreadable) likewise aborts here
	// rather than after the install window.
	held, err := sys.KernelHeld()
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: check kernel hold: %w", err)
	}
	if !held {
		return fmt.Errorf("%w: installed linux-* kernel packages are not all held (apt-mark showhold) — "+
			"hold them before arming a kernel roll", ErrKernelChannelUnavailable)
	}

	j.CandidateVersion = candidateVersion
	j.KnownGoodVersion = known
	j.ActiveSlot = activeSlot
	j.InactiveSlot = inactiveSlot
	j.StartedAt = sys.Now()
	return r.ktransition(j, KernelStatePreflight)
}

func (r *KernelRunner) assertFree(path string, margin uint64, label string) error {
	free, err := r.cfg.Sys.FreeBytes(path)
	if err != nil {
		return fmt.Errorf("kernel-upgrade preflight: free space on %s (%s): %w", path, label, err)
	}
	if free < margin {
		return fmt.Errorf("%w: insufficient %s space (%d < required %d bytes) — "+
			"prune before install", ErrKernelChannelUnavailable, label, free, margin)
	}
	return nil
}

func (r *KernelRunner) installCandidate(j *KernelJournal, candidateVersion string) error {
	sys := r.cfg.Sys

	defaultBefore, err := sys.DefaultBootEntry()
	if err != nil {
		return fmt.Errorf("kernel-upgrade install: read default boot entry: %w", err)
	}

	unameR, err := sys.InstallCandidateKernel(candidateVersion)
	if err != nil {
		return fmt.Errorf("kernel-upgrade install: %w", err)
	}
	// The candidate's actual uname -r is authoritative for the selector +
	// the promotion gate; record it (it may differ from the apt version arg).
	j.CandidateVersion = unameR

	// Re-assert the dpkg postinst's update-grub did NOT move the permanent
	// default (plan risk #2): the known-good slot must still be the default.
	defaultAfter, err := sys.DefaultBootEntry()
	if err != nil {
		return fmt.Errorf("kernel-upgrade install: re-read default boot entry: %w", err)
	}
	if defaultAfter != defaultBefore {
		return fmt.Errorf("kernel-upgrade install: candidate install MOVED the permanent "+
			"default (%s -> %s); aborting to avoid an unverified default boot", defaultBefore, defaultAfter)
	}

	// Re-assert the kernel set is held again after the install window.
	held, err := sys.KernelHeld()
	if err != nil {
		return fmt.Errorf("kernel-upgrade install: re-check kernel hold: %w", err)
	}
	if !held {
		return fmt.Errorf("kernel-upgrade install: kernel set is NOT held after install — rehold failed")
	}

	return r.ktransition(j, KernelStateInstalled)
}

// armCandidate returns whether ArmWatchdog succeeded; a best-effort D2 failure
// can continue arming but does not justify promising a watchdog-driven reset.
func (r *KernelRunner) armCandidate(j *KernelJournal) (bool, error) {
	sys := r.cfg.Sys

	// Point the INACTIVE slot's selector at the candidate (atomic ESP write).
	if err := sys.WriteSlotSelector(j.InactiveSlot, j.CandidateVersion); err != nil {
		return false, fmt.Errorf("kernel-upgrade arm: write %s selector: %w", j.InactiveSlot, err)
	}
	// Verify the selector reads back the candidate before we arm BootNext.
	got, err := sys.ReadSlotSelector(j.InactiveSlot)
	if err != nil {
		return false, fmt.Errorf("kernel-upgrade arm: read back %s selector: %w", j.InactiveSlot, err)
	}
	if got != j.CandidateVersion {
		return false, fmt.Errorf("kernel-upgrade arm: %s selector reads %q, expected candidate %q",
			j.InactiveSlot, got, j.CandidateVersion)
	}

	entries, err := sys.BootEntries()
	if err != nil {
		return false, fmt.Errorf("kernel-upgrade arm: read boot entries: %w", err)
	}
	inactiveID, ok := entries[j.InactiveSlot]
	if !ok {
		return false, fmt.Errorf("kernel-upgrade arm: inactive slot %s not registered", j.InactiveSlot)
	}

	watchdogArmed := false
	if err := sys.ArmWatchdog(); err != nil {
		if r.cfg.StrictWatchdog {
			// D1 (strict): a strict deployment REQUIRES a functioning watchdog.
			// The preflight only checked the BAKED persistence flag
			// (WatchdogStatus); the actual arm failing HERE means we would reboot
			// into the candidate with no functioning watchdog, silently defeating
			// strict mode's guarantee (#4872 B). Abort the arm — do NOT set
			// BootNext, do NOT reboot. The journal is still INSTALLED (we have not
			// transitioned to ARMED yet) and BootNext was never set, so the box
			// stays on the known-good default and a retry can re-arm cleanly.
			//
			// The failed arm may still have partially acquired the watchdog: the
			// real ArmWatchdog pets after opening /dev/watchdog, before it reports
			// a WDIOC_SETTIMEOUT failure. Disarm it so the aborted arm does not
			// leave the driver-default countdown running (#12162).
			return false, disarmStrictWatchdogAfterArmFailure(sys, err)
		}
		// D2 (best-effort): BootNext is the loop-safety. Log and continue; an
		// early-boot hang would need one external/console reset to recover.
		r.logf("kernel-upgrade arm: WARNING arm watchdog: %v (continuing; BootNext closes the loop)", err)
	} else {
		watchdogArmed = true
	}

	// Two-phase arm (#5847). The previous order persisted ARMED *before* the
	// NVRAM one-shot on the theory that an ARMED-without-BootNext journal is
	// harmless. It is NOT: a crash in that gap (or before the best-effort
	// rollback ran) left a journal claiming ARMED while the firmware still boots
	// the known-good default and no trial ever happens — a FALSE-ARMED journal.
	// Arm then refuses-forever (>= ARMED), and self-recovery treats it as a
	// genuine in-flight trial and suppresses expired-lease failback INDEFINITELY,
	// so a drained node never rejoins. The two orders are not symmetric — neither
	// single write is atomic with the NVRAM mutation — so make ARMED authoritative
	// via a positive readback instead:
	//
	//   1. record ARMING (prepared intent) BEFORE the NVRAM mutation, with a
	//      fresh per-attempt nonce;
	//   2. SetBootNext(inactiveID);
	//   3. POSITIVELY read BootNext back == inactiveID (a firmware that dropped
	//      or partial-wrote the variable must not yield a false-ARMED journal);
	//   4. only THEN durably transition ARMING -> ARMED, recording the confirmed
	//      boot id.
	//
	// A journal stuck at ARMING is NOT a genuine trial (BootNext unconfirmed):
	// Arm re-arms from it (ARMING < ARMED, so the >= ARMED refusal does not fire),
	// and self-recovery does not suppress failback (IsArmed reports true only for
	// the verified ARMED). armCandidate is idempotent, so a re-arm from ARMING
	// re-runs cleanly.
	j.ArmAttempts++
	j.ArmNonce = r.newArmNonce(j)
	j.BootID = ""
	if err := r.ktransition(j, KernelStateArming); err != nil {
		return false, disarmWatchdogAfterArmFailure(sys, err)
	}

	if err := sys.SetBootNext(inactiveID); err != nil {
		// #16809: an error here does NOT prove BootNext was never set. The
		// write can land in firmware and the exec still report failure —
		// runCmdTimeout kills efibootmgr at kernelNVRAMTimeout after the
		// SetVariable already completed, or efibootmgr exits non-zero
		// after the write. Treating the error as "never set" (the
		// pre-#16809 comment) left the candidate queued for an arbitrary
		// later reboot while the journal said ARMING and every gate
		// classified the node as unarmed. Clear unconditionally via the
		// same helper the post-SetBootNext paths use: clearing an absent
		// BootNext is already a success, and a clear failure is reported
		// loudly with the manual delete-bootnext command.
		return false, disarmAfterArmFailure(sys,
			fmt.Errorf("kernel-upgrade arm: efibootmgr --bootnext %s: %w", inactiveID, err))
	}

	// Positively confirm the firmware accepted the one-shot BEFORE recording the
	// verified-ARMED journal. If the readback disagrees (firmware silently
	// dropped / partial-wrote the variable), do NOT advance to ARMED — stay
	// ARMING and surface the error so no false-ARMED journal is persisted.
	got, err = sys.GetBootNext()
	if err != nil {
		return false, disarmAfterArmFailure(sys, fmt.Errorf(
			"kernel-upgrade arm: read back BootNext (staying ARMING): %w", err))
	}
	if got != inactiveID {
		return false, disarmAfterArmFailure(sys, fmt.Errorf(
			"kernel-upgrade arm: BootNext readback = %q, expected inactive slot %s "+
				"(%s); firmware did not accept the one-shot — refusing to record ARMED (staying ARMING)",
			got, j.InactiveSlot, inactiveID))
	}

	// Verified: the firmware WILL boot the candidate next. Record the confirmed
	// boot id and transition to the genuine (trial-in-flight) ARMED state.
	j.BootID = inactiveID
	// Record WHICH xpfd must verify this candidate, before the journal says
	// ARMED. The gate reads this instead of inferring a binary from ambient
	// state; failing here refuses the arm rather than producing an armed
	// candidate nothing is designated to verify (#6601 r6).
	if err := r.recordPromoteBinary(j); err != nil {
		return false, disarmAfterArmFailure(sys, fmt.Errorf("kernel-upgrade arm: %w", err))
	}
	if err := r.ktransition(j, KernelStateArmed); err != nil {
		if !isPostRenameJournalError(err) {
			return false, disarmAfterArmFailure(sys, err)
		}
		// The ARMED rename landed: BootNext was positively read back and the
		// visible journal now agrees with that queued trial. Do not unwind by
		// clearing BootNext/disarming the watchdog, which would leave a
		// false-ARMED journal (Arm refuses >= ARMED). As with #12162's landed
		// backstep/restore writes, classify the typed error by errors.As and
		// continue with the verified trial; durability across power loss is
		// unknown, but a plain error here would contradict the visible state.
		r.logf("kernel-upgrade arm: ARMED journal rename landed but directory sync failed "+
			"(durability across power loss is unknown): %v; proceeding to reboot", err)
	}

	return watchdogArmed, nil
}

// disarmWatchdogAfterArmFailure disarms the watchdog on a failed arm and
// preserves both the original cause and any disarm error.
func disarmWatchdogAfterArmFailure(sys KernelSystem, cause error) error {
	if err := sys.DisarmWatchdog(); err != nil {
		return fmt.Errorf("%w; AND the hardware watchdog could not be disarmed (%w) — "+
			"it may still reset the host", cause, err)
	}
	return cause
}

// disarmStrictWatchdogAfterArmFailure reports LANE 2 only when cleanup
// successfully disarmed any partially acquired watchdog.
func disarmStrictWatchdogAfterArmFailure(sys KernelSystem, armErr error) error {
	if err := sys.DisarmWatchdog(); err != nil {
		return fmt.Errorf("strict-watchdog (D1) arm failed: %w; AND the hardware watchdog "+
			"could not be disarmed (%w) — it may still reset the host; abort with an "+
			"infrastructure error rather than falling through to LANE 2",
			armErr, err)
	}
	return fmt.Errorf("%w: strict-watchdog (D1) arm failed: %v",
		ErrKernelChannelUnavailable, armErr)
}

// disarmAfterArmFailure clears BootNext before disarming the watchdog, at or
// after the SetBootNext call. It preserves the original cause plus cleanup
// errors (#6758, #12162, #16809). (The failed-Reboot path uses
// disarmAfterFailedReboot.)
//
// THE DIVERGENCE IT CLOSES. The two-phase arm records ARMING before touching
// NVRAM and only advances to ARMED after a positive BootNext readback. Every
// failure between those two points returned an error and left the journal at
// ARMING — but SetBootNext had ALREADY SUCCEEDED, so the firmware would still
// one-shot the candidate on the next reboot. ARMING is documented as exactly
// the opposite: "the firmware still boots the known-good default (no confirmed
// one-shot)", which is what lets `Arm` re-arm from ARMING and what stops
// self-recovery suppressing expired-lease failback. So BootNext stayed armed
// while every durable software gate classified the node as unarmed, and a
// drained node could rejoin with an untested candidate kernel queued for its
// next boot.
//
// The `recordPromoteBinary` path is the sharpest: the readback had already
// CONFIRMED the one-shot, so the candidate was genuinely queued while no xpfd
// was designated to verify it — an armed candidate with nothing to run the
// promotion gate, which #6601 added that record specifically to prevent.
//
// SINGLE-SOURCED for armCandidate's failure paths at or after the SetBootNext
// call (#16809: including SetBootNext's own error, whose write may have
// landed before the exec reported failure); a failed Reboot uses the same
// clear step and disarms only after it succeeds.
// Clearing an absent BootNext is not an error, so this is safe on the
// readback-mismatch path where the firmware may have dropped the variable.
//
// If the clear itself FAILS, armCandidate still attempts watchdog disarm and
// reports both cleanup errors. The failed-Reboot path instead keeps the
// watchdog running until it can restore the verified ARMED journal. This helper
// does not mutate the journal: armCandidate cannot manufacture ARMED because the
// promote binary may be missing on its recordPromoteBinary path.
func disarmAfterArmFailure(sys KernelSystem, cause error) error {
	_, cause = clearBootNextAfterArmFailure(sys, cause)
	return disarmWatchdogAfterArmFailure(sys, cause)
}

// disarmAfterFailedReboot keeps the watchdog armed if BootNext could not be
// cleared, allowing Arm to restore the already-verified ARMED journal.
func disarmAfterFailedReboot(sys KernelSystem, cause error) (bool, error) {
	bootNextCleared, cause := clearBootNextAfterArmFailure(sys, cause)
	if !bootNextCleared {
		return false, cause
	}
	return true, disarmWatchdogAfterArmFailure(sys, cause)
}

func clearBootNextAfterArmFailure(sys KernelSystem, cause error) (bool, error) {
	if cerr := sys.ClearBootNext(); cerr != nil {
		return false, fmt.Errorf("%w; AND the one-shot BootNext could not be cleared (%w) — "+
			"the firmware may still boot the candidate on the next reboot. Clear it "+
			"manually before rebooting: efibootmgr --delete-bootnext", cause, cerr)
	}
	return true, cause
}

// newArmNonce builds a per-attempt arm token (#5847). It combines the system
// clock with the run's monotonically-increasing attempt counter and the
// candidate/slot identity so a fresh arm is always distinguishable from a stale
// journal — the attempt counter guarantees uniqueness across attempts even under
// a stuck test clock.
func (r *KernelRunner) newArmNonce(j *KernelJournal) string {
	return fmt.Sprintf("%d-%d-%s-%s", r.cfg.Sys.Now().UnixNano(), j.ArmAttempts, j.InactiveSlot, j.CandidateVersion)
}

// Promote runs the POST-REBOOT promotion gate from the candidate boot. It is
// invoked by the promotion oneshot systemd unit early on the candidate boot
// (before xpfd admits traffic). It returns the completed outcome on a clean
// promote or known-good cleanup, and a non-nil error on a revert or infra
// failure. The outcome lets the CLI distinguish promotion from a discarded
// candidate and from an ordinary no-op boot.
func (r *KernelRunner) Promote() (KernelRollOutcome, error) {
	sys := r.cfg.Sys
	j, err := r.loadKernelJournal()
	if err != nil {
		return KernelRollOutcome{}, err
	}
	if !j.State.atLeast(KernelStateArmed) {
		// #16809: ARMING is prepared intent ONLY if this boot is not the
		// candidate. Process death between SetBootNext and the ARMED
		// rename (or a landed-but-errored SetBootNext whose clear never
		// ran) queues BootNext while the journal stays ARMING, so the
		// candidate CAN be the running kernel here. Classify on boot
		// evidence: a genuine trial is gated exactly like ARMED below;
		// unreadable evidence fails closed indeterminate (no prune, no
		// reboot, journal kept); positive non-candidate evidence is the
		// ordinary boot this branch has always meant.
		if j.State == KernelStateArming {
			trial, tj, terr := r.UnconfirmedTrial()
			if terr != nil {
				return KernelRollOutcome{}, r.recoverIndeterminate(j, terr)
			}
			if !trial {
				if err := r.settlePruneOwed(); err != nil {
					return KernelRollOutcome{}, err
				}
				r.logf("kernel-upgrade: no armed candidate (state=%s); ordinary boot, nothing to promote", j.State)
				return KernelRollOutcome{}, nil
			}
			j = tj
			r.logf("kernel-upgrade: ARMING journal but BootCurrent is the candidate slot "+
				"and the running kernel IS candidate %s — an unconfirmed trial whose "+
				"one-shot was queued without a verified ARMED record (#16809); running "+
				"the promotion gate", j.CandidateVersion)
			// Fall through to the ARMED gate below with this journal.
		} else {
			// Nothing armed -> this is an ordinary boot, not a candidate trial.
			// A prune deferred by an earlier revert survives the journal clear
			// that ended that roll in its own sidecar (#16811); this ordinary
			// boot is where it is collected, exactly once, now that the running
			// kernel can be proven not to be the deferred candidate.
			if err := r.settlePruneOwed(); err != nil {
				return KernelRollOutcome{}, err
			}
			r.logf("kernel-upgrade: no armed candidate (state=%s); ordinary boot, nothing to promote", j.State)
			return KernelRollOutcome{}, nil
		}
	}
	if j.State == KernelStatePromoted || j.State == KernelStateReverted {
		// The trial is terminal but its journal clear has not landed (or
		// failed). Defer to that trial: settling here could race the
		// terminal logic on the next pass that finishes clearing it.
		r.logf("kernel-upgrade: already terminal (%s); nothing to do", j.State)
		return KernelRollOutcome{}, nil
	}

	// Gate 1: did the firmware actually boot the candidate slot?
	entries, err := sys.BootEntries()
	if err != nil {
		// The candidate slot id is unknowable, so Gate 2/verify cannot run —
		// but a blanket revert is still wrong: on a firmware-fallback boot
		// the box may already be on the known-good kernel, where a reboot is
		// redundant and the outcome is "discarded", not "reverted" (#16446,
		// mirroring the #4872-A BootCurrent switch below). Discriminate on
		// RunningKernel first.
		return r.resolveUnconfirmedBoot(j, fmt.Errorf("read boot entries: %w", err))
	}
	candID, ok := entries[j.InactiveSlot]
	if !ok {
		// Same discrimination: a vanished candidate slot on an already
		// known-good boot needs no reboot; on the candidate it must revert
		// (no slot id to promote); unreadable stays indeterminate.
		return r.resolveUnconfirmedBoot(j, fmt.Errorf("candidate slot %s vanished from NVRAM", j.InactiveSlot))
	}
	cur, err := sys.BootCurrent()
	if err != nil {
		// Can't read which slot the firmware booted. The old code treated this
		// as "already on known-good" and ran cleanupAlreadyOnKnownGood, which
		// PRUNES the candidate slot (deletes /lib/modules/<candidate> +
		// /boot/*-<candidate>). But a transient efibootmgr/NVRAM read error does
		// NOT mean we are off the candidate — if BootNext actually booted it, we
		// would be deleting the running kernel's own modules/boot files (#4872 A).
		// Fail CLOSED on the destructive prune: check RunningKernel first.
		running, rkErr := sys.RunningKernel()
		switch {
		case rkErr != nil:
			// Neither the booted slot NOR the running kernel is knowable. We
			// cannot prove we are off the candidate, so we must NOT prune, and we
			// must NOT reboot (a read-only-root reboot loop is the other hazard).
			// Preserve the journal + candidate untouched and surface the error;
			// the next boot re-runs this gate, and any reboot meanwhile lands on
			// the known-good BootOrder front (BootNext already consumed).
			return KernelRollOutcome{}, r.recoverIndeterminate(j, fmt.Errorf(
				"read BootCurrent: %v; running kernel also unreadable: %w", err, rkErr))
		case running == j.CandidateVersion:
			// We ARE running the candidate despite the BootCurrent read error.
			// Do NOT prune the kernel we are running — run the verification gate
			// so a healthy candidate can still promote and an unhealthy one takes
			// the controlled (bounded) revert path, never the silent-delete path.
			r.logf("kernel-upgrade: BootCurrent unreadable (%v) but running kernel IS "+
				"candidate %s; running verification gate (NOT pruning)", err, running)
			return r.verifyAndPromote(j, candID, running)
		default:
			// Positive evidence we booted a non-candidate (known-good) kernel:
			// pruning the un-promoted candidate slot is safe.
			return r.cleanupAlreadyOnKnownGood(j, fmt.Errorf(
				"read BootCurrent: %v; running kernel %s != candidate %s — on known-good",
				err, running, j.CandidateVersion))
		}
	}
	if cur != candID {
		// Firmware ignored BootNext / fell back — this boot is ALREADY on a
		// non-candidate (known-good) slot. This is NOT a revert-needing reboot:
		// rebooting again would be redundant (r1 AGY double-reboot) and, if the
		// journal can't be cleared (read-only root), would loop forever
		// bypassing the SAFE-BOOTSTRAP lifeline (r1 AGY catastrophic). Just
		// clean up in place and continue THIS boot (exit 0, no reboot).
		return r.cleanupAlreadyOnKnownGood(j, fmt.Errorf(
			"BootCurrent=%s != candidate slot %s (%s) — already on known-good, no reboot", cur, j.InactiveSlot, candID))
	}

	// Gate 2: is the running kernel actually the candidate?
	running, err := sys.RunningKernel()
	if err != nil {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("uname -r: %w", err))
	}
	if running != j.CandidateVersion {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("running kernel %s != candidate %s", running, j.CandidateVersion))
	}
	return r.verifyAndPromote(j, candID, running)
}

// resolveUnconfirmedBoot discriminates the Gate-1 failures where the
// candidate's NVRAM state is unconfirmed — BootEntries unreadable, or the
// candidate slot missing from it — so no candID is available (#16446). It
// mirrors the #4872-A BootCurrent switch, except that with no slot id the
// candidate-running branch cannot enter verifyAndPromote (which needs candID
// for the promote BootOrder reorder) and instead takes the controlled,
// attempt-counted revert — which defers pruning the running candidate
// (#14165) and still requests the exit-3 reboot. Positive non-candidate
// evidence takes the no-reboot discarded cleanup; an unreadable running
// kernel fails closed indeterminate (no prune, no reboot, journal kept).
func (r *KernelRunner) resolveUnconfirmedBoot(j *KernelJournal, cause error) (KernelRollOutcome, error) {
	sys := r.cfg.Sys
	running, rkErr := sys.RunningKernel()
	switch {
	case rkErr != nil:
		return KernelRollOutcome{}, r.recoverIndeterminate(j, fmt.Errorf(
			"%v; running kernel also unreadable: %w", cause, rkErr))
	case running == j.CandidateVersion:
		// Running the candidate but cannot confirm or promote its slot:
		// the controlled revert (bounded, prune deferred while it runs).
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf(
			"%v; running kernel IS candidate %s but its NVRAM slot is unconfirmed", cause, running))
	default:
		// Positive evidence we booted a non-candidate (known-good) kernel:
		// pruning the un-promoted candidate slot is safe, no reboot needed.
		return r.cleanupAlreadyOnKnownGood(j, fmt.Errorf(
			"%v; running kernel %s != candidate %s — on known-good", cause, running, j.CandidateVersion))
	}
}

// verifyAndPromote runs the post-Gate-2 verification (verify-dataplane +
// forward beacon) and, on success, promotes the candidate; on any failure it
// reverts. It is entered only after we have CONFIRMED the running kernel is the
// candidate (`running == j.CandidateVersion`), either via the normal
// BootCurrent==candidate path or the #4872-A fail-closed path where BootCurrent
// was unreadable but RunningKernel positively identified the candidate — so it
// never prunes the kernel it is validating.
func (r *KernelRunner) verifyAndPromote(j *KernelJournal, candID, running string) (KernelRollOutcome, error) {
	sys := r.cfg.Sys

	// Gate 2b: the binary running this gate must be the one the ARMING
	// designated (#6601 r6). The outer hop selects from the arm record, so this
	// is normally trivially true; it earns its place when the gate was invoked
	// by hand or by a different xpfd than the one that armed. A mismatch
	// REVERTS — an undesignated binary must not authorize the promotion, and
	// reverting is the safe direction on an A/B kernel trial.
	if err := VerifyPromoteBinaryMatchesRecord(j.PromoteBinary); err != nil {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("arm-record mismatch: %w", err))
	}
	if err := r.checkKernelFloor(j); err != nil {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("anti-rollback floor: %w", err))
	}


	// Gate 3: verify-dataplane (the #1864 kernel verifier) on the candidate.
	ok, err := sys.VerifyDataplane()
	if err != nil {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("verify-dataplane error: %w", err))
	}
	if !ok {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("verify-dataplane REJECT on candidate kernel %s", running))
	}

	// Gate 4: forward health beacon (structural verify != actually forwards).
	ok, err = sys.ForwardBeacon(r.cfg.BeaconDeadline)
	if err != nil {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("forward beacon error: %w", err))
	}
	if !ok {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("forward beacon FAILED on candidate kernel %s", running))
	}

	// PASS: promote — non-destructive BootOrder reorder (candidate first). If
	// the reorder FAILS, the candidate is running but NOT durably the default;
	// the safe action is to REVERT (reboot to known-good) rather than leave it
	// un-promoted (which the oneshot would treat as a non-revert "infra error"
	// and continue booting an un-promoted candidate — r1 Copilot). revert()
	// restores the known-good BootOrder front + reboots.
	if err := sys.SetBootOrderFront(candID); err != nil {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("promote: set BootOrder front %s failed: %w", candID, err))
	}
	if err := r.advanceKernelFloor(j); err != nil {
		return KernelRollOutcome{}, r.revert(j, fmt.Errorf("persist anti-rollback floor: %w", err))
	}
	if err := sys.DisarmWatchdog(); err != nil {
		r.logf("kernel-upgrade promote: WARNING disarm watchdog: %v", err)
	}
	// Write the DURABLE promotion marker BEFORE clearing the journal, so the
	// external HA orchestrator's post-reboot version-check has a signal that
	// survives the clear (INC-2). Best-effort: a marker-write failure does not
	// un-promote (the BootOrder reorder already succeeded), but the orchestrator
	// then relies on `uname -r == target` alone.
	if err := sys.WritePromotionMarker(running); err != nil {
		r.logf("kernel-upgrade promote: WARNING write promotion marker: %v", err)
	}
	// #6495: durable last-roll outcome, alongside the marker and for the same
	// reason — the journal is about to be cleared. The marker answers the HA
	// orchestrator's "did THIS node promote version X"; this answers the
	// operator's "what happened to the last roll", which a cleared marker cannot
	// answer on a revert or known-good discard.
	outcome := r.recordRollOutcome(j, RollOutcomePromoted, "")
	// The candidate slot is now the active/known-good slot; the OTHER slot
	// (the former active) becomes the rollback target and keeps its kernel.
	if err := r.ktransition(j, KernelStatePromoted); err != nil {
		if !isPostRenameJournalError(err) {
			return KernelRollOutcome{}, err
		}
		// The PROMOTED rename landed: the gates passed and candidate-first
		// BootOrder, the promotion marker, and last-roll outcome are already
		// committed. Do not report an infra failure against that visible
		// terminal state; clear the journal below. Power-loss durability of the
		// rename remains unknown.
		r.logf("kernel-upgrade promote: PROMOTED journal rename landed but directory sync failed "+
			"(durability across power loss is unknown): %v; clearing terminal journal", err)
	}
	// #15181: a promoted roll is complete — clear the orchestrator's
	// kernel-roll lease so it cannot later be read as a crashed-roll
	// fingerprint against an unrelated operator drain. Best-effort, like
	// the marker write above (the orchestrator also clears on success).
	if err := sys.ClearRollLease(); err != nil {
		r.logf("kernel-upgrade promote: WARNING clear roll lease: %v", err)
	}
	r.logf("kernel-upgrade: PROMOTED candidate %s (slot %s now default)", running, j.InactiveSlot)
	if err := r.clearKernelJournal(); err != nil {
		return KernelRollOutcome{}, err
	}
	// Safety net for a prune-owed record naming the version just promoted
	// (#16811) — e.g. one a failed journal clear left behind across a
	// re-arm. The normal supersession happens at re-arm (see Arm). Without
	// this, such a record would be refused forever (running == that
	// candidate on every later boot). Best-effort: the promotion is already
	// committed and its journal cleared, so a settle failure is logged,
	// never reported against it.
	if err := r.settlePruneOwedAfterPromote(running); err != nil {
		r.logf("kernel-upgrade: WARNING settle prune owed after promote: %v", err)
	}
	return outcome, nil
}

// recoverIndeterminate handles the post-reboot case where NEITHER the booted
// slot (BootCurrent) NOR the running kernel (uname -r) is readable, so we
// cannot prove we are off the candidate. Both the destructive prune (which
// could delete a candidate we are actually running — #4872 A) and a reboot
// (read-only-root reboot loop) are unsafe here, so this fails CLOSED: it
// preserves the journal + candidate untouched, performs no prune and no reboot,
// and returns the (non-revert) error so the promotion oneshot maps it to an
// infra exit (NOT exit 3). The next boot re-runs the gate; if NVRAM/uname is
// readable then it resolves normally, and any reboot meanwhile falls through
// BootOrder to the known-good slot (BootNext already consumed).
func (r *KernelRunner) recoverIndeterminate(j *KernelJournal, why error) error {
	r.logf("kernel-upgrade: INDETERMINATE post-reboot state (%v); cannot confirm we are off "+
		"the candidate — preserving journal + candidate (NO prune, NO reboot) for the next "+
		"boot / operator to resolve", why)
	return fmt.Errorf("kernel-upgrade promote: indeterminate boot state (no prune, no reboot): %w", why)
}

// revert records the revert reason, prunes the un-promoted candidate, and
// returns an error so the caller (the promotion oneshot) issues a clean reboot
// to the known-good slot. The boot-LOOP is already closed by firmware (BootNext
// was consumed), so the reboot lands on the known-good slot.
func (r *KernelRunner) revert(j *KernelJournal, reason error) error {
	// #6495: record the outcome FIRST, before anything that can return early.
	// revert() has three exits — journal-unwritable, attempt-cap give-up, and
	// the normal reboot path — and the two early ones are precisely the states
	// an operator most needs explained (a read-only root, or a candidate that
	// failed three times). Recording at the top means every one of them leaves
	// a durable answer. Best-effort: a failed history write never changes what
	// the revert DOES.
	r.recordRollOutcome(j, RollOutcomeReverted, fmt.Sprintf("%v", reason))

	// Boot-attempt guard (r1 AGY catastrophic): if the journal cannot be
	// CLEARED (e.g. read-only root after a kernel oops), a naive revert would
	// loop forever — each boot re-reads ARMED, reverts, exits 3, reboots. Bound
	// the reboot requests: bump PromoteAttempts; once it exceeds the cap, STOP
	// requesting reboots (return nil = exit 0, continue THIS boot) so the box
	// stays up on whatever slot it is on (the firmware already prefers the
	// known-good default) and the SAFE-BOOTSTRAP lifeline is reachable for the
	// operator. We also confirm we can persist the bump; if we cannot, we must
	// NOT request a reboot (the loop-avoidance is the priority).
	j.PromoteAttempts++
	if err := r.saveKernelJournal(j); err != nil {
		r.logf("kernel-upgrade: REVERT but journal NOT persistable (%v); NOT rebooting "+
			"(avoid a read-only-root reboot loop) — staying up for operator recovery", err)
		return fmt.Errorf("kernel-upgrade revert (journal unwritable, not rebooting): %v", reason)
	}
	// Restore the box to the safest reachable state (known-good BootOrder front
	// + disarm watchdog + prune candidate) BEFORE deciding whether to reboot —
	// so that EVEN the attempt-cap-exceeded "give up" path below leaves the box
	// on the known-good default rather than abandoning it candidate-first
	// (r2 Copilot: the cap path previously cleared the journal without
	// restoring BootOrder).
	r.restoreKnownGood(j)

	if j.PromoteAttempts > maxPromoteAttempts {
		r.logf("kernel-upgrade: REVERT but %d attempts exceeded cap %d; NOT rebooting again "+
			"— staying up for operator recovery (BootOrder restored to known-good)", j.PromoteAttempts, maxPromoteAttempts)
		_ = r.clearKernelJournal()
		return fmt.Errorf("kernel-upgrade revert (attempt cap exceeded, not rebooting): %v", reason)
	}
	r.logf("kernel-upgrade: REVERT (%v); candidate NOT promoted, rebooting to known-good (attempt %d/%d)",
		reason, j.PromoteAttempts, maxPromoteAttempts)

	_ = r.ktransition(j, KernelStateReverted)
	// Clear the journal so the next boot is a clean ordinary boot.
	_ = r.clearKernelJournal()
	// Wrap ErrKernelReverted so the CLI maps this to exit 3 (reboot to
	// known-good), distinct from an infra error (exit 1). reason is chained
	// for the log/operator.
	return fmt.Errorf("%w: %v", ErrKernelReverted, reason)
}

// restoreKnownGood puts the box in the safest reachable state: the known-good
// (active) slot at the FRONT of BootOrder (so even if a prior crash left the
// candidate first, a reboot lands on known-good — Codex High), the watchdog
// disarmed (so an Arm()-armed watchdog can't bounce the known-good boot —
// Copilot), the inactive slot's selector rewritten to the known-good kernel,
// and — ONLY when positively off the candidate — the un-promoted candidate
// pruned. All best-effort: the firmware-cleared BootNext remains the floor
// regardless. Shared by revert() (incl. the attempt-cap give-up path) and
// cleanupAlreadyOnKnownGood.
//
// #14165: revert() is routinely entered WHILE RUNNING the candidate (Gate 2
// positively confirmed running == CandidateVersion, then verify / beacon /
// BootOrder failed). Pruning there purges linux-image-<candidate> and deletes
// /lib/modules/<candidate> + /boot/*-<candidate> from under the live kernel,
// and on the attempt-cap path the box then stays up in that orphaned state.
// So the destructive prune is gated on a fresh RunningKernel read: equal to
// the candidate, or unreadable (cannot prove we are off it), DEFERS the prune
// — the selector + BootOrder restore above still runs, so the next boot lands
// on known-good. Only positive evidence of a non-candidate running kernel
// prunes in place. The real PruneInactiveSlot re-checks uname -r itself as a
// second, independent fail-closed layer.
//
// #16811: the deferral is persisted. restoreKnownGood's callers clear the
// journal on every terminal exit (revert's exit-3 path, its attempt-cap
// exit, and cleanupAlreadyOnKnownGood), so without a record of its own the
// deferred prune was forgotten and the candidate leaked on disk forever.
// The deferral now writes a prune-owed sidecar (kernel_prune_owed.go); the
// next ordinary boot — or a superseding promote — collects it exactly once
// via settlePruneOwed. A same-boot exit that reaches here ALREADY off the
// candidate (cleanupAlreadyOnKnownGood) prunes in place below and clears
// any stale record for THIS candidate, so its debt never double-fires.
func (r *KernelRunner) restoreKnownGood(j *KernelJournal) {
	sys := r.cfg.Sys
	if entries, err := sys.BootEntries(); err == nil {
		if activeID, ok := entries[j.ActiveSlot]; ok {
			if err := sys.SetBootOrderFront(activeID); err != nil {
				r.logf("kernel-upgrade: WARNING restore known-good BootOrder front: %v", err)
			}
		} else {
			r.logf("kernel-upgrade: WARNING active slot %s not in NVRAM", j.ActiveSlot)
		}
	} else {
		r.logf("kernel-upgrade: WARNING read boot entries: %v", err)
	}
	if err := sys.DisarmWatchdog(); err != nil {
		r.logf("kernel-upgrade: WARNING disarm watchdog: %v", err)
	}
	// Non-destructive selector restore FIRST and UNCONDITIONALLY: even when
	// the prune below is deferred, the inactive slot must not keep pointing
	// at the candidate for the next boot.
	if err := sys.RestoreInactiveSlotSelector(j.InactiveSlot, j.KnownGoodVersion); err != nil {
		r.logf("kernel-upgrade: WARNING restore inactive slot selector: %v", err)
	}
	running, rkErr := sys.RunningKernel()
	switch {
	case rkErr != nil:
		// #16811: persist the owed prune BEFORE any terminal journal clear
		// by the caller, so the next off-candidate boot collects it.
		r.recordPruneOwed(j)
		r.logf("kernel-upgrade: WARNING running kernel unreadable (%v); DEFER prune of candidate %s until a boot can prove it is not running (prune-owed record written)", rkErr, j.CandidateVersion)
	case running == j.CandidateVersion:
		r.recordPruneOwed(j)
		r.logf("kernel-upgrade: candidate %s is the RUNNING kernel; DEFER prune (selector + BootOrder restored for next boot, prune-owed record written)", running)
	default:
		if err := sys.PruneInactiveSlot(j.InactiveSlot, j.KnownGoodVersion, j.CandidateVersion); err != nil {
			r.logf("kernel-upgrade: WARNING prune inactive slot: %v", err)
		} else if rec, rerr := r.readPruneOwed(); rerr == nil && rec.CandidateVersion == j.CandidateVersion {
			// The in-place prune just discharged any record owed for THIS
			// candidate (e.g. written by an earlier pass whose journal
			// clear failed); a different candidate's debt is untouched.
			if cerr := r.clearPruneOwed(); cerr != nil {
				r.logf("kernel-upgrade: WARNING clear discharged prune-owed record: %v", cerr)
			}
		}
	}
	// Clear the durable promotion marker (r2 AGY #6: a reverted node must not
	// retain a "promoted" marker from a prior same-version roll) and the local
	// kernel-roll lease (r2 AGY #5: a stranded lease would suppress this node's
	// self-recovery for the full TTL after the dead roll). Both best-effort.
	if err := sys.ClearPromotionMarker(); err != nil {
		r.logf("kernel-upgrade: WARNING clear promotion marker on restore: %v", err)
	}
	if err := sys.ClearRollLease(); err != nil {
		r.logf("kernel-upgrade: WARNING clear roll lease on restore: %v", err)
	}
}

// cleanupAlreadyOnKnownGood handles the case where the gate runs but the box is
// ALREADY on a non-candidate (known-good) slot — the firmware fell back, or we
// can't even tell which slot booted. There is nothing to revert TO (we're
// already safe), so this must NOT request a reboot (r1 AGY: a reboot here is
// redundant, and loops forever if the journal can't be cleared on a read-only
// root, bypassing the SAFE-BOOTSTRAP lifeline). It best-effort prunes the
// un-promoted candidate + clears the journal and returns the discarded outcome
// for the CLI (exit 0 — continue THIS boot). Journal-clear failure is
// non-fatal: on the next boot we are still on known-good and this same
// no-reboot path runs again.
func (r *KernelRunner) cleanupAlreadyOnKnownGood(j *KernelJournal, why error) (KernelRollOutcome, error) {
	r.logf("kernel-upgrade: already on a known-good slot (%v); cleaning up, NO reboot", why)
	// Record the candidate as discarded rather than promoted or reverted: the
	// firmware already left the box on known-good, so no revert reboot is needed.
	outcome := r.recordRollOutcome(j, RollOutcomeDiscarded, fmt.Sprintf("%v", why))
	// Restore the safest reachable state (BootOrder known-good front + disarm
	// watchdog + prune candidate), then clear the journal.
	r.restoreKnownGood(j)
	if err := r.clearKernelJournal(); err != nil {
		r.logf("kernel-upgrade: WARNING could not clear journal on known-good cleanup: %v "+
			"(non-fatal: next boot re-runs this no-reboot path)", err)
	}
	return outcome, nil
}

// IsArmed reports whether a VERIFIED candidate trial is recorded (used by the
// promotion oneshot to decide whether to run the gate at all, and by the HA
// orchestrator's version-check). It is deliberately state-only: ARMING is
// false here even when the current boot is an unconfirmed trial, because
// pre-boot callers (Arm's re-arm refusal, an offline status read) have no
// boot evidence to classify with. Boot-time callers that must not miss an
// unconfirmed trial use TrialInFlight (#16809).
func (r *KernelRunner) IsArmed() (bool, *KernelJournal, error) {
	j, err := r.loadKernelJournal()
	if err != nil {
		return false, nil, err
	}
	return j.State.atLeast(KernelStateArmed) && j.State != KernelStatePromoted && j.State != KernelStateReverted, j, nil
}

// TrialInFlight reports whether THIS boot is a candidate trial that must be
// gated and held: either a verified ARMED journal, or an ARMING journal the
// boot evidence convicts as a genuine (unconfirmed) trial (#16809). It is the
// single boot-time predicate for the daemon election hold and kernel
// self-recovery, replacing a bare IsArmed there: an unconfirmed trial runs an
// UNVERIFIED candidate, so it must be held SECONDARY and must suppress
// expired-lease failback exactly like ARMED, not rejoin as an ordinary boot.
//
// Fail-closed: classification errors are returned, never folded to false —
// a caller that cannot prove the boot is off the candidate must hold /
// suppress, not proceed. ARMED short-circuits WITHOUT the boot-evidence
// reads, preserving the verified path's behavior exactly (including the
// known-good-fallback discrimination, which the daemon applies on top of
// this predicate via the running-kernel check).
func (r *KernelRunner) TrialInFlight() (bool, *KernelJournal, error) {
	armed, j, err := r.IsArmed()
	if err != nil || armed {
		return armed, j, err
	}
	return r.UnconfirmedTrial()
}

// summary is a short human string for status output.
func (j *KernelJournal) summary() string {
	if j == nil || j.State == KernelStateInit {
		return "no kernel upgrade in progress"
	}
	return fmt.Sprintf("kernel-upgrade %s: candidate=%s known-good=%s active-slot=%s",
		strings.ToLower(string(j.State)), j.CandidateVersion, j.KnownGoodVersion, j.ActiveSlot)
}
func isPostRenameJournalError(err error) bool {
	var post *fsatomic.PostRenameSyncError
	return errors.As(err, &post)
}
