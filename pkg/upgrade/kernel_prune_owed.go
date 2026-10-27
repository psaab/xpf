package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #16811: the durable "prune owed" record.
//
// `restoreKnownGood` defers the destructive candidate prune while the
// candidate is (or may be) the running kernel (#14165). Before this record,
// the deferring pass then cleared the journal on its terminal exits, so the
// next boot took `Promote`'s ordinary-boot early return and the candidate
// packages, /lib/modules/<candidate> and /boot/*-<candidate> stayed
// installed, held, and on disk permanently.
//
// Keeping that debt in the kernel journal itself does not survive the exits
// that owe it: revert's normal exit-3 path and its attempt-cap exit both
// clear the journal, and `cleanupAlreadyOnKnownGood` does the same after
// its own off-candidate prune.
//
// The owed record therefore lives in its OWN sidecar beside the journal,
// written by the deferring pass and consumed (deleted) by the next gate
// pass that proves it is off the candidate. The shell boot gate does not
// read it: it is acted on only inside `Promote`, where the running kernel
// is checked again and the real `PruneInactiveSlot` re-checks uname -r a
// second time, so a stale or forged record can never prune a kernel that
// is actually running.
const pruneOwedRecordName = "kernel-prune-owed"

// PruneOwedRecord is the persisted statement that a candidate prune was
// deferred because the candidate was (or could have been) the running
// kernel, and is still owed once a later boot is positively off it.
//
// Slot / CandidateVersion / KnownGoodVersion mirror the journal fields the
// owning roll armed — exactly what `PruneInactiveSlot` consumes.
type PruneOwedRecord struct {
	Slot             string `json:"slot"`
	CandidateVersion string `json:"candidate_version"`
	KnownGoodVersion string `json:"known_good_version"`
}

// PruneOwedPath returns the prune-owed record path for a given kernel
// journal path. The record lives beside the journal, sharing its
// directory, without sharing the journal's lifetime.
func PruneOwedPath(journalPath string) string {
	return filepath.Join(filepath.Dir(journalPath), pruneOwedRecordName)
}

// recordPruneOwed persists the deferred prune BEFORE the terminal journal
// clear that would otherwise erase all memory of it. A write failure is
// logged and otherwise ignored: `restoreKnownGood` is best-effort by
// contract, and the deferred state (selector restored to known-good,
// candidate unselected) is already the safe resting state — the cost of a
// failed write is the pre-#16811 leak on that one roll, never a safety
// regression.
func (r *KernelRunner) recordPruneOwed(j *KernelJournal) {
	rec := PruneOwedRecord{
		Slot:             j.InactiveSlot,
		CandidateVersion: j.CandidateVersion,
		KnownGoodVersion: j.KnownGoodVersion,
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		r.logf("kernel-upgrade: WARNING marshal prune-owed record: %v", err)
		return
	}
	path := PruneOwedPath(r.cfg.JournalPath)
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		r.logf("kernel-upgrade: WARNING create prune-owed record dir: %v", err)
		return
	}
	if err := fsatomic.WriteFileDurable(path, data, 0o644); err != nil {
		r.logf("kernel-upgrade: WARNING persist prune-owed record %s: %v", path, err)
	}
}

// readPruneOwed reads the prune-owed record beside the journal. An absent
// record returns a zero record and a NIL error: "no prune is owed" is the
// ordinary state. A present-but-unreadable or malformed record is an
// ERROR, never a zero record: absence is acted on as a positive statement
// ("nothing is owed"), so it must not be reachable by mis-parsing a file
// that is present.
func (r *KernelRunner) readPruneOwed() (PruneOwedRecord, error) {
	path := PruneOwedPath(r.cfg.JournalPath)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return PruneOwedRecord{}, nil
		}
		return PruneOwedRecord{}, fmt.Errorf("read prune-owed record: %w", err)
	}
	rec := PruneOwedRecord{}
	if err := json.Unmarshal(data, &rec); err != nil {
		return PruneOwedRecord{}, fmt.Errorf("parse prune-owed record: %w", err)
	}
	if rec.Slot == "" || rec.CandidateVersion == "" || rec.KnownGoodVersion == "" {
		return PruneOwedRecord{}, fmt.Errorf(
			"prune-owed record %s is missing slot/candidate/known-good; refusing to act on it", path)
	}
	return rec, nil
}

// clearPruneOwed removes the prune-owed record. Called only after the owed
// prune has been positively discharged (or superseded by a new arm), so a
// prune that FAILED leaves the record behind for the next boot to retry.
func (r *KernelRunner) clearPruneOwed() error {
	if err := os.Remove(PruneOwedPath(r.cfg.JournalPath)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove prune-owed record: %w", err)
	}
	return nil
}

// settlePruneOwed discharges a deferred prune (#16811) on an ordinary boot:
// a leftover record is the ONLY remaining evidence that a prune was
// deferred, and this boot is where it is collected.
//
// The running kernel is re-checked here, and the prune seams check uname -r
// again internally, so the owed prune fires only on positive evidence that
// the box is off the deferred candidate. Still running it — or unable to
// prove otherwise — leaves the record in place and returns WITHOUT an
// error: this boot is not the one that can collect the debt, and that must
// not turn an otherwise clean boot into an infra failure.
//
// #17860: the debt is only allowed the FULL prune while it still OWNS the
// recorded slot. restoreKnownGood left that slot's selector at the debt's
// known-good when it deferred; a later roll reusing the slot (Arm writes
// the new candidate's selector into it, and may even promote it, making it
// the running default) overwrites exactly that evidence. A selector naming
// anything other than the debt's own versions means a later roll owns the
// slot now, so the selector restore is skipped and only the package half
// of the debt is collected (PurgeCandidatePackages): rewriting the
// repurposed slot's selector to a stale known-good would silently abandon
// that roll's kernel on the next reboot. An UNREADABLE selector proves
// nothing either way — fail closed and leave the record for a later boot.
func (r *KernelRunner) settlePruneOwed() error {
	rec, err := r.readPruneOwed()
	if err != nil {
		return err
	}
	if rec.CandidateVersion == "" {
		return nil
	}
	running, rkErr := r.cfg.Sys.RunningKernel()
	switch {
	case rkErr != nil:
		r.logf("kernel-upgrade: prune of candidate %s still owed but running kernel "+
			"unreadable (%v); leaving the prune-owed record for a later boot", rec.CandidateVersion, rkErr)
		return nil
	case running == rec.CandidateVersion:
		r.logf("kernel-upgrade: prune of candidate %s still owed but it is the "+
			"RUNNING kernel; leaving the prune-owed record for a later boot", rec.CandidateVersion)
		return nil
	}
	sel, selErr := r.cfg.Sys.ReadSlotSelector(rec.Slot)
	switch {
	case selErr != nil:
		r.logf("kernel-upgrade: prune of candidate %s still owed but slot %s selector "+
			"unreadable (%v); cannot prove the slot still belongs to this debt — "+
			"leaving the prune-owed record for a later boot (#17860)",
			rec.CandidateVersion, rec.Slot, selErr)
		return nil
	case sel != rec.KnownGoodVersion && sel != rec.CandidateVersion:
		// The recorded slot was repurposed by a later roll (#17860): its
		// selector names neither the debt's known-good (what the deferring
		// revert left) nor the debt's own candidate (a stranded selector
		// whose repair belongs to this debt). Restore-then-purge would move
		// that selector to a stale known-good and abandon the later roll's
		// kernel on the next reboot, so only the package debt is collected.
		if err := r.cfg.Sys.PurgeCandidatePackages(rec.CandidateVersion); err != nil {
			// Keep the record, exactly like a failed full prune: the debt
			// is still owed and the next boot retries it.
			return fmt.Errorf("kernel-upgrade: owed purge of candidate %s (slot %s repurposed to %s): %w",
				rec.CandidateVersion, rec.Slot, sel, err)
		}
		r.logf("kernel-upgrade: slot %s selector points at %s, no longer this debt's "+
			"{known-good %s, candidate %s}; purged deferred candidate %s packages "+
			"WITHOUT rewriting the repurposed slot's selector (#17860)",
			rec.Slot, sel, rec.KnownGoodVersion, rec.CandidateVersion, rec.CandidateVersion)
		return r.clearPruneOwed()
	}
	if err := r.cfg.Sys.PruneInactiveSlot(rec.Slot, rec.KnownGoodVersion, rec.CandidateVersion); err != nil {
		// Keep the record: the prune is still owed and the next boot
		// retries it. Only success discharges the debt.
		return fmt.Errorf("kernel-upgrade: owed prune of candidate %s in slot %s: %w",
			rec.CandidateVersion, rec.Slot, err)
	}
	r.logf("kernel-upgrade: pruned deferred candidate %s (slot %s); prune no longer owed",
		rec.CandidateVersion, rec.Slot)
	return r.clearPruneOwed()
}

// settlePruneOwedAfterPromote is the safety net for a prune-owed record
// naming the version JUST promoted (#16811): a record written by a pass
// whose journal clear failed (so a later pass still sees its trial), then
// superseded when that candidate was re-armed and promoted. The normal
// supersession happens at re-arm (see Arm); this discharge exists for
// records that appear between the arm and the promote or survive a
// failed clear. Pruning here would purge the running, just-promoted
// kernel, so the record is cleared by supersession and logged.
//
// A record for a DIFFERENT version means an older deferred candidate is
// still installed. Discharging THAT debt is not decided here: the next
// ordinary boot collects it via settlePruneOwed, and doing it inside
// this promotion would rewrite the recorded slot's selector to a STALE
// known-good — the slot the just-committed promotion may itself depend
// on. So a different-version record is preserved untouched.
//
// Best-effort by contract with its caller: a failure is logged there
// and never reported against the committed promotion.
func (r *KernelRunner) settlePruneOwedAfterPromote(promoted string) error {
	rec, err := r.readPruneOwed()
	if err != nil {
		return err
	}
	if rec.CandidateVersion == "" {
		return nil
	}
	if rec.CandidateVersion == promoted {
		r.logf("kernel-upgrade: deferred prune of candidate %s superseded by its "+
			"promotion; clearing the prune-owed record without pruning", rec.CandidateVersion)
		return r.clearPruneOwed()
	}
	return nil
}
