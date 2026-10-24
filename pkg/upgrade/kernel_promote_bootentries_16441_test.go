package upgrade

import (
	"fmt"
	"testing"
)

// #16441: Promote's Gate 1 sent a BootEntries() error, and a missing candidate
// slot, straight to revert (exit 3 + reboot) without the RunningKernel
// discrimination #4872-A added for the BootCurrent-unreadable sibling. A
// firmware-fallback boot that hit an efibootmgr/NVRAM failure therefore
// rebooted an already-safe box and recorded "reverted" where "discarded" was
// true. These tests pin the mirrored switch for both Gate-1 failure shapes
// crossed with known-good / candidate / unreadable running kernels.

// BootEntries fails and the running kernel is positively known-good: this is
// the research probe's defect row. It must match the control row
// (BootCurrent != candidate): discarded, no reboot (nil error), candidate
// pruned, journal cleared.
func TestKernelPromoteBootEntriesErrKnownGoodDiscards16441(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.entriesErr = fmt.Errorf("efibootmgr timed out: context deadline exceeded")
	f.running = "6.18.5-10-generic" // known-good, NOT the candidate

	outcome, err := r.Promote()
	if err != nil {
		t.Fatalf("#16441: positively-known-good boot must discard without reboot, got %v", err)
	}
	if errorsIsReverted(err) {
		t.Fatalf("#16441: known-good boot took the exit-3 revert path: %v", err)
	}
	if outcome.Outcome != RollOutcomeDiscarded || f.lastRoll.Outcome != RollOutcomeDiscarded {
		t.Fatalf("#16441: outcome/record = %q/%q, want discarded (not reverted)",
			outcome.Outcome, f.lastRoll.Outcome)
	}
	if !contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#16441: expected the un-promoted candidate pruned when positively on known-good")
	}
	if contains(f.calls, "bootorder-front:0004") {
		t.Fatal("#16441: must not promote when not running the candidate")
	}
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateInit {
		t.Fatalf("#16441: journal not cleared on known-good discard (state=%s)", j.State)
	}
}

// Candidate slot vanished from NVRAM and the running kernel is positively
// known-good: same no-reboot discarded outcome as the BootEntries-error row.
func TestKernelPromoteMissingSlotKnownGoodDiscards16441(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	delete(f.entries, SlotB)
	f.running = "6.18.5-10-generic"

	outcome, err := r.Promote()
	if err != nil {
		t.Fatalf("#16441: missing slot on known-good boot must discard without reboot, got %v", err)
	}
	if outcome.Outcome != RollOutcomeDiscarded || f.lastRoll.Outcome != RollOutcomeDiscarded {
		t.Fatalf("#16441: outcome/record = %q/%q, want discarded (not reverted)",
			outcome.Outcome, f.lastRoll.Outcome)
	}
	if contains(f.calls, "bootorder-front:0004") {
		t.Fatal("#16441: must not promote when the candidate slot is missing")
	}
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateInit {
		t.Fatalf("#16441: journal not cleared on known-good discard (state=%s)", j.State)
	}
}

// BootEntries fails while the CANDIDATE is running: revert stays mandatory
// (no fail-open weakening). The candidate cannot be promoted — its Boot####
// id is unknowable for the durable BootOrder reorder — so it takes the
// controlled revert, and the #14165 prune deferral protects the running
// kernel's files.
func TestKernelPromoteBootEntriesErrCandidateReverts16441(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.entriesErr = fmt.Errorf("efibootmgr timed out: context deadline exceeded")
	f.running = "6.18.5-12-generic" // the candidate IS running
	f.verifyPass = true
	f.beaconPass = true

	_, err := r.Promote()
	if !errorsIsReverted(err) {
		t.Fatalf("#16441: candidate-running BootEntries failure must revert, got %v", err)
	}
	if f.lastRoll.Outcome != RollOutcomeReverted {
		t.Fatalf("#16441: last-roll = %q, want reverted", f.lastRoll.Outcome)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#16441/#14165: pruned the RUNNING candidate on revert")
	}
	if contains(f.calls, "bootorder-front:0004") {
		t.Fatal("#16441: promoted a candidate whose boot entry was unreadable")
	}
}

// Candidate slot vanished from NVRAM while the CANDIDATE is running: same
// controlled revert as the BootEntries-error row.
func TestKernelPromoteMissingSlotCandidateReverts16441(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	delete(f.entries, SlotB)
	f.running = "6.18.5-12-generic"
	f.verifyPass = true
	f.beaconPass = true

	_, err := r.Promote()
	if !errorsIsReverted(err) {
		t.Fatalf("#16441: candidate-running missing slot must revert, got %v", err)
	}
	if f.lastRoll.Outcome != RollOutcomeReverted {
		t.Fatalf("#16441: last-roll = %q, want reverted", f.lastRoll.Outcome)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#16441/#14165: pruned the RUNNING candidate on revert")
	}
}

// BootEntries fails and RunningKernel is also unreadable: indeterminate.
// Fail closed — no prune, no reboot (non-revert error), journal preserved so
// the next boot re-runs the gate.
func TestKernelPromoteBootEntriesErrIndeterminate16441(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.entriesErr = fmt.Errorf("efibootmgr timed out: context deadline exceeded")
	f.runningErr = fmt.Errorf("uname -r failure")

	_, err := r.Promote()
	if err == nil {
		t.Fatal("#16441: indeterminate boot state must surface an error, not proceed as healthy")
	}
	if errorsIsReverted(err) {
		t.Fatalf("#16441: indeterminate must NOT be a revert (exit-3 reboot-loop risk), got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#16441: pruned the candidate while unable to prove we are off it")
	}
	if f.lastRollWrites != 0 {
		t.Fatalf("#16441: indeterminate must not record a roll outcome, got %d writes (%q)",
			f.lastRollWrites, f.lastRoll.Outcome)
	}
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateArmed {
		t.Fatalf("#16441: journal not preserved on indeterminate state (state=%s)", j.State)
	}
}

// Candidate slot vanished and RunningKernel is unreadable: same indeterminate
// fail-closed outcome as the BootEntries-error row.
func TestKernelPromoteMissingSlotIndeterminate16441(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	delete(f.entries, SlotB)
	f.runningErr = fmt.Errorf("uname -r failure")

	_, err := r.Promote()
	if err == nil {
		t.Fatal("#16441: indeterminate boot state must surface an error, not proceed as healthy")
	}
	if errorsIsReverted(err) {
		t.Fatalf("#16441: indeterminate must NOT be a revert (exit-3 reboot-loop risk), got %v", err)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Fatal("#16441: pruned the candidate while unable to prove we are off it")
	}
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateArmed {
		t.Fatalf("#16441: journal not preserved on indeterminate state (state=%s)", j.State)
	}
}
