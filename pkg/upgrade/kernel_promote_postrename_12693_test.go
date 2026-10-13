package upgrade

import (
	"errors"
	"os"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #12693 — verifyAndPromote's PROMOTED write returns *PostRenameSyncError: the
// rename landed (journal visibly PROMOTED) but the directory fsync failed.
// BootOrder was already reordered candidate-first, the watchdog disarmed, the
// promotion marker and durable last-roll record written, and the trial passes
// every gate. Returning that typed error maps Promote to infra exit 1 and
// leaves a durable PROMOTED journal + cleared-boot-next state behind, while
// its sibling ARMED/backstep/restore writes classify the same landed rename as
// success (#12549, #12162 F1). The PROMOTED write must be classified the same
// way: proceed to clear the journal and report the completed promotion, with
// only durability across power loss unknown.
func TestPromotePromotedPostRenameSyncProceedsToClear_12693(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = true

	var restore func()
	promotedWrites := 0
	t.Cleanup(func() {
		if restore != nil {
			restore()
		}
	})
	origLogf := r.cfg.Logf
	r.cfg.Logf = func(format string, args ...any) {
		origLogf(format, args...)
		if len(args) != 0 && args[0] == KernelStatePromoted {
			promotedWrites++
			restore = fsatomic.SetAfterRenameSyncDirForTesting(func(string) error {
				return errors.New("injected promoted-write directory fsync failure")
			})
		}
	}

	outcome, err := r.Promote()
	if restore != nil {
		restore()
		restore = nil
	}
	if err != nil {
		t.Fatalf("Promote error = %v, want landed PROMOTED write to complete the promotion", err)
	}
	if promotedWrites != 1 {
		t.Fatalf("PROMOTED transitions = %d, want exactly one", promotedWrites)
	}
	if outcome.Outcome != RollOutcomePromoted {
		t.Errorf("outcome = %q, want %q", outcome.Outcome, RollOutcomePromoted)
	}
	if f.order[0] != "0004" {
		t.Errorf("BootOrder front = %q, want 0004 (promoted candidate)", f.order[0])
	}
	if f.promotionMarker != "6.18.5-12-generic" {
		t.Errorf("promotion marker = %q, want candidate version", f.promotionMarker)
	}
	if f.lastRollWrites != 1 || f.lastRoll.Outcome != RollOutcomePromoted {
		t.Errorf("lastRoll writes=%d outcome=%q, want one promoted record", f.lastRollWrites, f.lastRoll.Outcome)
	}
	if f.wdArmed {
		t.Error("watchdog still armed after promote")
	}
	if _, statErr := os.Stat(r.cfg.JournalPath); !os.IsNotExist(statErr) {
		j, loadErr := r.loadKernelJournal()
		t.Errorf("journal not cleared after landed PROMOTED write (state=%s loadErr=%v statErr=%v)",
			j.State, loadErr, statErr)
	}
	// Terminal: a second Promote is a clean no-op, not a re-trial.
	outcome2, err := r.Promote()
	if err != nil {
		t.Fatalf("second Promote = %v, want clean no-op after clear", err)
	}
	if outcome2.Outcome != "" {
		t.Errorf("second Promote outcome = %q, want no-op", outcome2.Outcome)
	}
	if f.lastRollWrites != 1 {
		t.Errorf("lastRoll writes = %d after second Promote, want exactly one", f.lastRollWrites)
	}
}

// #12693 fail-closed converse: the PROMOTED write fails because the rename
// ITSELF fails, so PROMOTED never landed. That error is not a
// *PostRenameSyncError. Treating it as landed would report a completed
// promotion (and clear nothing / mislead the orchestrator) while the durable
// journal still says ARMED. Promote must return the rename error, leave the
// journal ARMED, and preserve the completed side effects it cannot undo
// (BootOrder reorder, marker, last-roll) honestly by surfacing the failure.
func TestPromotePromotedRenameFailureSurfaces_12693(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = true

	renameErr := errors.New("injected promoted-write rename failure")
	var restore func()
	promotedWrites := 0
	t.Cleanup(func() {
		if restore != nil {
			restore()
		}
	})
	origLogf := r.cfg.Logf
	r.cfg.Logf = func(format string, args ...any) {
		origLogf(format, args...)
		if len(args) != 0 && args[0] == KernelStatePromoted {
			promotedWrites++
			if promotedWrites == 1 {
				restore = fsatomic.SetRenameFileForTesting(func(string, string) error {
					return renameErr
				})
			}
		}
	}

	_, err := r.Promote()
	if restore != nil {
		restore()
		restore = nil
	}
	if !errors.Is(err, renameErr) {
		t.Fatalf("Promote error = %v, want the refused PROMOTED rename failure", err)
	}
	var post *fsatomic.PostRenameSyncError
	if errors.As(err, &post) {
		t.Fatalf("Promote error = %v classifies as PostRenameSyncError; the rename never landed", err)
	}
	if promotedWrites != 1 {
		t.Fatalf("PROMOTED transitions = %d, want exactly one", promotedWrites)
	}
	j, loadErr := r.loadKernelJournal()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if j.State != KernelStateArmed {
		t.Errorf("durable journal = state %s, want ARMED (PROMOTED never landed)", j.State)
	}
	if f.order[0] != "0004" {
		t.Errorf("BootOrder front = %q, want 0004 (reorder already succeeded)", f.order[0])
	}
}
