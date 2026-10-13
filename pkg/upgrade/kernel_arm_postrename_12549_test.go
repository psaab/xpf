package upgrade

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// #12549 — armCandidate's ARMED write returns *PostRenameSyncError: the rename
// landed (journal visibly ARMED, BootNext confirmed queued) but the directory
// fsync failed. Treating that as arm failure clears BootNext and disarms the
// watchdog against a visible ARMED journal — Arm then refuses forever
// (>= ARMED) while no trial is actually queued: the false-ARMED trap.
// armCandidate must classify the error as landed (same shape as the #12162 F1
// backstep/restore branches) and proceed to the reboot.
func TestArmCandidateArmedPostRenameSyncProceedsToReboot_12549(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	var restore func()
	armedWrites := 0
	t.Cleanup(func() {
		if restore != nil {
			restore()
		}
	})
	r.cfg.Logf = func(_ string, args ...any) {
		if restore != nil {
			restore()
			restore = nil
		}
		if len(args) != 0 && args[0] == KernelStateArmed {
			armedWrites++
			restore = fsatomic.SetAfterRenameSyncDirForTesting(func(string) error {
				return errors.New("injected armed-write directory fsync failure")
			})
		}
	}

	err := r.Arm("6.18.5-12-generic")
	if restore != nil {
		restore()
		restore = nil
	}
	if err != nil {
		t.Fatalf("Arm error = %v, want landed ARMED write to proceed to reboot", err)
	}
	if armedWrites != 1 {
		t.Fatalf("ARMED transitions = %d, want exactly one", armedWrites)
	}
	j, loadErr := r.loadKernelJournal()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if j.State != KernelStateArmed || j.BootID == "" || j.BootID != f.bootNext {
		t.Errorf("durable journal = state %s BootID %q BootNext %q; want matching ARMED trial",
			j.State, j.BootID, f.bootNext)
	}
	armed, _, err := r.IsArmed()
	if err != nil || !armed {
		t.Errorf("IsArmed = %v err=%v, want true/nil for the landed ARMED journal", armed, err)
	}
	if !f.wdArmed || f.disarmWatchdogCalls != 0 {
		t.Errorf("watchdogArmed=%v disarmCalls=%d; want protected trial retained",
			f.wdArmed, f.disarmWatchdogCalls)
	}
	if f.bootNext == "" || !f.rebooted {
		t.Errorf("BootNext=%q rebooted=%v; want queued one-shot and reboot", f.bootNext, f.rebooted)
	}
	if !contains(f.calls, "reboot") {
		t.Error("Reboot was not called after the landed ARMED write")
	}
	rearmErr := r.Arm("6.18.5-12-generic")
	if rearmErr == nil {
		t.Error("Arm accepted a second attempt while the landed ARMED trial is in flight")
	}
	if f.bootNext != j.BootID || !f.wdArmed || f.disarmWatchdogCalls != 0 {
		t.Errorf("after rejected re-arm: BootNext=%q watchdogArmed=%v disarmCalls=%d; want original trial retained",
			f.bootNext, f.wdArmed, f.disarmWatchdogCalls)
	}
	record, recordErr := ReadArmRecord(r.cfg.JournalPath)
	if recordErr != nil || record != j.PromoteBinary {
		t.Errorf("arm record = %q, err=%v; want the ARMED promote record %q",
			record, recordErr, j.PromoteBinary)
	}
}

// #12549 fail-closed converse: the ARMED write fails because the rename ITSELF
// fails, so the ARMED journal never landed. That error is not a
// *PostRenameSyncError. Treating it as landed would reboot into the candidate
// while the durable journal still says ARMING, which neither IsArmed nor the
// boot-time promotion gate treats as a trial in flight. armCandidate must
// refuse: Arm returns the rename error, the journal stays ARMING, BootNext is
// cleared, nothing reboots, and the watchdog is disarmed. The refusal must
// leave a clean retry: Arm re-arms from ARMING (contrast the landed case
// above, where a second Arm is rejected).
func TestArmCandidateArmedRenameFailureRefuses_12549(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	renameErr := errors.New("injected armed-write rename failure")
	var restore func()
	armedWrites := 0
	t.Cleanup(func() {
		if restore != nil {
			restore()
		}
	})
	r.cfg.Logf = func(_ string, args ...any) {
		if restore != nil {
			restore()
			restore = nil
		}
		if len(args) != 0 && args[0] == KernelStateArmed {
			armedWrites++
			if armedWrites == 1 {
				restore = fsatomic.SetRenameFileForTesting(func(string, string) error {
					return renameErr
				})
			}
		}
	}

	err := r.Arm("6.18.5-12-generic")
	if restore != nil {
		restore()
		restore = nil
	}
	if !errors.Is(err, renameErr) {
		t.Fatalf("Arm error = %v, want the refused ARMED rename failure", err)
	}
	var post *fsatomic.PostRenameSyncError
	if errors.As(err, &post) {
		t.Fatalf("Arm error = %v classifies as PostRenameSyncError; the rename never landed", err)
	}
	if armedWrites != 1 {
		t.Fatalf("ARMED transitions = %d, want exactly one", armedWrites)
	}
	j, loadErr := r.loadKernelJournal()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if j.State != KernelStateArming || j.BootID != "" {
		t.Errorf("durable journal = state %s BootID %q; want ARMING without BootID", j.State, j.BootID)
	}
	armed, _, err := r.IsArmed()
	if err != nil || armed {
		t.Errorf("IsArmed = %v err=%v, want false/nil for the unlanded ARMED write", armed, err)
	}
	if f.bootNext != "" || !contains(f.calls, "bootnext-clear") {
		t.Errorf("BootNext=%q calls=%v; want the queued one-shot cleared", f.bootNext, f.calls)
	}
	if f.rebooted || contains(f.calls, "reboot") {
		t.Errorf("rebooted=%v calls=%v; want no reboot after the refused arm", f.rebooted, f.calls)
	}
	if f.armWatchdogCalls != 1 || f.wdArmed || f.disarmWatchdogCalls != 1 {
		t.Errorf("armCalls=%d watchdogArmed=%v disarmCalls=%d; want armed once, then disarmed once",
			f.armWatchdogCalls, f.wdArmed, f.disarmWatchdogCalls)
	}

	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("retry Arm from ARMING = %v, want a clean re-arm", err)
	}
	j, loadErr = r.loadKernelJournal()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if j.State != KernelStateArmed || j.BootID == "" || j.BootID != f.bootNext {
		t.Errorf("after retry: journal = state %s BootID %q BootNext %q; want matching ARMED trial",
			j.State, j.BootID, f.bootNext)
	}
	if !f.wdArmed || !f.rebooted {
		t.Errorf("after retry: watchdogArmed=%v rebooted=%v; want protected trial and reboot",
			f.wdArmed, f.rebooted)
	}
}
