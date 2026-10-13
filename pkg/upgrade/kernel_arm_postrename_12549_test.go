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
