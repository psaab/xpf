package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corruptKernelJournal15170 writes bytes that loadKernelJournal cannot
// parse at the temp kernel journal path, modelling storage corruption of
// /var/lib/xpf/kernel-upgrade.state (fsatomic makes torn writes unlikely;
// corruption/EIO is the narrow trigger B17-01 names).
func corruptKernelJournal15170(t *testing.T, journalPath string) {
	t.Helper()
	if err := os.WriteFile(journalPath, []byte("{corrupt-kernel-journal"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func countCall15170(fs *fakeSystem, name string) int {
	n := 0
	for _, c := range fs.calls {
		if c == name {
			n++
		}
	}
	return n
}

// TestCorruptKernelJournal_RefusedBeforeStop_15170 is the B17-01 forward
// cell: a corrupt kernel journal must refuse the cut BEFORE StopUnit.
//
// RED on base: 6d ran only inside flip(), after STOP, so Run stopped the
// daemon, failed at 6d, auto-rolled back (re-running 6d against the same
// corrupt journal), failed again there, and returned with unitRunning=false.
func TestCorruptKernelJournal_RefusedBeforeStop_15170(t *testing.T) {
	jp := useTempKernelJournal6639(t)
	corruptKernelJournal15170(t, jp)

	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("Run must refuse when the kernel journal is corrupt")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") ||
		!strings.Contains(err.Error(), "kernel") {
		t.Fatalf("error = %v, want a refuse-before-STOP kernel-arm refusal", err)
	}
	if countCall15170(fs, "stop") != 0 {
		t.Fatalf("StopUnit ran despite the pre-STOP refusal (calls=%v)", fs.calls)
	}
	if !fs.unitRunning {
		t.Fatal("daemon left offline after a pre-STOP refusal")
	}
	if got, rerr := r.readCurrentVersion(); rerr != nil || got != "1.0.0" {
		t.Fatalf("current = %q (err=%v), want untouched 1.0.0", got, rerr)
	}
}

// TestCorruptKernelJournal_AutoRollbackRestartsPrevious_15170 is the
// B17-01 recovery cell. The journal is VALID (ARMED) when the forward cut
// passes its pre-STOP probe and stops the daemon; it is then corrupted
// (modelling corruption landing in the STOP->FLIP window) so the forward
// 6d fails — and the auto-rollback re-flip must NOT fail on the same 6d:
// it must re-flip to 1.0.0 and StartUnit, ending with unitRunning=true on
// 1.0.0. The corruption is injected from the fake's StopUnit hook, which
// runs at STOP entry — the first instant the defect window opens.
//
// RED on base: the rollback's flip() re-ran 6d against the corrupt journal,
// rollback() returned before StartUnit, and the daemon stayed offline.
func TestCorruptKernelJournal_AutoRollbackRestartsPrevious_15170(t *testing.T) {
	jp := useTempKernelJournal6639(t)

	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	oldBin := filepath.Join(cfg.VersionsDir, "1.0.0", "xpfd")
	armKernelCandidate6639(t, jp, oldBin)

	fs.stopHook = func() { corruptKernelJournal15170(t, jp) }

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("Run must report the failed cut (a flip failure is never a successful cut)")
	}
	if !fs.unitRunning {
		t.Fatalf("daemon left offline after auto-rollback (calls=%v)", fs.calls)
	}
	if got, rerr := r.readCurrentVersion(); rerr != nil || got != "1.0.0" {
		t.Fatalf("current = %q (err=%v), want rolled-back 1.0.0", got, rerr)
	}
	if countCall15170(fs, "start") == 0 {
		t.Fatalf("StartUnit never ran on the rollback path (calls=%v)", fs.calls)
	}
}

// TestCorruptKernelJournal_OperatorRollbackRestartsPrevious_15170 covers
// the `upgrade --rollback` leg (rollback.go executeRollback): with a
// corrupt kernel journal its re-flip must still start the target daemon.
// No candidate is armed here — the journal cannot even be read — so this
// leg exercises the tolerant re-flip, not the pre-STOP probe (RollbackTo
// has no STOP to refuse before that is not already its own).
//
// RED on base: executeRollback's flip() failed at 6d and returned before
// StartUnit with the daemon down.
func TestCorruptKernelJournal_OperatorRollbackRestartsPrevious_15170(t *testing.T) {
	jp := useTempKernelJournal6639(t)
	corruptKernelJournal15170(t, jp)

	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	if err := fx.r.RollbackTo("", RollbackOptions{}); err != nil {
		t.Fatalf("RollbackTo: %v", err)
	}
	if !fx.fs.unitRunning {
		t.Fatalf("operator rollback left the daemon offline (calls=%v)", fx.fs.calls)
	}
	if got := currentTarget(t, fx.cfg); got != "1.0.0" {
		t.Fatalf("current -> %q, want 1.0.0", got)
	}
}
