package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #12554: deterministic removal failures use a non-empty directory at the
// arm-record path. Unlike permission-based failures, ENOTEMPTY also works as
// root. The caller swaps this in after recordPromoteBinary has written the
// sidecar and before the unwind tries to remove it.
func pinArmRecordRemovalFailure(t *testing.T, journalPath string) error {
	t.Helper()
	path := ArmRecordPath(journalPath)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove written arm record: %v", err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("replace arm record with directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "child"), []byte("x"), 0o644); err != nil {
		t.Fatalf("make arm-record directory non-empty: %v", err)
	}
	err := os.Remove(path)
	if err == nil {
		t.Fatalf("removing non-empty arm-record directory unexpectedly succeeded")
	}
	return errors.Unwrap(err)
}

func cleanArmRecordRemovalFailure(journalPath string) {
	path := ArmRecordPath(journalPath)
	_ = os.Remove(path)
}

func assertRecordRemovalReported(t *testing.T, err, removalErr error, phrase string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), phrase) {
		t.Errorf("Arm error = %v, want record-removal report %q", err, phrase)
	}
	if !errors.Is(err, removalErr) {
		t.Errorf("Arm error = %v, want wrapped record-removal error %v", err, removalErr)
	}
}

// K1: restore and watchdog disarm both fail. Removing this reporting branch
// returns its sibling error without the stale-record failure.
func TestArmReportsRecordRemovalFailureAfterRestoreAndDisarmFailure_12554(t *testing.T) {
	f := newFakeKernelSystem()
	rebootErr := errors.New("reboot failed")
	clearErr := errors.New("BootNext clear failed")
	disarmErr := errors.New("watchdog disarm failed")
	f.rebootErr, f.clearBootNextErr, f.disarmWatchdogErr = rebootErr, clearErr, disarmErr
	r := newKernelRunner(t, f)
	journalPath := r.cfg.JournalPath
	armedWrites, swapped := 0, false
	var removalErr error
	r.cfg.Logf = func(format string, args ...any) {
		r.cfg.JournalPath = journalPath
		if strings.Contains(format, "-> %s") && len(args) > 0 && args[0] == KernelStateArmed {
			armedWrites++
			if armedWrites == 2 {
				removalErr = pinArmRecordRemovalFailure(t, journalPath)
				swapped = true
				r.cfg.JournalPath = "/proc/self/12554-k1/restore.state"
			}
		}
	}
	t.Cleanup(func() { cleanArmRecordRemovalFailure(journalPath) })

	err := r.Arm("6.18.5-12-generic")
	r.cfg.JournalPath = journalPath
	if !swapped {
		t.Fatalf("did not inject record-removal failure (Arm error %v)", err)
	}
	if !errors.Is(err, rebootErr) || !errors.Is(err, clearErr) || !errors.Is(err, disarmErr) {
		t.Errorf("Arm error = %v, want reboot, clear, and disarm causes", err)
	}
	assertRecordRemovalReported(t, err, removalErr, "stale arm record could not be removed")
}

// K2: restore fails but watchdog disarm succeeds; this is the sibling
// reporting branch and must retain the same record-removal cause.
func TestArmReportsRecordRemovalFailureAfterRestoreWithDisarmSuccess_12554(t *testing.T) {
	f := newFakeKernelSystem()
	rebootErr := errors.New("reboot failed")
	clearErr := errors.New("BootNext clear failed")
	f.rebootErr, f.clearBootNextErr = rebootErr, clearErr
	r := newKernelRunner(t, f)
	journalPath := r.cfg.JournalPath
	armedWrites, swapped := 0, false
	var removalErr error
	r.cfg.Logf = func(format string, args ...any) {
		r.cfg.JournalPath = journalPath
		if strings.Contains(format, "-> %s") && len(args) > 0 && args[0] == KernelStateArmed {
			armedWrites++
			if armedWrites == 2 {
				removalErr = pinArmRecordRemovalFailure(t, journalPath)
				swapped = true
				r.cfg.JournalPath = "/proc/self/12554-k2/restore.state"
			}
		}
	}
	t.Cleanup(func() { cleanArmRecordRemovalFailure(journalPath) })

	err := r.Arm("6.18.5-12-generic")
	r.cfg.JournalPath = journalPath
	if !swapped {
		t.Fatalf("did not inject record-removal failure (Arm error %v)", err)
	}
	if !errors.Is(err, rebootErr) || !errors.Is(err, clearErr) {
		t.Errorf("Arm error = %v, want reboot and clear causes", err)
	}
	assertRecordRemovalReported(t, err, removalErr, "stale arm record could not be removed")
}

// K3: BootNext is cleared and disarm is attempted after failed reboot; this
// exit must report a failed stale-record removal too.
func TestArmReportsRecordRemovalFailureAfterBootNextCleared_12554(t *testing.T) {
	f := newFakeKernelSystem()
	rebootErr := errors.New("reboot failed")
	f.rebootErr = rebootErr
	r := newKernelRunner(t, f)
	journalPath := r.cfg.JournalPath
	swapped := false
	var removalErr error
	r.cfg.Logf = func(format string, _ ...any) {
		r.cfg.JournalPath = journalPath
		if !swapped && strings.Contains(format, "rebooting (one-shot)") {
			removalErr = pinArmRecordRemovalFailure(t, journalPath)
			swapped = true
		}
	}
	t.Cleanup(func() { cleanArmRecordRemovalFailure(journalPath) })

	err := r.Arm("6.18.5-12-generic")
	r.cfg.JournalPath = journalPath
	if !swapped {
		t.Fatalf("did not inject record-removal failure (Arm error %v)", err)
	}
	if !errors.Is(err, rebootErr) {
		t.Errorf("Arm error = %v, want original reboot error", err)
	}
	assertRecordRemovalReported(t, err, removalErr, "stale arm record could not be removed")
}
