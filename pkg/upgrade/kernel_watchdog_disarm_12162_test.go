package upgrade

import (
	"errors"
	"strings"
	"testing"
)

// #12162 — a failed kernel arm leaves the hardware watchdog counting toward a
// spurious reset.
//
// armCandidate acquires the watchdog (ArmWatchdog) and then walks several
// fallible steps (persist ARMING, SetBootNext, BootNext readback, record the
// promote binary, persist ARMED). Every post-acquisition failure return exited
// WITHOUT DisarmWatchdog: the shared cleanup helper only cleared BootNext.
// Likewise Arm returned a Reboot() error with the watchdog still armed.
//
// The retained fake models arm/disarm CALLS, not Linux driver behavior or
// reset timing: the observable here is the fake's wdArmed state (mirroring
// the production Acquire-vs-Disarm pairing), never a physical reset window.
// No live watchdog device is exercised.

func TestArmDisarmsWatchdogOnPostAcquisitionFailures_12162(t *testing.T) {
	cases := []struct {
		name           string
		failTransition KernelState
		stage          func(t *testing.T, f *fakeKernelSystem)
	}{
		{
			name:           "ARMING persist fails",
			failTransition: KernelStateArming,
		},
		{
			name: "SetBootNext fails",
			stage: func(t *testing.T, f *fakeKernelSystem) {
				f.setBootNextErr = errors.New("efibootmgr: cannot write efivarfs")
			},
		},
		{
			name: "BootNext readback fails",
			stage: func(t *testing.T, f *fakeKernelSystem) {
				f.getBootNextErr = errors.New("efivarfs readback raced / unavailable")
			},
		},
		{
			name: "BootNext readback disagrees",
			stage: func(t *testing.T, f *fakeKernelSystem) {
				f.getBootNextRet = "Boot9999"
			},
		},
		{
			name: "record promote binary fails",
			stage: func(t *testing.T, f *fakeKernelSystem) {
				withArmingBinaryResolver(t, func() (string, error) {
					return "", errors.New("no live xpfd to record")
				})
			},
		},
		{
			name:           "ARMED persist fails",
			failTransition: KernelStateArmed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeKernelSystem()
			r := newKernelRunner(t, f)
			j := &KernelJournal{
				State:            KernelStateInstalled,
				CandidateVersion: "6.18.5-12-generic",
				KnownGoodVersion: "6.18.5-10-generic",
				ActiveSlot:       SlotA,
				InactiveSlot:     SlotB,
			}
			if tc.stage != nil {
				tc.stage(t, f)
			}
			if tc.failTransition != "" {
				r.cfg.Logf = func(_ string, args ...any) {
					if len(args) != 0 && args[0] == tc.failTransition {
						// ktransition logs immediately before the durable write.
						// Moving only the failing transition to an invalid /proc
						// path deterministically injects that write failure even
						// when the test runner has permission to chmod its files.
						r.cfg.JournalPath = "/proc/self/12162/kernel-upgrade.state"
					}
				}
			}

			if err := r.armCandidate(j); err == nil {
				t.Fatal("premise broken: the staged arm failure must be returned")
			}
			if f.armWatchdogCalls != 1 {
				t.Fatalf("ArmWatchdog calls = %d, want exactly one successful acquisition", f.armWatchdogCalls)
			}
			if f.disarmWatchdogCalls != 1 {
				t.Errorf("DisarmWatchdog calls = %d, want exactly one after failed arm", f.disarmWatchdogCalls)
			}
			if f.wdArmed {
				t.Error("watchdog still armed after a failed arm")
			}
		})
	}
}

func TestArmDisarmsWatchdogWhenRebootFails_12162(t *testing.T) {
	f := newFakeKernelSystem()
	rebootErr := errors.New("systemctl reboot: exit 1")
	f.rebootErr = rebootErr
	r := newKernelRunner(t, f)

	err := r.Arm("6.18.5-12-generic")
	if !errors.Is(err, rebootErr) {
		t.Fatalf("Arm error = %v, want original Reboot error %v", err, rebootErr)
	}
	if f.armWatchdogCalls != 1 {
		t.Fatalf("ArmWatchdog calls = %d, want exactly one successful acquisition", f.armWatchdogCalls)
	}
	if f.disarmWatchdogCalls != 1 {
		t.Errorf("DisarmWatchdog calls = %d, want exactly one after failed Reboot", f.disarmWatchdogCalls)
	}
	if f.wdArmed {
		t.Error("watchdog still armed after Reboot failed")
	}
	if f.bootNext != "" {
		t.Errorf("BootNext = %q after failed Reboot, want it cleared", f.bootNext)
	}
	if !contains(f.calls, "bootnext-clear") {
		t.Error("ClearBootNext was not called after failed Reboot")
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State != KernelStateArming || j.BootID != "" {
		t.Errorf("journal after failed Reboot = state %s, BootID %q; want ARMING with no BootID", j.State, j.BootID)
	}
	if armed, _, err := r.IsArmed(); err != nil {
		t.Fatal(err)
	} else if armed {
		t.Error("IsArmed() is true after failed Reboot was unwound to ARMING")
	}

	f.rebootErr = nil
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("retry from ARMING: %v", err)
	}
	if !f.rebooted {
		t.Error("retry from ARMING did not reboot after re-arming")
	}
	if f.armWatchdogCalls != 2 {
		t.Errorf("ArmWatchdog calls after retry = %d, want 2", f.armWatchdogCalls)
	}
	j, err = r.loadKernelJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State != KernelStateArmed || j.BootID == "" || f.bootNext != j.BootID {
		t.Errorf("retry state = %s, journal BootID = %q, BootNext = %q; want ARMED with matching nonempty BootID",
			j.State, j.BootID, f.bootNext)
	}
}

func TestArmKeepsProtectedTrialWhenRebootBackstepPersistFails_12162(t *testing.T) {
	f := newFakeKernelSystem()
	rebootErr := errors.New("systemctl reboot: exit 1")
	f.rebootErr = rebootErr
	r := newKernelRunner(t, f)
	journalPath := r.cfg.JournalPath
	armingTransitions := 0
	r.cfg.Logf = func(_ string, args ...any) {
		if len(args) != 0 && args[0] == KernelStateArming {
			armingTransitions++
			if armingTransitions == 2 {
				// The first ARMING write is the normal arm path. Fail only the
				// failed-Reboot backstep, after ARMED has been durably recorded.
				r.cfg.JournalPath = "/proc/self/12162/reboot-backstep.state"
			}
		}
	}

	err := r.Arm("6.18.5-12-generic")
	r.cfg.JournalPath = journalPath
	if !errors.Is(err, rebootErr) {
		t.Fatalf("Arm error = %v, want original Reboot error %v", err, rebootErr)
	}
	if err == nil || !strings.Contains(err.Error(), "journal step back to ARMING failed") ||
		!strings.Contains(err.Error(), "journal remains ARMED") ||
		!strings.Contains(err.Error(), "BootNext") ||
		!strings.Contains(err.Error(), "hardware watchdog still armed") ||
		!strings.Contains(err.Error(), "host will reset into the candidate trial") ||
		!strings.Contains(err.Error(), "watchdog timeout") {
		t.Fatalf("Arm error = %v, want explicit protected-trial state and timeout guidance", err)
	}
	if armingTransitions != 2 {
		t.Fatalf("ARMING transitions = %d, want normal arm plus failed-Reboot backstep", armingTransitions)
	}
	if f.bootNext == "" || !f.wdArmed || f.disarmWatchdogCalls != 0 {
		t.Errorf("BootNext=%q watchdogArmed=%v disarmCalls=%d; want queued BootNext and armed watchdog untouched",
			f.bootNext, f.wdArmed, f.disarmWatchdogCalls)
	}
	j, loadErr := r.loadKernelJournal()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if j.State != KernelStateArmed || j.BootID != f.bootNext {
		t.Errorf("durable journal = state %s BootID %q, BootNext %q; want ARMED matching queued BootNext",
			j.State, j.BootID, f.bootNext)
	}
	if armed, _, loadErr := r.IsArmed(); loadErr != nil {
		t.Fatal(loadErr)
	} else if !armed {
		t.Error("IsArmed() is false despite the preserved watchdog-protected trial")
	}
}

func TestArmRetainsArmedJournalWhenBootNextClearFailsAfterReboot_12162(t *testing.T) {
	f := newFakeKernelSystem()
	rebootErr := errors.New("systemctl reboot: exit 1")
	clearErr := errors.New("efibootmgr: cannot clear BootNext")
	f.rebootErr = rebootErr
	f.clearBootNextErr = clearErr
	r := newKernelRunner(t, f)

	err := r.Arm("6.18.5-12-generic")
	if !errors.Is(err, rebootErr) || !errors.Is(err, clearErr) {
		t.Fatalf("Arm error = %v, want Reboot and BootNext-clear causes", err)
	}
	if f.bootNext == "" || !contains(f.calls, "bootnext-clear") {
		t.Errorf("BootNext=%q; want failed clear call to leave the queued id in place", f.bootNext)
	}
	if !f.wdArmed || f.disarmWatchdogCalls != 0 {
		t.Errorf("watchdogArmed=%v disarmCalls=%d; want watchdog left armed until BootNext is cleared",
			f.wdArmed, f.disarmWatchdogCalls)
	}
	j, loadErr := r.loadKernelJournal()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if j.State != KernelStateArmed || j.BootID != f.bootNext {
		t.Errorf("journal = state %s BootID %q, BootNext %q; want ARMED matching queued BootNext",
			j.State, j.BootID, f.bootNext)
	}
	if armed, _, loadErr := r.IsArmed(); loadErr != nil {
		t.Fatal(loadErr)
	} else if !armed {
		t.Error("IsArmed() is false while BootNext remains queued")
	}
	if !strings.Contains(err.Error(), "efibootmgr --delete-bootnext") ||
		!strings.Contains(err.Error(), "journal remains ARMED") {
		t.Errorf("Arm error = %v, want manual-clear command and retained journal state", err)
	}
}

func TestArmReportsWatchdogDisarmFailure_12162(t *testing.T) {
	f := newFakeKernelSystem()
	armErr := errors.New("efibootmgr: cannot write efivarfs")
	disarmErr := errors.New("watchdog magic-close failed")
	f.setBootNextErr = armErr
	f.disarmWatchdogErr = disarmErr
	r := newKernelRunner(t, f)
	j := &KernelJournal{
		State:            KernelStateInstalled,
		CandidateVersion: "6.18.5-12-generic",
		KnownGoodVersion: "6.18.5-10-generic",
		ActiveSlot:       SlotA,
		InactiveSlot:     SlotB,
	}

	err := r.armCandidate(j)
	if !errors.Is(err, armErr) {
		t.Errorf("arm error = %v, want original failure %v", err, armErr)
	}
	if !errors.Is(err, disarmErr) {
		t.Errorf("arm error = %v, want watchdog cleanup failure %v", err, disarmErr)
	}
	if f.disarmWatchdogCalls != 1 {
		t.Errorf("DisarmWatchdog calls = %d, want exactly one", f.disarmWatchdogCalls)
	}
}

// TestSuccessfulArmKeepsWatchdogArmed_12162 is the OVER-DISARMING control: a
// successful arm MUST leave the watchdog armed — the trial boot relies on it
// to convert an early-boot hang into the reset that triggers the BootNext
// fallback. An implementation that disarmed unconditionally would pass every
// failure case above and STRAND every successful arm with no hang protection.
func TestSuccessfulArmKeepsWatchdogArmed_12162(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)

	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if !f.wdArmed {
		t.Error("successful arm disarmed the watchdog; the trial boot needs it armed")
	}
	if f.disarmWatchdogCalls != 0 {
		t.Errorf("DisarmWatchdog calls = %d after successful arm, want none", f.disarmWatchdogCalls)
	}
	if f.bootNext == "" {
		t.Error("successful arm cleared BootNext; the one-shot must survive")
	}
}

func TestArmDisarmsWatchdogOnStrictPartialAcquisition_12162(t *testing.T) {
	f := newFakeKernelSystem()
	f.armWatchdogErr = errors.New("watchdog WDIOC_SETTIMEOUT(600s): invalid argument")
	f.wdArmed = true // ArmWatchdog petted the device before returning its error.
	r := newKernelRunner(t, f)
	r.cfg.StrictWatchdog = true

	err := r.Arm("6.18.5-12-generic")
	if !errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("Arm error = %v, want strict-watchdog ErrKernelChannelUnavailable", err)
	}
	if f.disarmWatchdogCalls != 1 {
		t.Errorf("DisarmWatchdog calls = %d, want one after partial acquisition", f.disarmWatchdogCalls)
	}
	if f.wdArmed {
		t.Error("watchdog remained armed after strict partial-acquisition failure")
	}
	if f.bootNext != "" || f.rebooted {
		t.Errorf("strict partial failure set BootNext=%q or rebooted=%v", f.bootNext, f.rebooted)
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State != KernelStateInstalled {
		t.Errorf("journal state = %s, want INSTALLED after strict abort", j.State)
	}
}

func TestArmReportsDisarmFailureOnBootNextReadbackError_12162(t *testing.T) {
	f := newFakeKernelSystem()
	readErr := errors.New("efivarfs readback failed")
	disarmErr := errors.New("watchdog magic-close failed")
	f.getBootNextErr = readErr
	f.disarmWatchdogErr = disarmErr
	r := newKernelRunner(t, f)
	j := &KernelJournal{
		State:            KernelStateInstalled,
		CandidateVersion: "6.18.5-12-generic",
		KnownGoodVersion: "6.18.5-10-generic",
		ActiveSlot:       SlotA,
		InactiveSlot:     SlotB,
	}

	err := r.armCandidate(j)
	if !errors.Is(err, readErr) || !errors.Is(err, disarmErr) {
		t.Errorf("arm error = %v, want both readback and disarm causes", err)
	}
	if f.bootNext != "" {
		t.Errorf("BootNext = %q after readback failure, want it cleared", f.bootNext)
	}
	if !contains(f.calls, "bootnext-clear") {
		t.Error("ClearBootNext was not called after readback failure")
	}
	if f.disarmWatchdogCalls != 1 {
		t.Errorf("DisarmWatchdog calls = %d, want exactly one", f.disarmWatchdogCalls)
	}
}

func TestArmStillDisarmsWhenBootNextClearFails_12162(t *testing.T) {
	f := newFakeKernelSystem()
	readErr := errors.New("efivarfs readback failed")
	clearErr := errors.New("efibootmgr could not clear BootNext")
	disarmErr := errors.New("watchdog magic-close failed")
	f.getBootNextErr = readErr
	f.clearBootNextErr = clearErr
	f.disarmWatchdogErr = disarmErr
	r := newKernelRunner(t, f)
	j := &KernelJournal{
		State:            KernelStateInstalled,
		CandidateVersion: "6.18.5-12-generic",
		KnownGoodVersion: "6.18.5-10-generic",
		ActiveSlot:       SlotA,
		InactiveSlot:     SlotB,
	}

	err := r.armCandidate(j)
	if !errors.Is(err, readErr) || !errors.Is(err, clearErr) || !errors.Is(err, disarmErr) {
		t.Errorf("arm error = %v, want readback, BootNext-clear, and disarm causes", err)
	}
	if f.bootNext == "" || !contains(f.calls, "bootnext-clear") {
		t.Errorf("BootNext=%q; want failed clear call to leave the queued id in place", f.bootNext)
	}
	if f.disarmWatchdogCalls != 1 || !f.wdArmed {
		t.Errorf("DisarmWatchdog calls=%d watchdogArmed=%v; want a disarm attempt whose injected failure leaves it armed",
			f.disarmWatchdogCalls, f.wdArmed)
	}
}

func TestArmReportsDisarmFailureWhenRebootFails_12162(t *testing.T) {
	f := newFakeKernelSystem()
	rebootErr := errors.New("systemctl reboot: exit 1")
	disarmErr := errors.New("watchdog magic-close failed")
	f.rebootErr = rebootErr
	f.disarmWatchdogErr = disarmErr
	r := newKernelRunner(t, f)

	err := r.Arm("6.18.5-12-generic")
	if !errors.Is(err, rebootErr) || !errors.Is(err, disarmErr) {
		t.Errorf("Arm error = %v, want both Reboot and disarm causes", err)
	}
	if f.bootNext != "" {
		t.Errorf("BootNext = %q after failed Reboot, want it cleared", f.bootNext)
	}
	if !contains(f.calls, "bootnext-clear") {
		t.Error("ClearBootNext was not called after failed Reboot")
	}
	j, loadErr := r.loadKernelJournal()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if j.State != KernelStateArming || j.BootID != "" {
		t.Errorf("journal after failed Reboot = state %s, BootID %q; want ARMING with no BootID", j.State, j.BootID)
	}
}

func TestArmReportsDisarmFailureWhenARMINGPersistFails_12162(t *testing.T) {
	f := newFakeKernelSystem()
	disarmErr := errors.New("watchdog magic-close failed")
	f.disarmWatchdogErr = disarmErr
	r := newKernelRunner(t, f)
	r.cfg.Logf = func(_ string, args ...any) {
		if len(args) != 0 && args[0] == KernelStateArming {
			r.cfg.JournalPath = "/proc/self/12162/kernel-upgrade.state"
		}
	}
	j := &KernelJournal{
		State:            KernelStateInstalled,
		CandidateVersion: "6.18.5-12-generic",
		KnownGoodVersion: "6.18.5-10-generic",
		ActiveSlot:       SlotA,
		InactiveSlot:     SlotB,
	}

	err := r.armCandidate(j)
	if err == nil || !errors.Is(err, disarmErr) {
		t.Errorf("arm error = %v, want journal persist and disarm failures", err)
	}
	if f.disarmWatchdogCalls != 1 {
		t.Errorf("DisarmWatchdog calls = %d, want exactly one", f.disarmWatchdogCalls)
	}
}
