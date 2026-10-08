package upgrade

import (
	"errors"
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
