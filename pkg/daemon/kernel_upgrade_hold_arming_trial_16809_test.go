package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/upgrade"
)

// runnerWithSys returns a kernelRunnerFn seam whose KernelRunner reads the
// journal at path AND classifies boots against sys — the shape the
// production daemon constructs (one system surface for both). The #5682
// stubKernelSys seam cannot serve here: its embedded nil KernelSystem
// panics on the BootEntries/BootCurrent reads UnconfirmedTrial makes, which
// is exactly the surface a fail-closed classification must exercise for real.
func runnerWithSys(path string, sys upgrade.KernelSystem) func() (*upgrade.KernelRunner, error) {
	return func() (*upgrade.KernelRunner, error) {
		return upgrade.NewKernelRunner(upgrade.KernelConfig{JournalPath: path, Sys: sys})
	}
}

// #16809 — the daemon election hold gated on IsArmed (ARMED only), so a boot
// whose journal is stuck at ARMING with BootNext actually queued (process
// death between SetBootNext and the ARMED rename, or a landed-but-errored
// SetBootNext) ran an UNVERIFIED candidate election-eligible: no hold, and
// self-recovery could rejoin it. The hold now classifies on
// upgrade.TrialInFlight: ARMING + BootCurrent == the inactive slot's entry +
// running kernel == candidate acquires the candidate hold; ARMING on a
// positively known-good boot still acquires none (the #5847 interrupted-arm
// node must be able to rejoin), and unreadable boot evidence fails closed.
//
// fakeKernelSys (kernel_upgrade_hold_failclosed_5682_test.go) only models
// RunningKernel/ReadPromotionMarker, so these tests extend it with the boot
// entries / BootCurrent surface TrialInFlight reads.
type armingTrialKernelSys struct {
	fakeKernelSys
	entries      map[string]string
	entriesErr   error
	bootCurrent  string
	bootCurrentE error
}

func (f armingTrialKernelSys) BootEntries() (map[string]string, error) {
	if f.entriesErr != nil {
		return nil, f.entriesErr
	}
	cp := map[string]string{}
	for k, v := range f.entries {
		cp[k] = v
	}
	return cp, nil
}

func (f armingTrialKernelSys) BootCurrent() (string, error) {
	return f.bootCurrent, f.bootCurrentE
}

func TestHoldSecondaryArmingTrial_16809(t *testing.T) {
	const candidate = "6.19.0-1-generic"
	const knownGood = "6.18.4-11-generic"
	newJournal := func(t *testing.T, state upgrade.KernelState) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "kernel-upgrade.state")
		writeJournal(t, p, upgrade.KernelJournal{
			State:            state,
			CandidateVersion: candidate,
			KnownGoodVersion: knownGood,
			ActiveSlot:       upgrade.SlotA,
			InactiveSlot:     upgrade.SlotB,
		})
		return p
	}
	candidateSys := func() upgrade.KernelSystem {
		return armingTrialKernelSys{
			fakeKernelSys: fakeKernelSys{running: candidate},
			entries:       map[string]string{upgrade.SlotA: "0003", upgrade.SlotB: "0004"},
			bootCurrent:   "0004", // the inactive (candidate) slot booted
		}
	}

	t.Run("unconfirmed_trial_boot_holds", func(t *testing.T) {
		path := newJournal(t, upgrade.KernelStateArming)
		m := cluster.NewManager(0, 1)
		sys := candidateSys()
		d := &Daemon{cluster: m, kernelRunnerFn: runnerWithSys(path, sys), kernelSystemFn: func() upgrade.KernelSystem { return sys }}
		d.holdSecondaryIfKernelCandidateArmed()
		if !m.KernelUpgradeHeld() {
			t.Fatal("an ARMING journal on the candidate boot must hold SECONDARY — " +
				"the candidate is running UNVERIFIED (pre-fix: IsArmed false, no hold)")
		}
		if got := m.KernelUpgradeHoldReason(); got != cluster.KernelUpgradeHoldCandidate {
			t.Fatalf("hold reason = %q, want the candidate reason", got)
		}
		if d.kernelUpgradeHoldFailClosed {
			t.Fatal("a convicted unconfirmed trial is an ordinary candidate hold, not fail-closed")
		}
	})

	t.Run("arming_on_known_good_boot_sets_no_hold", func(t *testing.T) {
		path := newJournal(t, upgrade.KernelStateArming)
		m := cluster.NewManager(0, 1)
		sys := armingTrialKernelSys{
			fakeKernelSys: fakeKernelSys{running: knownGood},
			entries:       map[string]string{upgrade.SlotA: "0003", upgrade.SlotB: "0004"},
			bootCurrent:   "0003", // the active (known-good) slot booted
		}
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerWithSys(path, sys),
			kernelSystemFn: func() upgrade.KernelSystem { return sys },
		}
		d.holdSecondaryIfKernelCandidateArmed()
		if m.KernelUpgradeHeld() {
			t.Fatal("ARMING on a positively known-good boot must NOT hold — the " +
				"interrupted-arm node must stay electable (#5847 control)")
		}
	})

	t.Run("arming_unreadable_boot_evidence_holds_fail_closed", func(t *testing.T) {
		path := newJournal(t, upgrade.KernelStateArming)
		m := cluster.NewManager(0, 1)
		sys := armingTrialKernelSys{
			fakeKernelSys: fakeKernelSys{running: candidate},
			entriesErr:    errors.New("NVRAM unreadable"),
		}
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerWithSys(path, sys),
			kernelSystemFn: func() upgrade.KernelSystem { return sys },
		}
		d.holdSecondaryIfKernelCandidateArmed()
		if !m.KernelUpgradeHeld() || !d.kernelUpgradeHoldFailClosed {
			t.Fatalf("held=%v failClosed=%v, want a fail-closed hold when the ARMING "+
				"boot cannot be classified", m.KernelUpgradeHeld(), d.kernelUpgradeHoldFailClosed)
		}
	})

	t.Run("armed_control_still_holds_without_boot_evidence_reads", func(t *testing.T) {
		// The verified-ARMED path must be unchanged: it short-circuits in
		// TrialInFlight, so even unreadable boot entries hold as before
		// (the running-kernel discriminator then governs).
		path := newJournal(t, upgrade.KernelStateArmed)
		m := cluster.NewManager(0, 1)
		sys := candidateSys().(armingTrialKernelSys)
		sys.entriesErr = errors.New("NVRAM unreadable")
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerWithSys(path, sys),
			kernelSystemFn: func() upgrade.KernelSystem { return sys },
		}
		d.holdSecondaryIfKernelCandidateArmed()
		if !m.KernelUpgradeHeld() {
			t.Fatal("a verified ARMED candidate boot must still hold (control unchanged)")
		}
	})
}
