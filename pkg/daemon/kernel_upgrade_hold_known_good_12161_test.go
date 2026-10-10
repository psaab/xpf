package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/upgrade"
)

// #12161: on a known-good FALLBACK boot the daemon must not treat every ARMED
// journal as a candidate trial. The hold exists to keep an UNVERIFIED CANDIDATE
// kernel SECONDARY; a node already running known-good while the journal is
// still ARMED (daemon-before-gate ordering) is not running the candidate, so no
// hold may be set — the gate then discards the candidate, clears the
// journal/marker, and the node stays electable. Absent this check the ordinary
// hold leaks: its reconcile releases only when the promotion marker names the
// running kernel, and a discard writes no marker, so a healthy undrained node
// stays ineligible and peer failure cannot promote it.
//
// The version comparison must hold FAIL CLOSED: when RunningKernel is
// unreadable the daemon cannot prove it is off the candidate, so it holds.
func TestHoldSecondaryIfKernelCandidateArmed_KnownGoodFallback_12161(t *testing.T) {
	const candidate = "6.19.0-1-generic"
	const knownGood = "6.18.4-11-generic"
	newJournal := func(t *testing.T) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "kernel-upgrade.state")
		writeJournal(t, p, upgrade.KernelJournal{
			State:            upgrade.KernelStateArmed,
			CandidateVersion: candidate,
			KnownGoodVersion: knownGood,
			ActiveSlot:       upgrade.SlotA,
			InactiveSlot:     upgrade.SlotB,
		})
		return p
	}

	t.Run("fallback_boot_running_known_good_sets_no_hold", func(t *testing.T) {
		path := newJournal(t)
		m := cluster.NewManager(0, 1)
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerAt(path),
			kernelSystemFn: func() upgrade.KernelSystem {
				return fakeKernelSys{running: knownGood}
			},
		}

		d.holdSecondaryIfKernelCandidateArmed()

		if m.KernelUpgradeHeld() {
			t.Fatal("known-good fallback boot (running != candidate) must not set the candidate hold")
		}
		if d.kernelUpgradeHoldFailClosed {
			t.Fatal("known-good fallback boot must not set the fail-closed flag")
		}
	})

	t.Run("unreadable_running_kernel_holds_fail_closed", func(t *testing.T) {
		path := newJournal(t)
		m := cluster.NewManager(0, 1)
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerAt(path),
			kernelSystemFn: func() upgrade.KernelSystem {
				return fakeKernelSys{runningErr: errors.New("uname unreadable")}
			},
		}

		d.holdSecondaryIfKernelCandidateArmed()

		if !m.KernelUpgradeHeld() {
			t.Fatal("unreadable RunningKernel with an ARMED journal must hold fail-closed")
		}
		if got := m.KernelUpgradeHoldReason(); got != cluster.KernelUpgradeHoldCandidate {
			t.Fatalf("hold reason = %q, want the candidate reason", got)
		}
		if d.kernelUpgradeHoldFailClosed {
			t.Fatal("armed hold must not set the fail-closed flag")
		}
	})

	t.Run("candidate_boot_running_candidate_still_holds", func(t *testing.T) {
		path := newJournal(t)
		m := cluster.NewManager(0, 1)
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerAt(path),
			kernelSystemFn: func() upgrade.KernelSystem {
				return fakeKernelSys{running: candidate}
			},
		}

		d.holdSecondaryIfKernelCandidateArmed()

		if !m.KernelUpgradeHeld() {
			t.Fatal("genuine candidate boot (running == candidate) must keep the hold")
		}
		if d.kernelUpgradeHoldFailClosed {
			t.Fatal("armed hold must not set the fail-closed flag")
		}
	})
}

// #12161 daemon-before-gate ordering: the daemon reads the journal while it is
// still ARMED (fallback boot), then the gate discards the candidate and clears
// the journal + marker. The node must be ELECTABLE afterwards — no leaked hold
// — while a genuine candidate trial that the gate reverts must stay held
// through the revert window.
func TestKnownGoodFallbackElectableAfterGateDiscard_12161(t *testing.T) {
	const candidate = "6.19.0-1-generic"
	const knownGood = "6.18.4-11-generic"

	t.Run("discarded_fallback_stays_electable", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "kernel-upgrade.state")
		writeJournal(t, path, upgrade.KernelJournal{
			State:            upgrade.KernelStateArmed,
			CandidateVersion: candidate,
			KnownGoodVersion: knownGood,
			ActiveSlot:       upgrade.SlotA,
			InactiveSlot:     upgrade.SlotB,
		})
		m := cluster.NewManager(0, 1)
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerAt(path),
			kernelSystemFn: func() upgrade.KernelSystem {
				return fakeKernelSys{running: knownGood}
			},
		}

		// Daemon bringup runs BEFORE the gate: the journal is still ARMED.
		d.holdSecondaryIfKernelCandidateArmed()

		// The gate then discards the candidate and clears the journal and the
		// marker (cleanupAlreadyOnKnownGood writes no marker), without
		// rebooting. Model the gate's journal cleanup after daemon bringup.
		if err := os.Remove(path); err != nil {
			t.Fatalf("gate clears journal: %v", err)
		}

		// Reconcile ticks must never strand the node SECONDARY.
		for i := 0; i < 3; i++ {
			d.reconcileKernelUpgradeHold()
		}
		// A fresh election after gate cleanup is eligible to promote this
		// otherwise healthy known-good node.
		m.UpdateConfig(&config.ClusterConfig{
			RethCount: 1,
			RedundancyGroups: []*config.RedundancyGroup{{
				ID: 0, NodePriorities: map[int]int{0: 200},
			}},
		})
		if !m.IsLocalPrimary(0) {
			t.Fatal("known-good node must be electable after the gate discards the candidate")
		}
		if m.KernelUpgradeHeld() {
			t.Fatal("fallback node holds an election hold after the gate discarded the candidate")
		}
	})

	t.Run("gate_before_daemon_no_hold", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "kernel-upgrade.state")
		writeJournal(t, path, upgrade.KernelJournal{
			State:            upgrade.KernelStateArmed,
			CandidateVersion: candidate,
			KnownGoodVersion: knownGood,
			ActiveSlot:       upgrade.SlotA,
			InactiveSlot:     upgrade.SlotB,
		})
		// The gate wins the ordering race and clears the journal before daemon
		// manager-init attempts to read it.
		if err := os.Remove(path); err != nil {
			t.Fatalf("gate clears journal: %v", err)
		}
		m := cluster.NewManager(0, 1)
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerAt(path),
			kernelSystemFn: func() upgrade.KernelSystem {
				return fakeKernelSys{running: knownGood}
			},
		}
		d.holdSecondaryIfKernelCandidateArmed()
		m.UpdateConfig(&config.ClusterConfig{
			RethCount: 1,
			RedundancyGroups: []*config.RedundancyGroup{{
				ID: 0, NodePriorities: map[int]int{0: 200},
			}},
		})
		if !m.IsLocalPrimary(0) || m.KernelUpgradeHeld() {
			t.Fatal("gate-before-daemon ordering must leave the known-good node electable")
		}
	})

	t.Run("reverted_candidate_stays_held_through_revert_window", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "kernel-upgrade.state")
		writeJournal(t, path, upgrade.KernelJournal{
			State:            upgrade.KernelStateArmed,
			CandidateVersion: candidate,
			KnownGoodVersion: knownGood,
			ActiveSlot:       upgrade.SlotA,
			InactiveSlot:     upgrade.SlotB,
		})
		m := cluster.NewManager(0, 1)
		d := &Daemon{
			cluster:        m,
			kernelRunnerFn: runnerAt(path),
			kernelSystemFn: func() upgrade.KernelSystem {
				// The broken candidate is still RUNNING; the revert cleared the
				// journal pre-reboot and wrote no (or a stale) marker.
				return fakeKernelSys{running: candidate}
			},
		}

		d.holdSecondaryIfKernelCandidateArmed()
		if !m.KernelUpgradeHeld() {
			t.Fatal("precondition: genuine candidate boot must hold")
		}

		// The revert cleared the journal before the reboot; the marker does
		// not name the running candidate. The hold must SURVIVE: clearing it
		// here would let the unverified candidate transiently claim primary
		// in the seconds before the reboot completes.
		if err := os.Remove(path); err != nil {
			t.Fatalf("revert clears journal: %v", err)
		}
		d.reconcileKernelUpgradeHold()
		if !m.KernelUpgradeHeld() {
			t.Fatal("revert window must keep holding: the unverified candidate is still running")
		}
	})
}

// A fail-closed hold can later discover an ARMED journal. That conversion must
// apply the same running-vs-candidate check as the boot-time path: if the node
// is already on known-good, release rather than creating the ordinary hold
// that would survive the gate's journal cleanup.
func TestFailClosedHoldArmedOnKnownGoodFallbackReleases_12161(t *testing.T) {
	const candidate = "6.19.0-1-generic"
	const knownGood = "6.18.4-11-generic"
	path := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	if err := os.WriteFile(path, []byte("{corrupt"), 0o644); err != nil {
		t.Fatalf("write unreadable journal: %v", err)
	}
	m := cluster.NewManager(0, 1)
	d := &Daemon{
		cluster:        m,
		kernelRunnerFn: runnerAt(path),
		kernelSystemFn: func() upgrade.KernelSystem {
			return fakeKernelSys{running: knownGood}
		},
	}
	d.holdSecondaryIfKernelCandidateArmed()
	if !m.KernelUpgradeHeld() || !d.kernelUpgradeHoldFailClosed {
		t.Fatal("unreadable-journal startup must first hold fail-closed")
	}

	writeJournal(t, path, upgrade.KernelJournal{
		State:            upgrade.KernelStateArmed,
		CandidateVersion: candidate,
		KnownGoodVersion: knownGood,
	})
	d.reconcileKernelUpgradeHold()
	if m.KernelUpgradeHeld() {
		t.Fatal("known-good fallback must not convert an unreadable-journal hold to a candidate hold")
	}
	if d.kernelUpgradeHoldFailClosed {
		t.Fatal("known-good fallback release must clear fail-closed bookkeeping")
	}
}
