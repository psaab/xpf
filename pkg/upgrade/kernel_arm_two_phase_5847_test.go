// #5847: the kernel-roll ARM used to persist the ARMED journal BEFORE arming
// the NVRAM BootNext one-shot. A crash in that gap (or before the best-effort
// rollback ran) left a journal claiming ARMED while the firmware still boots the
// known-good default and NO trial ever happens — a FALSE-ARMED journal. Arm then
// refused-forever (>= ARMED) and KernelSelfRecovery treated it as a genuine
// in-flight trial, SUPPRESSING expired-lease failback INDEFINITELY, so a drained
// node never rejoined.
//
// The fix is a TWO-PHASE arm: record ARMING (prepared intent) before any NVRAM
// mutation, SetBootNext, POSITIVELY read BootNext back == the inactive slot, and
// only then durably transition ARMING -> ARMED (recording the confirmed boot id
// + a per-attempt nonce). A journal stuck at ARMING is NOT a genuine trial: Arm
// RE-ARMS from it and self-recovery does NOT suppress failback (IsArmed reports
// true only for the verified ARMED).
//
// FAIL-ON-REVERT: revert armCandidate to save-ARMED-before-readback (drop the
// ARMING phase) and the injected readback-failure / mismatch scenarios reach
// (false-)ARMED instead of ARMING — Test 1 (re-arm + self-recovery) and Test 2
// (readback mismatch) go RED.
package upgrade

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// armToStuckArming drives Arm with a readback that fails, modelling a crash
// between recording the ARMING intent and the verified ARMED transition (the
// BootNext one-shot was never confirmed). It returns the runner + fake with the
// on-disk journal stuck at ARMING.
func armToStuckArming(t *testing.T) (*KernelRunner, *fakeKernelSystem) {
	t.Helper()
	f := newFakeKernelSystem()
	// The firmware readback fails: we cannot confirm BootNext, so the arm must
	// NOT advance past ARMING (a crash-before-verified-ARMED proxy).
	f.getBootNextErr = errors.New("efivarfs readback raced / unavailable")
	r := newKernelRunner(t, f)

	if err := r.Arm("6.18.5-12-generic"); err == nil {
		t.Fatal("arm must fail when the BootNext readback cannot confirm the one-shot")
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatalf("load journal: %v", err)
	}
	if j.State != KernelStateArming {
		t.Fatalf("journal state = %s, want ARMING (intent persisted, ARMED NOT reached without a "+
			"confirmed BootNext) — #5847", j.State)
	}
	if armed, _, _ := r.IsArmed(); armed {
		t.Fatal("IsArmed must be FALSE at ARMING — an unconfirmed arm is not a verified trial (#5847)")
	}
	// #16809 control: IsArmed is state-only by design, but the BOOT must also
	// classify as no-trial here — the fake defaults BootCurrent to the queued
	// BootNext ("" after the failed arm's clear, i.e. the known-good slot) and
	// the running kernel is the known-good, so TrialInFlight must stay false
	// and an interrupted arm's node must still be able to rejoin.
	if trial, _, terr := r.TrialInFlight(); terr != nil || trial {
		t.Fatalf("TrialInFlight = %v err=%v at ARMING on a known-good boot, want false/nil (#16809 control)", trial, terr)
	}
	return r, f
}

// TestKernelArmStuckArming_ReArmsAndSelfRecovers_5847 is the headline #5847 fix:
// a journal stuck at ARMING (crash before the verified ARMED) must (a) let Arm
// RE-ARM (not refuse-forever) and (b) NOT suppress expired-lease self-recovery
// (the drained node rejoins).
func TestKernelArmStuckArming_ReArmsAndSelfRecovers_5847(t *testing.T) {
	t.Run("Arm re-arms from ARMING", func(t *testing.T) {
		r, f := armToStuckArming(t)
		// Heal the firmware and re-arm the SAME candidate: ARMING < ARMED, so the
		// ">= ARMED" refusal does not fire and the two-phase arm completes.
		f.getBootNextErr = nil
		f.rebooted = false
		if err := r.Arm("6.18.5-12-generic"); err != nil {
			t.Fatalf("re-arm from ARMING must succeed (not refuse-forever), got %v", err)
		}
		j, _ := r.loadKernelJournal()
		if j.State != KernelStateArmed {
			t.Fatalf("re-arm journal state = %s, want ARMED", j.State)
		}
		if !f.rebooted {
			t.Fatal("a successful re-arm must reach the candidate reboot")
		}
	})

	t.Run("self-recovery does NOT suppress on ARMING", func(t *testing.T) {
		r, _ := armToStuckArming(t)
		now := time.Unix(1_700_000_000, 0)
		cl := &fakeSRCluster{drained: true, peerOK: true}
		sr := NewKernelSelfRecovery(SelfRecoveryConfig{
			NodeID:    0,
			LeasePath: filepath.Join(t.TempDir(), "kernel-roll.lease"),
			Grace:     10 * time.Second,
			Now:       func() time.Time { return now },
			// REAL wiring: the same IsArmed the daemon feeds self-recovery.
			Armed: func() (bool, error) { a, _, e := r.IsArmed(); return a, e },
		}, cl)
		// An EXPIRED lease naming node 0 (orchestrator crashed mid-roll).
		writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})

		if did, err := sr.Tick(); err != nil || did {
			t.Fatalf("first tick only starts the grace timer (did=%v err=%v)", did, err)
		}
		now = now.Add(11 * time.Second) // past grace
		did, err := sr.Tick()
		if err != nil {
			t.Fatalf("tick: %v", err)
		}
		if !did || cl.resets != 1 {
			t.Fatalf("a journal stuck at ARMING is NOT a genuine trial — self-recovery must rejoin the "+
				"drained node, not suppress it forever (did=%v resets=%d) — the #5847 wedge", did, cl.resets)
		}
	})
}

// TestKernelArmBootNextReadbackMismatch_StaysArming_5847 pins that when
// SetBootNext returns success but the READBACK reports a different id (firmware
// silently dropped / partial-wrote the variable), the arm does NOT advance to
// ARMED — it stays ARMING and surfaces the error, so no false-ARMED journal is
// ever persisted.
func TestKernelArmBootNextReadbackMismatch_StaysArming_5847(t *testing.T) {
	f := newFakeKernelSystem()
	f.getBootNextRet = "9999" // firmware reports a DIFFERENT id than we set (0004)
	r := newKernelRunner(t, f)

	err := r.Arm("6.18.5-12-generic")
	if err == nil {
		t.Fatal("a BootNext readback that disagrees with the armed id must FAIL the arm (no false-ARMED)")
	}
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateArmed {
		// good: did NOT reach ARMED
	} else {
		t.Fatalf("readback mismatch reached ARMED — a firmware that dropped the one-shot must not " +
			"yield a verified-ARMED journal (#5847)")
	}
	if j.State != KernelStateArming {
		t.Fatalf("journal state = %s, want ARMING after a readback mismatch", j.State)
	}
	if armed, _, _ := r.IsArmed(); armed {
		t.Fatal("IsArmed must be FALSE — the one-shot was never confirmed (#5847)")
	}
}

// TestKernelArmVerifiedArmedStillSuppresses_5847 is the NO-REGRESSION guard: a
// genuine verified ARMED (readback == the armed inactive slot) remains a real
// trial-in-flight, so self-recovery STILL suppresses expired-lease failback and
// IsArmed reports true — exactly as before #5847.
func TestKernelArmVerifiedArmedStillSuppresses_5847(t *testing.T) {
	f := newFakeKernelSystem() // GetBootNext mirrors bootNext -> readback matches
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("arm (verified): %v", err)
	}
	j, _ := r.loadKernelJournal()
	if j.State != KernelStateArmed {
		t.Fatalf("journal state = %s, want ARMED (verified)", j.State)
	}
	if armed, _, _ := r.IsArmed(); !armed {
		t.Fatal("a verified ARMED must be IsArmed true (genuine trial)")
	}

	now := time.Unix(1_700_000_000, 0)
	cl := &fakeSRCluster{drained: true, peerOK: true}
	sr := NewKernelSelfRecovery(SelfRecoveryConfig{
		NodeID:    0,
		LeasePath: filepath.Join(t.TempDir(), "kernel-roll.lease"),
		Grace:     10 * time.Second,
		Now:       func() time.Time { return now },
		Armed:     func() (bool, error) { a, _, e := r.IsArmed(); return a, e },
	}, cl)
	writeLease(t, sr.cfg.LeasePath, KernelRollLease{NodeID: 0, ExpiresAt: now.Add(-time.Minute)})

	_, _ = sr.Tick()
	now = now.Add(11 * time.Second) // well past grace
	if did, err := sr.Tick(); err != nil || did || cl.resets != 0 {
		t.Fatalf("a genuine VERIFIED-ARMED trial must STILL suppress failback (no regression to the "+
			"real trial-in-flight case): did=%v err=%v resets=%d", did, err, cl.resets)
	}
}

// TestKernelArmProvenanceNonceAndBootID_5847 pins that the verified ARMED journal
// records the confirmed boot id AND a per-attempt nonce, and that a fresh arm
// gets a DISTINCT nonce from a stale (crashed) ARMING journal — so provenance
// distinguishes a stale journal from a fresh arm.
func TestKernelArmProvenanceNonceAndBootID_5847(t *testing.T) {
	r, f := armToStuckArming(t)
	stale, _ := r.loadKernelJournal()
	if stale.ArmNonce == "" || stale.ArmAttempts != 1 {
		t.Fatalf("the ARMING intent must record a nonce + attempt count (nonce=%q attempts=%d)",
			stale.ArmNonce, stale.ArmAttempts)
	}
	if stale.BootID != "" {
		t.Fatalf("BootID must be empty until a VERIFIED ARMED, got %q", stale.BootID)
	}

	// Re-arm to a verified ARMED (a fresh attempt).
	f.getBootNextErr = nil
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	fresh, _ := r.loadKernelJournal()
	if fresh.State != KernelStateArmed {
		t.Fatalf("state = %s, want ARMED", fresh.State)
	}
	wantBoot := f.entries[SlotB] // inactive slot (A is active) -> the armed id
	if fresh.BootID != wantBoot {
		t.Fatalf("verified ARMED BootID = %q, want the confirmed inactive-slot id %q", fresh.BootID, wantBoot)
	}
	if fresh.ArmNonce == "" {
		t.Fatal("verified ARMED must carry an arm nonce (provenance)")
	}
	if fresh.ArmAttempts != 2 {
		t.Fatalf("arm attempts = %d, want 2 (stale attempt + fresh re-arm)", fresh.ArmAttempts)
	}
	if fresh.ArmNonce == stale.ArmNonce {
		t.Fatalf("a fresh arm must get a DISTINCT nonce from the stale ARMING journal "+
			"(both = %q) — provenance cannot distinguish stale vs fresh (#5847)", fresh.ArmNonce)
	}
}
