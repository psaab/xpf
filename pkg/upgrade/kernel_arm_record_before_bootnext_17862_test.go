package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #17862 — retro-review of #16809 (PR #17622). The two-phase arm records
// ARMING, sets BootNext, reads it back, and only THEN writes the arm record
// (recordPromoteBinary). Process death anywhere between the SetBootNext write
// landing and the record write therefore leaves the exact state the boot gate
// cannot gate: journal ARMING, a queued one-shot, and NO arm record. The shell
// gate folds recordless ARMING to not-armed and quiet-exits ("nothing to
// promote", exit 0), so the Go Promote classifier — the only half that convicts
// on BootCurrent + uname -r and runs verify-dataplane/beacon/revert — is never
// invoked. The candidate boots unverified with no revert.
//
// The fix: persist the promotion authority BEFORE the NVRAM mutation, so any
// boot the one-shot can produce finds the record present. The tests here pin
// that ordering; the shell half (recordless ARMING is no longer laundered as
// "not-armed") is pinned in scripts/image/test_kernel_promote_explicit_path.py.
//
// FAIL-ON-REVERT: move recordPromoteBinary back after the readback and the two
// ordering rows go RED — the probe sees no record at SetBootNext time, and the
// SetBootNext-failure arm leaves no sidecar at all.

// bootNextProbeSystem wraps the fake firmware so a test can ask the one
// question the crash window turns on: was the arm record DURABLE at the moment
// SetBootNext mutated NVRAM? Every later observation is too late to answer it.
type bootNextProbeSystem struct {
	*fakeKernelSystem
	armRecordPath        string
	recordSeenAtBootNext bool
	recordAtBootNext     string
}

func (p *bootNextProbeSystem) SetBootNext(id string) error {
	if data, err := os.ReadFile(p.armRecordPath); err == nil {
		p.recordSeenAtBootNext = true
		p.recordAtBootNext = strings.TrimSpace(string(data))
	}
	return p.fakeKernelSystem.SetBootNext(id)
}

func newProbingRunner(t *testing.T, sys KernelSystem, journal string) *KernelRunner {
	t.Helper()
	withBootGateJournal(t, journal)
	r, err := NewKernelRunner(KernelConfig{
		JournalPath:     journal,
		KernelFloorPath: filepath.Join(t.TempDir(), "kernel-floor"),
		Sys:             sys,
		Logf:            func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewKernelRunner: %v", err)
	}
	return r
}

// TestArmRecordIsDurableBeforeBootNext_17862 is the core ordering invariant:
// the arm record must exist (with the resolved arming binary) BEFORE SetBootNext
// runs. Otherwise death in the window leaves a bootable candidate with no
// designated verifier, and the boot gate has nothing to run.
func TestArmRecordIsDurableBeforeBootNext_17862(t *testing.T) {
	live := fakeXpfd(t, filepath.Join(t.TempDir(), "versions", "vB"), 0)
	withArmingBinaryResolver(t, func() (string, error) { return live, nil })

	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	probe := &bootNextProbeSystem{
		fakeKernelSystem: newFakeKernelSystem(),
		armRecordPath:    ArmRecordPath(journal),
	}
	r := newProbingRunner(t, probe, journal)

	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if !probe.recordSeenAtBootNext {
		t.Fatalf("SetBootNext mutated NVRAM before the arm record %s was "+
			"durable. That is the #17862 crash window: process death after the "+
			"one-shot write leaves journal=ARMING + a queued candidate + NO "+
			"record, the boot gate folds recordless ARMING to not-armed and "+
			"quiet-exits, and the candidate boots with no verification and no "+
			"revert", probe.armRecordPath)
	}
	if probe.recordAtBootNext != live {
		t.Errorf("arm record observed at SetBootNext time = %q, want the "+
			"resolved arming binary %q — a partial or stale record at that "+
			"moment is the same ungated boot as no record", probe.recordAtBootNext, live)
	}
}

// TestArmRecordSurvivesSetBootNextFailure_17862: an arm that dies AT the NVRAM
// step (the widest part of the window: two efibootmgr execs around it) must
// still leave the record behind. With the record written only after the
// readback, this path never writes it at all.
func TestArmRecordSurvivesSetBootNextFailure_17862(t *testing.T) {
	live := fakeXpfd(t, filepath.Join(t.TempDir(), "versions", "vB"), 0)
	withArmingBinaryResolver(t, func() (string, error) { return live, nil })

	f := newFakeKernelSystem()
	f.setBootNextErr = errors.New("efibootmgr: NVRAM write failed")
	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	r := newProbingRunner(t, f, journal)

	if err := r.Arm("6.18.5-12-generic"); err == nil {
		t.Fatal("premise broken: the arm must fail when SetBootNext errors")
	}
	rec, err := ReadArmRecord(journal)
	if err != nil {
		t.Fatalf("ReadArmRecord: %v", err)
	}
	if rec != live {
		t.Fatalf("arm record after a SetBootNext failure = %q, want %q. The "+
			"record must be durable before the NVRAM mutation: an arm aborted "+
			"at the one-shot write (or killed around it) leaves ARMING with no "+
			"designated verifier, and the boot gate has nothing to run (#17862)",
			rec, live)
	}
	// Unchanged #6758/#16809 semantics on this path: BootNext cleared,
	// journal stays ARMING (the disarm must not manufacture ARMED).
	if f.bootNext != "" {
		t.Errorf("BootNext = %q after the failed SetBootNext; want cleared", f.bootNext)
	}
	if !contains(f.calls, "bootnext-clear") {
		t.Errorf("calls = %v, want a BootNext clear on the SetBootNext error path", f.calls)
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State != KernelStateArming {
		t.Errorf("journal state = %s, want ARMING", j.State)
	}
}

// TestPromoteGatesRecordlessUnconfirmedTrial_17862 is the Go-half control for
// the recordless crash state: a journal stuck at ARMING with NO sidecar, on the
// candidate boot. Promote never read the sidecar for classification (the outer
// shell hop selects the binary from it; the Go half convicts on boot evidence
// and tolerates an empty journal PromoteBinary), so the gate is NOT the broken
// link — the shell invocation was. This row keeps that split honest: if someone
// later makes Promote depend on the record, this is the shape that must not
// quietly become an ordinary-boot no-op.
func TestPromoteGatesRecordlessUnconfirmedTrial_17862(t *testing.T) {
	f := candidateBootFake()
	f.verifyPass = false // Gate 3 REJECTs the candidate
	r := newKernelRunner(t, f)

	// The crash state exactly: ARMING journal, NO arm record.
	j := &KernelJournal{
		CandidateVersion: armingTrialCandidate,
		KnownGoodVersion: armingTrialKnownGood,
		ActiveSlot:       SlotA,
		InactiveSlot:     SlotB,
		ArmAttempts:      1,
		ArmNonce:         "test-nonce",
	}
	if err := r.ktransition(j, KernelStateArming); err != nil {
		t.Fatalf("write ARMING journal: %v", err)
	}
	if _, err := os.Stat(ArmRecordPath(r.cfg.JournalPath)); !os.IsNotExist(err) {
		t.Fatalf("premise broken: an arm record exists at %s (err=%v)",
			ArmRecordPath(r.cfg.JournalPath), err)
	}

	_, err := r.Promote()
	if !errorsIsReverted(err) {
		t.Fatalf("Promote on a recordless unconfirmed trial = %v, want "+
			"ErrKernelReverted — the Go half gates on boot evidence and must "+
			"not need the sidecar to classify (#17862)", err)
	}
	if f.selectors[SlotB] != armingTrialKnownGood {
		t.Errorf("inactive selector = %q, want restored to known-good %q after "+
			"the revert", f.selectors[SlotB], armingTrialKnownGood)
	}
}
