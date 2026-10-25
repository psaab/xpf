package upgrade

import (
	"errors"
	"strings"
	"testing"
)

// #16809 — ARMING was classified everywhere as "firmware one-shot never
// set", but two paths reach a boot with BootNext actually queued while the
// journal still says ARMING:
//
//   (a) process death between SetBootNext (armCandidate) and the ARMED
//       rename — the candidate boots with verify-dataplane and the beacon
//       never run, while Promote, the daemon election hold and the status
//       surface all treated it as an ordinary boot;
//   (b) a SetBootNext error AFTER the write landed (the 10s NVRAM kill
//       timeout, or a non-zero exit after SetVariable): the error branch
//       did not clear BootNext, so the candidate stayed queued for an
//       arbitrary later reboot.
//
// The fix: (1) the SetBootNext error branch clears BootNext via
// disarmAfterArmFailure, exactly like the post-SetBootNext paths (#6758);
// (2) on boot, ARMING + BootCurrent == entries[InactiveSlot] + running
// kernel == CandidateVersion is convicted as a genuine (unconfirmed) trial
// — Promote gates it, the daemon holds on it, and the status surface stops
// asserting "next boot is known-good" without reading boot evidence.
//
// FAIL-ON-REVERT: reverting (1) leaves f.bootNext set in
// TestSetBootNextErrorAfterWriteClearsBootNext_16809; reverting (2) makes
// Promote return the ordinary-boot no-op (outcome zero, no error, journal
// untouched) in the defect rows below instead of gated/reverted.

const (
	armingTrialCandidate = "6.18.5-12-generic"
	armingTrialKnownGood = "6.18.5-10-generic"
)

// stuckArmingJournal writes the journal exactly as a crashed arm leaves it:
// ARMING, candidate staged in the inactive slot (xpf-B), no BootID (the
// verified ARMED transition never happened), plus the arm record the arming
// wrote before SetBootNext (recordPromoteBinary runs before the ARMED
// transition, so a death in the window leaves it behind).
func stuckArmingJournal(t *testing.T, r *KernelRunner) {
	t.Helper()
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
	// The sidecar, written by recordPromoteBinary the way armCandidate calls
	// it (it stamps the journal it is given and persists the one-line file).
	if err := r.recordPromoteBinary(j); err != nil {
		t.Fatalf("recordPromoteBinary: %v", err)
	}
}

// candidateBootFake models the candidate boot for a journal stuck at ARMING:
// the firmware honored the queued one-shot (BootCurrent == xpf-B's id, via
// the fake's bootNext default) and the running kernel IS the candidate.
func candidateBootFake() *fakeKernelSystem {
	f := newFakeKernelSystem()
	f.bootNext = f.entries[SlotB] // firmware consumed this one-shot
	f.running = armingTrialCandidate
	return f
}

// ── (b) SetBootNext error after the write landed ──────────────────────

func TestSetBootNextErrorAfterWriteClearsBootNext_16809(t *testing.T) {
	f := newFakeKernelSystem()
	f.setBootNextErr = errors.New("efibootmgr killed: NVRAM timeout")
	f.setBootNextLands = true // the write landed before the exec failed
	r := newKernelRunner(t, f)

	if err := r.Arm(armingTrialCandidate); err == nil {
		t.Fatal("premise broken: the arm must fail when SetBootNext errors")
	}
	if f.bootNext != "" {
		t.Errorf("BootNext is still %q after a landed-but-errored SetBootNext — "+
			"the candidate stays queued for an arbitrary later reboot while the "+
			"journal records ARMING (#16809 variant b)", f.bootNext)
	}
	if !contains(f.calls, "bootnext-clear") {
		t.Errorf("calls = %v, want a BootNext clear on the SetBootNext error path", f.calls)
	}
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State != KernelStateArming {
		t.Errorf("journal state = %s, want ARMING — the disarm must not change "+
			"the journal's meaning, only make NVRAM agree with it", j.State)
	}
	if f.wdArmed || f.disarmWatchdogCalls != 1 {
		t.Errorf("watchdogArmed=%v disarmCalls=%d, want disarmed exactly once", f.wdArmed, f.disarmWatchdogCalls)
	}
}

// TestSetBootNextErrorUnclearableIsLoud_16809: if the clear itself fails,
// the divergence is real and must be reported with the manual command —
// and the candidate boot that follows is then gated (see the Promote rows).
func TestSetBootNextErrorUnclearableIsLoud_16809(t *testing.T) {
	f := newFakeKernelSystem()
	f.setBootNextErr = errors.New("efibootmgr killed: NVRAM timeout")
	f.setBootNextLands = true
	f.clearBootNextErr = errors.New("efivarfs delete failed")
	r := newKernelRunner(t, f)

	err := r.Arm(armingTrialCandidate)
	if err == nil {
		t.Fatal("premise broken: the arm must fail")
	}
	if !strings.Contains(err.Error(), "efibootmgr --delete-bootnext") {
		t.Errorf("error = %v, want the manual delete-bootnext guidance for the "+
			"unclearable queued one-shot", err)
	}
	if f.bootNext == "" {
		t.Error("premise broken: an unclearable BootNext must remain queued in the fake")
	}
}

// ── (a) process death: Promote gates the unconfirmed trial ────────────

func TestPromoteGatesUnconfirmedTrialOnVerifyReject_16809(t *testing.T) {
	f := candidateBootFake()
	f.verifyPass = false // Gate 3 REJECTs the candidate
	r := newKernelRunner(t, f)
	stuckArmingJournal(t, r)

	if trial, _, err := r.TrialInFlight(); err != nil || !trial {
		t.Fatalf("premise: TrialInFlight = %v err=%v, want a genuine unconfirmed trial", trial, err)
	}
	_, err := r.Promote()
	if !errorsIsReverted(err) {
		t.Fatalf("Promote on an unconfirmed trial with a REJECTing candidate = %v, "+
			"want ErrKernelReverted (gated, then reboot to known-good); the pre-fix "+
			"ordinary-boot no-op returns nil here", err)
	}
	// The revert deferred the prune (the candidate is running) but restored
	// the inactive slot's selector for the next boot.
	if f.selectors[SlotB] != armingTrialKnownGood {
		t.Errorf("inactive selector = %q, want restored to known-good %q after the revert",
			f.selectors[SlotB], armingTrialKnownGood)
	}
}

func TestPromotePromotesHealthyUnconfirmedTrial_16809(t *testing.T) {
	f := candidateBootFake()
	f.verifyPass = true
	f.beaconPass = true
	r := newKernelRunner(t, f)
	stuckArmingJournal(t, r)

	outcome, err := r.Promote()
	if err != nil {
		t.Fatalf("Promote on a healthy unconfirmed trial = %v, want a clean promote; "+
			"the pre-fix code no-oped and left the candidate running unverified", err)
	}
	if outcome.Outcome != RollOutcomePromoted {
		t.Errorf("outcome = %q, want %q", outcome.Outcome, RollOutcomePromoted)
	}
	if f.order[0] != f.entries[SlotB] {
		t.Errorf("BootOrder front = %s, want the candidate slot %s promoted to front",
			f.order[0], f.entries[SlotB])
	}
	if f.promotionMarker != armingTrialCandidate {
		t.Errorf("promotion marker = %q, want the candidate %q", f.promotionMarker, armingTrialCandidate)
	}
	if _, err := r.loadKernelJournal(); err == nil {
		// loadKernelJournal folds ENOENT to a zero journal; assert via IsArmed.
		if armed, _, _ := r.IsArmed(); armed {
			t.Error("journal still armed after a completed promote")
		}
	}
}

// Control: ARMING on a positively known-good boot stays a no-op — same
// journal, but the firmware booted the ACTIVE slot and the running kernel
// is the known-good. This is the interrupted-arm case #5847 protects: it
// must neither gate nor hold nor revert.
func TestPromoteArmingOnKnownGoodBootStaysNoOp_16809(t *testing.T) {
	f := newFakeKernelSystem() // running == known-good by default
	f.bootCurrent = f.entries[SlotA]
	f.bootNext = ""
	r := newKernelRunner(t, f)
	stuckArmingJournal(t, r)

	if trial, _, err := r.TrialInFlight(); err != nil || trial {
		t.Fatalf("TrialInFlight = %v err=%v on a known-good ARMING boot, want false/nil", trial, err)
	}
	outcome, err := r.Promote()
	if err != nil {
		t.Fatalf("Promote on a known-good ARMING boot = %v, want the ordinary-boot no-op", err)
	}
	if outcome != (KernelRollOutcome{}) {
		t.Errorf("outcome = %+v, want the zero no-op outcome", outcome)
	}
	if f.lastRollWrites != 0 {
		t.Errorf("last-roll writes = %d, want none — no roll happened on this boot", f.lastRollWrites)
	}
}

// Control: candidate SLOT booted but a different kernel running (selector
// mismatch) is not convicted by BootCurrent alone — both halves of the
// predicate are required.
func TestPromoteArmingCandidateSlotWrongKernelStaysNoOp_16809(t *testing.T) {
	f := candidateBootFake()
	f.running = armingTrialKnownGood // slot booted, candidate kernel not running
	r := newKernelRunner(t, f)
	stuckArmingJournal(t, r)

	if trial, _, err := r.TrialInFlight(); err != nil || trial {
		t.Fatalf("TrialInFlight = %v err=%v with a non-candidate running kernel, want false/nil", trial, err)
	}
	if _, err := r.Promote(); err != nil {
		t.Fatalf("Promote = %v, want the ordinary-boot no-op", err)
	}
}

// Fail-closed: ARMING with UNREADABLE boot evidence must not be classified
// as an ordinary boot — no prune, no reboot, journal preserved.
func TestPromoteArmingUnreadableEvidenceFailsClosed_16809(t *testing.T) {
	f := candidateBootFake()
	f.bootCurrentErr = errors.New("efibootmgr unreadable")
	r := newKernelRunner(t, f)
	stuckArmingJournal(t, r)

	_, err := r.Promote()
	if err == nil || errorsIsReverted(err) {
		t.Fatalf("Promote with unreadable BootCurrent on an ARMING boot = %v, want a "+
			"non-revert indeterminate error (no prune, no reboot)", err)
	}
	if !strings.Contains(err.Error(), "indeterminate") {
		t.Errorf("error = %v, want the indeterminate classification", err)
	}
	j, lerr := r.loadKernelJournal()
	if lerr != nil || j.State != KernelStateArming {
		t.Errorf("journal = %v err=%v, want preserved at ARMING", j, lerr)
	}
	if contains(f.calls, "prune:"+SlotB) {
		t.Error("the candidate was pruned on an indeterminate boot — fail-closed violated")
	}
}

// ── boot-evidence predicate, table form ───────────────────────────────

func TestUnconfirmedTrialPredicate_16809(t *testing.T) {
	mk := func(t *testing.T, f *fakeKernelSystem) *KernelRunner {
		r := newKernelRunner(t, f)
		stuckArmingJournal(t, r)
		return r
	}
	t.Run("candidate boot is a trial", func(t *testing.T) {
		if trial, _, err := mk(t, candidateBootFake()).TrialInFlight(); err != nil || !trial {
			t.Errorf("TrialInFlight = %v err=%v, want true/nil", trial, err)
		}
	})
	t.Run("known-good slot booted is not", func(t *testing.T) {
		f := newFakeKernelSystem()
		f.bootCurrent = f.entries[SlotA]
		if trial, _, err := mk(t, f).TrialInFlight(); err != nil || trial {
			t.Errorf("TrialInFlight = %v err=%v, want false/nil", trial, err)
		}
	})
	t.Run("boot entries unreadable fails closed", func(t *testing.T) {
		f := candidateBootFake()
		f.entriesErr = errors.New("NVRAM unreadable")
		if _, _, err := mk(t, f).TrialInFlight(); err == nil {
			t.Error("TrialInFlight with unreadable boot entries = nil error, want fail-closed")
		}
	})
	t.Run("candidate slot vanished fails closed", func(t *testing.T) {
		f := candidateBootFake()
		delete(f.entries, SlotB)
		if _, _, err := mk(t, f).TrialInFlight(); err == nil {
			t.Error("TrialInFlight with the candidate slot missing = nil error, want fail-closed")
		}
	})
	t.Run("running kernel unreadable fails closed", func(t *testing.T) {
		f := candidateBootFake()
		f.runningErr = errors.New("uname failed")
		if _, _, err := mk(t, f).TrialInFlight(); err == nil {
			t.Error("TrialInFlight with an unreadable running kernel = nil error, want fail-closed")
		}
	})
	t.Run("verified ARMED short-circuits without boot evidence", func(t *testing.T) {
		f := candidateBootFake()
		f.entriesErr = errors.New("NVRAM unreadable") // must NOT be consulted
		r := newKernelRunner(t, f)
		j := &KernelJournal{
			CandidateVersion: armingTrialCandidate,
			KnownGoodVersion: armingTrialKnownGood,
			ActiveSlot:       SlotA,
			InactiveSlot:     SlotB,
		}
		if err := r.ktransition(j, KernelStateArmed); err != nil {
			t.Fatal(err)
		}
		if trial, _, err := r.TrialInFlight(); err != nil || !trial {
			t.Errorf("TrialInFlight at ARMED = %v err=%v, want true/nil (verified path unchanged)", trial, err)
		}
	})
}

// ── status surface ────────────────────────────────────────────────────

func TestReadChannelStatusUnconfirmedTrial_16809(t *testing.T) {
	f := candidateBootFake()
	r := newKernelRunner(t, f)
	stuckArmingJournal(t, r)

	st := ReadChannelStatus(r.cfg.JournalPath, f)
	if st.Armed {
		t.Error("an ARMING journal must not report the VERIFIED armed bit")
	}
	if !st.UnconfirmedTrial {
		t.Error("ARMING on the candidate boot must report UnconfirmedTrial — " +
			"the pre-fix surface asserted the next boot is known-good here")
	}
	if st.TrialClassificationErr != nil {
		t.Errorf("classification err = %v, want nil on readable evidence", st.TrialClassificationErr)
	}
	out := renderStatus(st)
	if !strings.Contains(out, "UNCONFIRMED candidate trial is IN FLIGHT") {
		t.Errorf("render must name the unconfirmed trial:\n%s", out)
	}
	if strings.Contains(out, "next boot is the KNOWN-GOOD") {
		t.Errorf("render must not assert a known-good next boot on the candidate boot:\n%s", out)
	}
}

func TestReadChannelStatusArmingUnclassifiable_16809(t *testing.T) {
	f := candidateBootFake()
	f.bootCurrentErr = errors.New("efibootmgr unreadable")
	r := newKernelRunner(t, f)
	stuckArmingJournal(t, r)

	st := ReadChannelStatus(r.cfg.JournalPath, f)
	if st.UnconfirmedTrial {
		t.Error("unreadable evidence must not convict a trial")
	}
	if st.TrialClassificationErr == nil {
		t.Fatal("unreadable evidence must surface a classification error, not a bare not-armed")
	}
	if st.ReadErr != nil {
		t.Errorf("ReadErr = %v, want nil — the durable state WAS read; only the "+
			"boot classification failed", st.ReadErr)
	}
	out := renderStatus(st)
	if !strings.Contains(out, "could NOT be") || !strings.Contains(out, "proven known-good") {
		t.Errorf("render must refuse the known-good assumption on unclassifiable evidence:\n%s", out)
	}
}
