package upgrade

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func renderStatus(st ChannelStatus) string {
	var b bytes.Buffer
	RenderChannelStatus(&b, st)
	return b.String()
}

// ── the durable last-roll record (#6495 criterion 3) ──────────────────

// A REVERT must leave a durable record. This is the whole point: revert()
// clears the journal by design and the promotion marker is written only on
// PROMOTE, so before this a rejected candidate left `promoted=none` /
// `armed=none` — correct, and indistinguishable from a box that never tried.
func TestRevertRecordsADurableOutcome(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	j := &KernelJournal{
		CandidateVersion: "6.18.5-12-generic",
		KnownGoodVersion: "6.18.4-11-generic",
		ActiveSlot:       SlotA, InactiveSlot: SlotB,
		State: KernelStateArmed,
	}
	_ = r.revert(j, errors.New("verify-dataplane REJECT on candidate kernel"))

	got := f.lastRoll
	if !got.Recorded() {
		t.Fatal("revert left no durable outcome — the reason survives only in " +
			"journald, which on an appliance may not be persistent")
	}
	if !got.Reverted() {
		t.Errorf("Outcome = %q, want %q", got.Outcome, RollOutcomeReverted)
	}
	if got.Version != "6.18.5-12-generic" {
		t.Errorf("Version = %q, want the candidate", got.Version)
	}
	if got.KnownGood != "6.18.4-11-generic" {
		t.Errorf("KnownGood = %q — without it a revert cannot be rendered as "+
			"\"tried X, still on Y\"", got.KnownGood)
	}
	if !strings.Contains(got.Reason, "verify-dataplane REJECT") {
		t.Errorf("Reason = %q, want the gate that failed", got.Reason)
	}
	if got.UnixSec == 0 {
		t.Error("no timestamp recorded")
	}
}

// The record is written BEFORE revert()'s early returns. Those two exits — a
// journal that cannot be persisted (read-only root) and the attempt-cap
// give-up — are precisely the states an operator most needs explained, and a
// record written at the bottom would skip both.
func TestRevertRecordsOnTheEarlyExitPaths(t *testing.T) {
	t.Run("journal unwritable", func(t *testing.T) {
		f := newFakeKernelSystem()
		r := newKernelRunner(t, f)
		// Point the journal at a path that cannot be created.
		r.cfg.JournalPath = "/proc/self/cannot/exist/journal.state"
		j := &KernelJournal{CandidateVersion: "cand", State: KernelStateArmed}
		_ = r.revert(j, errors.New("beacon FAILED"))
		if !f.lastRoll.Recorded() {
			t.Fatal("a revert that could not persist its journal recorded no " +
				"outcome — the read-only-root case is exactly when the " +
				"operator has least else to go on")
		}
		if !strings.Contains(f.lastRoll.Reason, "beacon FAILED") {
			t.Errorf("Reason = %q", f.lastRoll.Reason)
		}
	})

	t.Run("attempt cap exceeded", func(t *testing.T) {
		f := newFakeKernelSystem()
		r := newKernelRunner(t, f)
		j := &KernelJournal{
			CandidateVersion: "cand", ActiveSlot: SlotA, InactiveSlot: SlotB,
			State: KernelStateArmed, PromoteAttempts: maxPromoteAttempts,
		}
		_ = r.revert(j, errors.New("third strike"))
		if !f.lastRoll.Recorded() {
			t.Fatal("the give-up path recorded no outcome")
		}
	})
}

// A PROMOTE records too, so "last roll" is a complete history rather than a
// failures-only log an operator would learn to read as "something went wrong".
func TestRecordRollOutcomePromoted(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	j := &KernelJournal{CandidateVersion: "6.19.0-1-generic", KnownGoodVersion: "6.18.4-11-generic"}
	r.recordRollOutcome(j, RollOutcomePromoted, "")
	if f.lastRoll.Outcome != RollOutcomePromoted {
		t.Fatalf("Outcome = %q", f.lastRoll.Outcome)
	}
	if f.lastRoll.Reason != "" {
		t.Errorf("a promote needs no reason; got %q", f.lastRoll.Reason)
	}
}

// A history-write failure must NEVER change what the channel does. A revert
// that could not record itself is still a revert.
func TestRecordRollOutcomeFailureIsNonFatal(t *testing.T) {
	f := newFakeKernelSystem()
	f.lastRollErr = errors.New("read-only file system")
	r := newKernelRunner(t, f)
	j := &KernelJournal{
		CandidateVersion: "cand", ActiveSlot: SlotA, InactiveSlot: SlotB,
		State: KernelStateArmed,
	}
	err := r.revert(j, errors.New("gate failed"))
	if !errors.Is(err, ErrKernelReverted) {
		t.Fatalf("a failed history write changed the revert outcome: err = %v "+
			"(want ErrKernelReverted)", err)
	}
}

// The reason is collapsed to one line: it lands in a status table, and a
// wrapped multi-line exec error would break the layout.
func TestRollReasonIsCollapsedToOneLine(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	r.recordRollOutcome(&KernelJournal{}, RollOutcomeReverted,
		"exec failed:\n  stdout: nope\n  stderr: also nope")
	if strings.ContainsAny(f.lastRoll.Reason, "\n\r") {
		t.Errorf("Reason contains a newline: %q", f.lastRoll.Reason)
	}
	if !strings.Contains(f.lastRoll.Reason, "stderr: also nope") {
		t.Errorf("collapsing dropped content: %q", f.lastRoll.Reason)
	}
}

// ── ReadChannelStatus ─────────────────────────────────────────────────

func TestReadChannelStatusArmedAndIdle(t *testing.T) {
	dir := t.TempDir()
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	r.cfg.JournalPath = dir + "/kernel.state"

	// Idle: no journal file at all.
	st := ReadChannelStatus(r.cfg.JournalPath, f)
	if st.Armed {
		t.Error("no journal must not report armed")
	}
	if st.ReadErr != nil {
		t.Errorf("an absent journal is not an error: %v", st.ReadErr)
	}

	// Armed.
	if err := r.saveKernelJournal(&KernelJournal{
		CandidateVersion: "cand", KnownGoodVersion: "kg",
		ActiveSlot: SlotA, InactiveSlot: SlotB, State: KernelStateArmed,
	}); err != nil {
		t.Fatalf("saveKernelJournal: %v", err)
	}
	st = ReadChannelStatus(r.cfg.JournalPath, f)
	if !st.Armed {
		t.Fatal("a verified ARMED journal must report armed")
	}
	if st.Journal.CandidateVersion != "cand" {
		t.Errorf("candidate = %q", st.Journal.CandidateVersion)
	}
}

// ARMING is prepared intent whose firmware one-shot was never read back, on a
// boot POSITIVELY known-good (the fake's default: no queued BootNext, running
// kernel is the known-good). Reporting it as armed would tell an operator a
// trial is in flight that will not happen. (An ARMING boot that IS the
// candidate is the #16809 unconfirmed trial — kernel_arming_trial_16809_test.go.)
func TestReadChannelStatusArmingIsNotArmed(t *testing.T) {
	dir := t.TempDir()
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	r.cfg.JournalPath = dir + "/kernel.state"
	// A complete ARMING journal (candidate + both slots, as a real arm
	// writes) so the #16809 boot classification has evidence to read: the
	// fake boots the known-good slot and runs the known-good kernel.
	if err := r.saveKernelJournal(&KernelJournal{
		CandidateVersion: "cand", KnownGoodVersion: "kg",
		ActiveSlot: SlotA, InactiveSlot: SlotB, State: KernelStateArming,
	}); err != nil {
		t.Fatalf("saveKernelJournal: %v", err)
	}
	st := ReadChannelStatus(r.cfg.JournalPath, f)
	if st.Armed {
		t.Fatal("ARMING must NOT report armed — the firmware one-shot was " +
			"never confirmed, so the next boot is known-good")
	}
	if st.UnconfirmedTrial {
		t.Fatal("ARMING on a positively known-good boot must NOT report an " +
			"unconfirmed trial (#16809 control)")
	}
	if st.TrialClassificationErr != nil {
		t.Fatalf("known-good ARMING classification err = %v, want nil", st.TrialClassificationErr)
	}
	out := renderStatus(st)
	if !strings.Contains(out, "ARMING is prepared intent only") {
		t.Errorf("the ARMING distinction must be explained, not just implied:\n%s", out)
	}
	if !strings.Contains(out, "positively the KNOWN-GOOD") {
		t.Errorf("the ARMING note must ground the known-good claim in this boot's evidence:\n%s", out)
	}
}

// ReadChannelStatus must not mutate anything: it runs at operator polling
// frequency against the same durable state the promotion gate depends on.
func TestReadChannelStatusIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	f := newFakeKernelSystem()
	f.promotionMarker = "6.18.4-11-generic"
	r := newKernelRunner(t, f)
	r.cfg.JournalPath = dir + "/kernel.state"
	j := &KernelJournal{CandidateVersion: "cand", State: KernelStateArmed}
	if err := r.saveKernelJournal(j); err != nil {
		t.Fatalf("saveKernelJournal: %v", err)
	}
	before := f.lastRollWrites
	for i := 0; i < 3; i++ {
		ReadChannelStatus(r.cfg.JournalPath, f)
	}
	if f.lastRollWrites != before {
		t.Errorf("ReadChannelStatus wrote the last-roll record (%d writes)",
			f.lastRollWrites-before)
	}
	if f.promotionMarker != "6.18.4-11-generic" {
		t.Errorf("ReadChannelStatus mutated the promotion marker: %q", f.promotionMarker)
	}
	after, err := r.loadKernelJournal()
	if err != nil {
		t.Fatalf("loadKernelJournal: %v", err)
	}
	if after.State != KernelStateArmed || after.CandidateVersion != "cand" {
		t.Errorf("ReadChannelStatus mutated the journal: %+v", after)
	}
}

// An unreadable channel is itself the finding. Refusing to render would leave
// the operator with strictly less than before.
func TestReadChannelStatusReportsAnUnreadableJournalWithoutHidingTheRest(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/kernel.state"
	if err := writeFileForTest(path, "{not json"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := newFakeKernelSystem()
	f.promotionMarker = "6.18.4-11-generic"
	st := ReadChannelStatus(path, f)
	if st.ReadErr == nil {
		t.Fatal("a corrupt journal must be reported")
	}
	out := renderStatus(st)
	if !strings.Contains(out, "WARNING") {
		t.Errorf("the read failure must be surfaced:\n%s", out)
	}
	if !strings.Contains(out, "6.18.4-11-generic") {
		t.Errorf("a corrupt journal must not suppress the readable state:\n%s", out)
	}
}

// ── rendering ─────────────────────────────────────────────────────────

func TestRenderArmedNamesCandidateKnownGoodAndSlots(t *testing.T) {
	out := renderStatus(ChannelStatus{
		Armed: true,
		Journal: KernelJournal{
			CandidateVersion: "6.19.0-1-generic",
			KnownGoodVersion: "6.18.4-11-generic",
			ActiveSlot:       SlotA, InactiveSlot: SlotB,
			State: KernelStateArmed, BootID: "0004",
			StartedAt: time.Unix(1755792000, 0),
		},
		RunningVersion: "6.18.4-11-generic",
	})
	for _, want := range []string{
		"6.19.0-1-generic", "6.18.4-11-generic", SlotA, SlotB, "Boot0004",
		"IN FLIGHT",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render is missing %q:\n%s", want, out)
		}
	}
}

func TestRenderIdleChannel(t *testing.T) {
	out := renderStatus(ChannelStatus{})
	if !strings.Contains(out, "no candidate kernel is armed") {
		t.Errorf("an idle channel must say so:\n%s", out)
	}
	if !strings.Contains(out, "Last roll:       none recorded") {
		t.Errorf("no roll history must be named, not blank:\n%s", out)
	}
}

// The post-revert case #6495 exists for: after the journal clear, the render
// must still say WHAT was tried and WHY it was rejected.
func TestRenderPostRevertShowsWhatWasTriedAndWhy(t *testing.T) {
	out := renderStatus(ChannelStatus{
		RunningVersion: "6.18.4-11-generic",
		LastRoll: KernelRollOutcome{
			Version: "6.19.0-1-generic", KnownGood: "6.18.4-11-generic",
			Outcome: RollOutcomeReverted,
			Reason:  "verify-dataplane REJECT on candidate kernel 6.19.0-1-generic",
			UnixSec: 1755792000,
		},
	})
	if !strings.Contains(out, "no candidate kernel is armed") {
		t.Errorf("post-revert the channel is idle:\n%s", out)
	}
	for _, want := range []string{
		"reverted", "6.19.0-1-generic", "verify-dataplane REJECT",
		"2025-08-21", // UnixSec rendered in UTC
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render is missing %q — this is the post-revert amnesia "+
				"#6495 exists to fix:\n%s", want, out)
		}
	}
}

func TestRenderNamesTheClusterHold(t *testing.T) {
	// The literal is supplied by the caller (the daemon passes
	// cluster.KernelUpgradeHoldReason). This package must not import
	// pkg/cluster — its own tests already do, which would be a cycle — so the
	// AGREEMENT between the two surfaces is asserted in pkg/daemon, where both
	// are reachable. Here we only assert that a supplied reason is rendered
	// verbatim rather than summarised away.
	const reason = "kernel-candidate promotion gate (test literal)"
	out := renderStatus(ChannelStatus{HoldReason: reason})
	if !strings.Contains(out, "HELD SECONDARY") {
		t.Errorf("the election hold must be named:\n%s", out)
	}
	if !strings.Contains(out, reason) {
		t.Errorf("the hold REASON must be rendered verbatim:\n%s", out)
	}
}

func TestRenderNeverPanicsOnAZeroSnapshot(t *testing.T) {
	// The status surface must survive a channel it cannot read at all.
	_ = renderStatus(ChannelStatus{ReadErr: errors.New("boom")})
}

func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
