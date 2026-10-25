package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16811: a prune deferred while the candidate is the running kernel must
// survive the terminal journal clear and be collected exactly once on the
// next off-candidate boot.
//
// Boot 1 (candidate boot, verify REJECT): revert -> restoreKnownGood
// defers the prune (candidate running, #14165) and revert then clears the
// journal. The prune-owed sidecar is the only memory of the debt.
// Boot 2 (known-good boot, journal absent): Promote's ordinary-boot branch
// settles it — exactly one PruneInactiveSlot, record consumed — so a
// third boot is a clean no-op with no second prune.

func countCalls(calls []string, want string) int {
	n := 0
	for _, c := range calls {
		if c == want {
			n++
		}
	}
	return n
}

func owedRecordExists(t *testing.T, r *KernelRunner) bool {
	t.Helper()
	_, err := os.Stat(PruneOwedPath(r.cfg.JournalPath))
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatalf("stat prune-owed record: %v", err)
	return false
}

// The issue's acceptance cell: gate-fail on the candidate shows exactly
// one prune on boot 2.
func TestPruneOwedCollectedExactlyOnceOnNextBoot16811(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	// Boot 1: running the candidate, verify REJECT -> revert (exit 3).
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = false
	f.beaconPass = true
	if _, err := r.Promote(); !errorsIsReverted(err) {
		t.Fatalf("boot 1: expected a controlled revert, got %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 0 {
		t.Fatalf("boot 1: prune ran %d times while running the candidate, want 0 (#14165)", n)
	}
	if !owedRecordExists(t, r) {
		t.Fatal("boot 1: deferred prune left no prune-owed record; the journal " +
			"clear that ends the revert would forget the debt (#16811)")
	}
	// The record carries the full prune triple.
	rec, err := r.readPruneOwed()
	if err != nil {
		t.Fatalf("boot 1: readPruneOwed: %v", err)
	}
	if rec.Slot != SlotB || rec.CandidateVersion != "6.18.5-12-generic" ||
		rec.KnownGoodVersion != "6.18.5-10-generic" {
		t.Fatalf("boot 1: prune-owed record = %+v, want {%s 6.18.5-12-generic 6.18.5-10-generic}",
			rec, SlotB)
	}
	// revert cleared the journal: boot 2 takes the ordinary-boot branch.
	if _, err := os.Stat(r.cfg.JournalPath); !os.IsNotExist(err) {
		t.Fatalf("boot 1: journal should be cleared by the revert (stat err=%v)", err)
	}

	// Boot 2: known-good running, no journal. Exactly one prune.
	f.calls = nil
	f.running = "6.18.5-10-generic"
	f.bootCurrent = "0003"
	if _, err := r.Promote(); err != nil {
		t.Fatalf("boot 2: Promote: %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 1 {
		t.Fatalf("boot 2: prune ran %d times, want exactly 1 (calls=%v) (#16811)", n, f.calls)
	}
	if owedRecordExists(t, r) {
		t.Fatal("boot 2: prune-owed record survived its own collection")
	}

	// Boot 3: nothing owed, nothing pruned again.
	f.calls = nil
	if _, err := r.Promote(); err != nil {
		t.Fatalf("boot 3: Promote: %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 0 {
		t.Fatalf("boot 3: prune ran %d times with nothing owed, want 0", n)
	}
}

// Positive/control cell, unchanged: a boot that is already off the
// candidate prunes in place on the SAME pass, exactly once, and leaves no
// record behind.
func TestPruneOwedOffCandidateControlPrunesInPlaceOnce16811(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.bootCurrent = "0003" // firmware booted the known-good slot
	f.running = "6.18.5-10-generic"

	if _, err := r.Promote(); err != nil {
		t.Fatalf("known-good cleanup: %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 1 {
		t.Fatalf("off-candidate cleanup pruned %d times on the same pass, want exactly 1", n)
	}
	if owedRecordExists(t, r) {
		t.Fatal("off-candidate in-place prune left a prune-owed record behind")
	}

	// And the next boot does not prune a second time.
	f.calls = nil
	if _, err := r.Promote(); err != nil {
		t.Fatalf("next boot: %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 0 {
		t.Fatalf("next boot pruned %d times after an in-place prune, want 0", n)
	}
}

// Fail-closed: a leftover record whose candidate is STILL the running
// kernel is not collected, and the record survives for a later boot.
func TestPruneOwedStillRunningCandidateNotCollected16811(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	r.recordPruneOwed(&KernelJournal{
		InactiveSlot:     SlotB,
		CandidateVersion: "6.18.5-12-generic",
		KnownGoodVersion: "6.18.5-10-generic",
	})
	if !owedRecordExists(t, r) {
		t.Fatal("recordPruneOwed did not persist the record")
	}
	f.running = "6.18.5-12-generic" // candidate still running (operator reboot did not happen)
	if _, err := r.Promote(); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 0 {
		t.Fatalf("pruned the RUNNING candidate %d times from a leftover record (#14165)", n)
	}
	if !owedRecordExists(t, r) {
		t.Fatal("prune-owed record was dropped while its candidate is still running")
	}

	// Unreadable running kernel: also not collected, record also survives.
	f.runningErr = errors.New("uname -r failure")
	if _, err := r.Promote(); err != nil {
		t.Fatalf("Promote with unreadable uname: %v", err)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 0 {
		t.Fatalf("pruned %d times with an unreadable running kernel (fail-closed violated)", n)
	}
	if !owedRecordExists(t, r) {
		t.Fatal("prune-owed record was dropped while the running kernel was unreadable")
	}
}

// Supersede: promoting a new candidate retires an older deferred prune.
// Without settling after the promote, a same-version record would strand
// forever (running == that candidate on every later boot).
func TestPruneOwedSettledBySupersedingPromote16811(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)

	// Roll 1: candidate fails on its boot; prune deferred + journal cleared.
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm roll 1: %v", err)
	}
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = false
	if _, err := r.Promote(); !errorsIsReverted(err) {
		t.Fatalf("roll 1 Promote: %v", err)
	}
	if !owedRecordExists(t, r) {
		t.Fatal("roll 1: no prune-owed record after the deferred revert")
	}

	// Roll 2: the SAME version is re-armed (operator retried after fixing
	// the cause) and this time promotes.
	f.running = "6.18.5-10-generic"
	f.bootCurrent = "0003"
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm roll 2: %v", err)
	}
	if owedRecordExists(t, r) {
		t.Fatal("re-arming the deferred version should supersede its prune-owed record")
	}
	f.calls = nil
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = true
	outcome, err := r.Promote()
	if err != nil {
		t.Fatalf("roll 2 Promote: %v", err)
	}
	if outcome.Outcome != RollOutcomePromoted {
		t.Fatalf("roll 2 outcome = %q, want promoted", outcome.Outcome)
	}
	if n := countCalls(f.calls, "prune:"+SlotB); n != 0 {
		t.Fatalf("roll 2 pruned the just-promoted candidate's slot %d times", n)
	}
	if owedRecordExists(t, r) {
		t.Fatal("the superseding promote left the stale prune-owed record behind; " +
			"it would be refused on every later boot (running == that candidate)")
	}
}

// A malformed record is surfaced, never silently treated as "nothing
// owed" — the same rule the arm/refusal records apply (#6601/#6622).
func TestPruneOwedMalformedRecordIsAnError16811(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	path := PruneOwedPath(r.cfg.JournalPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, body := range []string{
		"not json at all",
		`{"slot":"xpf-B"}`, // missing candidate/known-good
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write record: %v", err)
		}
		if _, err := r.Promote(); err == nil {
			t.Fatalf("Promote with prune-owed record %q succeeded; a present-but-"+
				"unreadable debt must surface, not read as 'nothing owed'", body)
		} else if !strings.Contains(err.Error(), "prune-owed") {
			t.Fatalf("Promote error = %v, want it to name the prune-owed record", err)
		}
		if n := countCalls(f.calls, "prune:"+SlotB); n != 0 {
			t.Fatalf("pruned %d times from a malformed record", n)
		}
	}
}

// The record path is derived from the journal directory, mirroring the
// arm/refusal sidecars: a non-default journal moves its debt with it.
func TestPruneOwedPathDerivesFromJournal16811(t *testing.T) {
	got := PruneOwedPath(filepath.Join("/var/lib/xpf", "kernel-upgrade.state"))
	want := "/var/lib/xpf/kernel-prune-owed"
	if got != want {
		t.Fatalf("PruneOwedPath = %q, want %q", got, want)
	}
}
