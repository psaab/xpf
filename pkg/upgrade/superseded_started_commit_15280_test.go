package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedStartedSuperseded15280 stages a stale STARTED (health-confirmed) journal
// for 2.0.0 whose COMMIT stamp never landed (Committing process died or the
// stamp write failed before the journal moved to COMMITTED), superseded by
// staged 3.0.0 on top of a committed 1.0.0 live install.
func seedStartedSuperseded15280(t *testing.T) (*fakeSystem, *Runner, Config) {
	t.Helper()
	fs := newFakeSystem(t, "3.0.0")
	r, cfg := testEnv(t, fs)

	// 1.0.0 is the genuinely committed predecessor: stamp it committed (it is
	// also the live `current` before the 2.0.0 flip).
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.writeCommitStamp(committedStamp{
		Version:             "1.0.0",
		Committed:           true,
		CommittedAtUnixNano: 1_700_000_000_000_000_000,
	}); err != nil {
		t.Fatal(err)
	}

	// The 2.0.0 cut flipped `current`, started, and health-confirmed
	// (StateStarted), but its commit stamp never landed, so it still carries
	// only the in-flight (uncommitted) stamp COPY wrote.
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-2.0.0")
	}
	if err := r.stampInFlightVersion("2.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := r.flip("2.0.0"); err != nil {
		t.Fatal(err)
	}
	j := &Journal{State: StateStarted, TargetVersion: "2.0.0", PreviousVersion: "1.0.0"}
	if err := r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	return fs, r, cfg
}

// TestSupersededStartedCutIsStampedCommitted15280 pins D05-02 (#15280): a
// STARTED (health-confirmed) journal superseded by a newer package must have
// its target stamped committed during superseded-journal recovery, exactly as
// the FLIPPED success arm stamps a finished stale half-cut. Otherwise the
// version is left committed:false and defaultRollbackTarget from the newer
// version skips back two steps.
func TestSupersededStartedCutIsStampedCommitted15280(t *testing.T) {
	fs, r, cfg := seedStartedSuperseded15280(t)
	// Fail the fresh 3.0.0 cut at PREFLIGHT so the test stops right after
	// superseded recovery (the stamp + GC + journal clear) and before the
	// fresh cut can proceed. Unlike the FLIPPED-arm test there is no
	// health call during STARTED recovery to hang the injection on, so set
	// it up front: the stale STARTED arm never probes the envelope reader.
	fs.readerErr = errors.New("injected fresh preflight failure")

	// Sanity: 2.0.0 starts uncommitted.
	if stamp, present := r.readCommittedStamp("2.0.0"); !present || stamp == nil || stamp.Committed {
		t.Fatalf("seeded 2.0.0 stamp = %+v present=%v; want present uncommitted", stamp, present)
	}

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "injected fresh preflight failure") {
		t.Fatalf("superseded STARTED recovery + injected fresh cut failure = %v; want preflight failure", err)
	}

	// The health-confirmed stale cut must have been stamped committed with
	// its journaled predecessor.
	stamp, present := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || !stamp.Committed {
		t.Fatalf("stamp(2.0.0) = %+v present=%v; want committed", stamp, present)
	}
	if stamp.Predecessor != "1.0.0" {
		t.Fatalf("stamp(2.0.0).Predecessor = %q; want 1.0.0", stamp.Predecessor)
	}
	// The stamp write proves the cut was finished as healthy, so the
	// committed-cut evidence must describe 2.0.0 (parity with the FLIPPED
	// success arm, #13543).
	if proof := r.LastCommittedCut(); !proof.healthConfirmed || proof.version != "2.0.0" {
		t.Fatalf("committed cut after stale STARTED finish = %+v; want health-confirmed 2.0.0", proof)
	}
	// Journal cleared (recovery completed; fresh cut was then refused).
	if _, err := os.Stat(cfg.JournalPath); !os.IsNotExist(err) {
		t.Fatalf("journal after superseded recovery: stat err=%v; want cleared", err)
	}
	// Current still names the verified-live 2.0.0; the fresh cut was refused
	// before STOP.
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "2.0.0" {
		t.Fatalf("current = %q after superseded STARTED recovery, want 2.0.0", cur)
	}
}

// TestSupersededStartedCutRollbackTarget15280 exercises the end-to-end
// consequence from the issue: after the superseding 3.0.0 cut completes, the
// default rollback target must be the health-confirmed 2.0.0, not 1.0.0 two
// steps back.
func TestSupersededStartedCutRollbackTarget15280(t *testing.T) {
	_, r, cfg := seedStartedSuperseded15280(t)

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("superseding cut: %v", err)
	}
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "3.0.0" {
		t.Fatalf("current = %q after superseding cut, want 3.0.0", cur)
	}
	if stamp, present := r.readCommittedStamp("2.0.0"); !present || stamp == nil || !stamp.Committed {
		t.Fatalf("stamp(2.0.0) = %+v present=%v; want committed", stamp, present)
	}
	got, err := r.defaultRollbackTarget("3.0.0")
	if err != nil {
		t.Fatalf("defaultRollbackTarget(3.0.0): %v", err)
	}
	if got != "2.0.0" {
		t.Fatalf("defaultRollbackTarget(3.0.0) = %q; want 2.0.0", got)
	}
}

// TestSupersededStartedCutStampFailureSurfaces15280: if the stale STARTED
// stamp write itself fails, recovery must surface the failure and preserve
// the journal (mirroring the FLIPPED success arm's stamp error), rather
// than resetting the journal and proceeding with an uncommitted
// verified-live version.
func TestSupersededStartedCutStampFailureSurfaces15280(t *testing.T) {
	fs, r, cfg := seedStartedSuperseded15280(t)
	// Remove the 2.0.0 dir's write-ability seam deterministically: replace
	// the version dir's stamp path with a directory so stampCommittedVersion
	// fails. The recovery must surface that failure rather than resetting
	// the journal and proceeding with an uncommitted verified-live version.
	stampPath := r.committedStampPath("2.0.0")
	if err := os.Remove(stampPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stampPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stampPath, "occupant"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = fs
	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "commit stale version 2.0.0") {
		t.Fatalf("Run with failing stale stamp = %v; want surfaced commit stale version failure", err)
	}
	// The stale journal must be preserved for retry, and the fresh cut must
	// not have proceeded.
	j, lerr := r.loadJournal()
	if lerr != nil || j.State != StateStarted || j.TargetVersion != "2.0.0" {
		t.Fatalf("journal after stamp failure = %+v err=%v; want preserved STARTED 2.0.0", j, lerr)
	}
	for _, c := range fs.calls {
		if c == "health:3.0.0" {
			t.Fatalf("fresh cut proceeded after stale stamp failure; calls=%v", fs.calls)
		}
	}
	// Current still names 2.0.0.
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "2.0.0" {
		t.Fatalf("current = %q after stamp failure, want 2.0.0", cur)
	}
}

// TestSupersededStartedCutNonLiveRefuses15280 is the fail-closed guard: a
// STARTED journal whose target is no longer the live `current` must NOT be
// stamped committed (that would mint a rollback candidate that was never
// the verified-live base); recovery refuses and preserves the journal.
func TestSupersededStartedCutNonLiveRefuses15280(t *testing.T) {
	_, r, cfg := seedStartedSuperseded15280(t)
	// Repoint current back to 1.0.0: the health-confirmed 2.0.0 is no
	// longer live (e.g. an operator flipped away out of band).
	link := filepath.Join(cfg.VersionsDir, currentLink)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1.0.0", link); err != nil {
		t.Fatal(err)
	}
	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "stale STARTED recovery") {
		t.Fatalf("Run with non-live STARTED target = %v; want stale STARTED recovery refusal", err)
	}
	if stamp, present := r.readCommittedStamp("2.0.0"); present && stamp != nil && stamp.Committed {
		t.Fatalf("non-live 2.0.0 was stamped committed: %+v", stamp)
	}
	j, lerr := r.loadJournal()
	if lerr != nil || j.State != StateStarted || j.TargetVersion != "2.0.0" {
		t.Fatalf("journal after non-live refusal = %+v err=%v; want preserved STARTED 2.0.0", j, lerr)
	}
}
