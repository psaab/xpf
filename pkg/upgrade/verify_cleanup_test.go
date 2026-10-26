package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyFailCleanup_RecopiesOnRetry proves the #1967 verify-fail cleanup:
// a cut that fails VERIFY removes versions/<ver> AND rewinds the journal so a
// same-version retry recopies the (corrected) staged tree and re-verifies it
// — rather than skipping the copy (copyStaged short-circuits when the dir
// exists) and re-verifying the stale failing copy forever.
func TestVerifyFailCleanup_RecopiesOnRetry(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	fs.verifyPass = false // first attempt: verifier rejects.
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0") // seeded host => reaches VERIFY.

	if err := r.Run(Options{}); err == nil {
		t.Fatal("expected verify reject on first run")
	}

	// The copied version dir must be GONE (cleanup ran).
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	if _, err := os.Stat(verDir); !os.IsNotExist(err) {
		t.Fatalf("versions/2.0.0 not removed after verify failure: stat err=%v", err)
	}
	// The journal must be rewound BELOW PREFLIGHT (so the retry re-snapshots
	// the DB and recopies) and the stale snapshot fields cleared.
	j, err := r.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if j.State.atLeast(StatePreflight) {
		t.Fatalf("journal at %s after verify-fail cleanup; want < PREFLIGHT so retry re-snapshots + recopies", j.State)
	}
	if j.DBSnapshotPath != "" || j.AdvancedStateFloor {
		t.Errorf("snapshot fields not cleared after verify-fail cleanup: path=%q floor=%v",
			j.DBSnapshotPath, j.AdvancedStateFloor)
	}
	// The orphan DB snapshot dotfile must be gone, and — critically — the
	// PERSISTED journal must not reference any snapshot (persist-before-remove
	// ordering, Codex r2): on disk, a snapshot is never referenced after it is
	// deleted. We already reloaded j from disk above, so the cleared fields
	// prove the persisted record; assert the dotfile removal too.
	snap := filepath.Join(cfg.VersionsDir, ".2.0.0.dbsnap")
	if _, serr := os.Stat(snap); !os.IsNotExist(serr) {
		t.Errorf("orphan DB snapshot %s not removed after verify-fail cleanup: %v", snap, serr)
	}

	// Operator drops a CORRECTED staged binary under the SAME version and the
	// verifier now passes. Under #1981 Option B a corrected re-stage PUBLISHES
	// a NEW generation; the retry re-resolves current-gen, recopies the
	// corrected bytes, and completes the cut.
	fs.verifyPass = true
	// Mark staged content as "corrected" so we can confirm the version dir was
	// recopied from the fresh staged bytes (not a leftover).
	writeFakeBin(t, filepath.Join(cfg.StagedDir, "xpfd"), "binary-xpfd-corrected")
	publishStagedGen(t, r) // re-publish the corrected staged set (postinst step).

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("retry after corrected staged should succeed: %v", err)
	}
	got, rerr := os.ReadFile(filepath.Join(verDir, "xpfd"))
	if rerr != nil {
		t.Fatalf("versions/2.0.0/xpfd missing after successful retry: %v", rerr)
	}
	if string(got) != string(fakeBinContent("binary-xpfd-corrected")) {
		t.Errorf("version dir not recopied from corrected staged: got %q", string(got))
	}
	// current must now point at 2.0.0 (the cut committed).
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "2.0.0" {
		t.Errorf("current = %q after retry, want 2.0.0", cur)
	}
}

// TestVerifyFailCleanup_NeverDeletesActiveVersion proves guard (a): when the
// TargetVersion equals the live `current` version (a degenerate same-version
// re-stage), a verify failure must NOT delete the running daemon's version
// dir. The journal still rewinds so a retry re-enters cleanly.
func TestVerifyFailCleanup_NeverDeletesActiveVersion(t *testing.T) {
	// Staged version == the seeded current version (2.0.0): a re-stage of the
	// already-running version that fails verify.
	fs := newFakeSystem(t, "2.0.0")
	fs.verifyPass = false
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "2.0.0") // current == target == 2.0.0.

	if err := r.Run(Options{}); err == nil {
		t.Fatal("expected verify reject")
	}

	// The ACTIVE version dir (== current) must SURVIVE — deleting it would
	// destroy the running daemon's binaries.
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	if _, err := os.Stat(verDir); err != nil {
		t.Fatalf("active version dir versions/2.0.0 deleted on same-version verify-fail: %v", err)
	}
	if _, err := os.Stat(filepath.Join(verDir, "xpfd")); err != nil {
		t.Fatalf("active version binary deleted on same-version verify-fail: %v", err)
	}
	// current must still resolve to 2.0.0.
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "2.0.0" {
		t.Errorf("current moved off the active version: %q", cur)
	}
}

// TestVerifyFailCleanup_NeverDeletesPreviousVersion proves guard (a) for the
// rollback-target case: when TargetVersion == PreviousVersion, the version
// dir backs a recoverable daemon and must not be deleted. (Constructed via a
// hand-built journal so PreviousVersion is forced equal to the target.)
func TestVerifyFailCleanup_NeverDeletesPreviousVersion(t *testing.T) {
	fs := newFakeSystem(t, "3.0.0")
	fs.verifyPass = false
	r, cfg := testEnv(t, fs)

	// Build versions/3.0.0 as if a prior cut had copied it, current -> some
	// other version so the active-version guard does NOT fire (we exercise the
	// PreviousVersion== guard specifically).
	seedInitialCurrent(t, r, cfg, "1.0.0")
	verDir := filepath.Join(cfg.VersionsDir, "3.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-3.0.0")
	}
	// Persist a journal at COPIED with PreviousVersion forced == target so the
	// guard's TargetVersion==PreviousVersion branch is the one under test.
	j := &Journal{State: StateCopied, TargetVersion: "3.0.0", PreviousVersion: "3.0.0"}
	if err := r.saveJournal(j); err != nil {
		t.Fatal(err)
	}

	if err := r.Run(Options{}); err == nil {
		t.Fatal("expected verify reject")
	}
	if _, err := os.Stat(filepath.Join(verDir, "xpfd")); err != nil {
		t.Fatalf("version dir deleted when TargetVersion==PreviousVersion: %v", err)
	}
}

// TestPreStartVersionDirCheck_RollsBack proves the #1967 C3 diagnostic: if
// the flipped-in versions/<ver> loses its binary in the FLIP->START window,
// the cut fails fast with a clear error and auto-rolls-back to the previous
// version (instead of an opaque systemd exec failure). The version dir is
// removed via the healthHook (which fires inside the post-start health probe)
// — but C3 checks BEFORE StartUnit, so we instead remove it via a resume:
// craft a journal at FLIPPED with the target dir already gone, then Run().
func TestPreStartVersionDirCheck_RollsBack(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	// Simulate a crash-resume at FLIPPED: current already points at 2.0.0 and
	// the unit drop-in is templated, BUT versions/2.0.0 has been removed by a
	// concurrent GC/disk event before START. Build that exact state.
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-2.0.0")
	}
	// No DB snapshot / AdvancedStateFloor=false: rollback here is a pure
	// re-flip to PreviousVersion (no config-DB restore needed). The point of
	// this test is the C3 pre-START dir check + the re-flip, not DB restore.
	j := &Journal{
		State:              StateFlipped,
		TargetVersion:      "2.0.0",
		PreviousVersion:    "1.0.0",
		AdvancedStateFloor: false,
	}
	// Point current at the target as flip would have.
	if err := r.flip("2.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	// Now the GC/disk event: remove the target's binary.
	if err := os.RemoveAll(verDir); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected the cut to fail when versions/2.0.0 vanished pre-START")
	}
	// The error must name the concrete missing-binary cause (C3 diagnostic)
	// or the rollback it triggered.
	if !strings.Contains(err.Error(), "incomplete before") && !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("error not a clear pre-start/rollback diagnostic: %v", err)
	}
	// Auto-rollback must have re-flipped current back to 1.0.0.
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "1.0.0" {
		t.Errorf("current = %q after pre-start failure, want rollback to 1.0.0", cur)
	}
}

// TestVerifyFailCleanup_SaveJournalFailureKeepsSnapshot proves the Codex r3
// fix: if the journal rewrite does NOT persist, cleanupFailedVerifyCopy must
// NOT remove the orphan DB snapshot — else the persisted (still StateCopied,
// DBSnapshotPath set) journal would reference a deleted snapshot.
//
// The journal directory is kept SEPARATE from VersionsDir and ONLY the journal
// dir is made read-only (Codex r4): the prior version of this test chmod'd
// VersionsDir, which blocked BOTH the version-dir removal AND the snapshot
// removal, so the old buggy code would have "passed" for the wrong reason.
// With VersionsDir writable and only the journal dir read-only, the version
// dir IS removed (proving the unlink branch ran), saveJournal fails, and the
// snapshot must still survive — a true regression test for the r3 bug.
func TestVerifyFailCleanup_SaveJournalFailureKeepsSnapshot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: a read-only dir does not block writes")
	}
	root := t.TempDir()
	versionsDir := filepath.Join(root, "versions") // writable
	journalDir := filepath.Join(root, "journal")   // made read-only below
	if err := os.MkdirAll(versionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(journalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fs := newFakeSystem(t, "2.0.0")
	r, err := NewRunner(Config{
		StagedDir:       filepath.Join(root, "staged"),
		VersionsDir:     versionsDir,
		SbinDir:         filepath.Join(root, "sbin"),
		ConfigDBDir:     filepath.Join(root, "cfgdb"),
		JournalPath:     filepath.Join(journalDir, "upgrade.state"),
		BinaryFloorPath: filepath.Join(root, "binary-floor"),
		Unit:            "xpfd",
		Sys:             fs,
		Logf:            func(format string, a ...any) { t.Logf("LOG "+format, a...) },
	})
	if err != nil {
		t.Fatal(err)
	}

	// Plant a DB snapshot dotfile + a (non-active, current is absent) version
	// dir under the WRITABLE VersionsDir, so the removal branch genuinely runs.
	snap := filepath.Join(versionsDir, ".2.0.0.dbsnap")
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	verDir := filepath.Join(versionsDir, "2.0.0")
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Make ONLY the journal directory read-only so saveJournal fails while
	// VersionsDir operations succeed.
	if err := os.Chmod(journalDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(journalDir, 0o755) })

	j := &Journal{State: StateCopied, TargetVersion: "2.0.0", PreviousVersion: "1.0.0",
		DBSnapshotPath: snap, AdvancedStateFloor: true}
	r.cleanupFailedVerifyCopy(j)

	// The version dir MUST be removed (the unlink branch ran — VersionsDir is
	// writable), proving we reached the saveJournal step.
	if _, err := os.Stat(verDir); !os.IsNotExist(err) {
		t.Fatalf("version dir not removed (unlink branch did not run): stat err=%v", err)
	}
	// The snapshot MUST survive: saveJournal failed, so removing it would leave
	// the persisted journal referencing a deleted snapshot (the r3 bug).
	if _, err := os.Stat(snap); err != nil {
		t.Fatalf("orphan snapshot removed despite a saveJournal failure: %v", err)
	}
}

// TestStaleHalfCut_VanishedDirRollsBack proves the stale-half-cut resume path
// also honors the C3 diagnostic (#1967, Codex r1 High): when a NEWER apt
// install supersedes a crashed FLIPPED cut whose target dir has since
// vanished, finishing it is doomed — the resume must route to auto-rollback
// (not a bare StartUnit error that strands the unit). This exercises the
// resume-vs-fresh "finish a stale half-cut" branch with a missing target dir.
func TestStaleHalfCut_VanishedDirRollsBack(t *testing.T) {
	// staged is the NEW version (3.0.0); the journal records a crashed FLIPPED
	// cut to a DIFFERENT, now-vanished target (2.0.0).
	fs := newFakeSystem(t, "3.0.0")
	r, cfg := testEnv(t, fs)
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-3.0.0")
	}
	seedInitialCurrent(t, r, cfg, "1.0.0")
	// Flip current to 2.0.0 as the crashed half-cut would have, then remove
	// the 2.0.0 dir (the GC/disk event), leaving a stale FLIPPED journal.
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-2.0.0")
	}
	if err := r.flip("2.0.0"); err != nil {
		t.Fatal(err)
	}
	j := &Journal{State: StateFlipped, TargetVersion: "2.0.0", PreviousVersion: "1.0.0"}
	if err := r.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(verDir); err != nil {
		t.Fatal(err)
	}

	// Run with the new 3.0.0 staged: the resume must finish-or-rollback the
	// stale 2.0.0 half-cut, then cut to 3.0.0. With the vanished dir it must
	// roll back to 1.0.0, then proceed to a fresh 3.0.0 cut.
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("resume + fresh cut should succeed: %v", err)
	}
	// The end state: current must be 3.0.0 (the fresh cut completed after the
	// stale half-cut was rolled back, NOT stranded).
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "3.0.0" {
		t.Errorf("current = %q after stale-half-cut recovery + fresh cut, want 3.0.0", cur)
	}
}

// TestRemoveAllPartials_FsyncsAfterSweep proves #1967 C4: removeAllPartials
// fsyncs VersionsDir after removing a stray .partial, so the unlink cannot be
// resurrected by a crash before the next parent fsync. It also proves the
// no-partials path does NOT fsync (the gate avoids needless work).
func TestRemoveAllPartials_FsyncsAfterSweep(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Install a recorder for the C4 fsync seam.
	orig := partialSweepSyncDir
	t.Cleanup(func() { partialSweepSyncDir = orig })
	var synced []string
	partialSweepSyncDir = func(dir string) error {
		synced = append(synced, dir)
		return orig(dir)
	}

	// No partials present: sweep must NOT fsync.
	r.removeAllPartials()
	if len(synced) != 0 {
		t.Fatalf("fsync fired with no partials to sweep: %v", synced)
	}

	// Drop a stray .partial dir, then sweep: fsync MUST fire on VersionsDir
	// and the partial must be gone.
	partial := r.partialDir("2.0.0")
	if err := os.MkdirAll(partial, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "x"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.removeAllPartials()
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("stray partial not swept: stat err=%v", err)
	}
	if len(synced) != 1 || synced[0] != cfg.VersionsDir {
		t.Fatalf("expected one fsync of VersionsDir after sweep, got %v", synced)
	}
}
