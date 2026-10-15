// #6556: a RESUMED cut reused the config-DB snapshot taken at the ORIGINAL
// preflight, so a later auto-rollback silently reverted every commit made in
// the interruption window.
//
// cutover.go gated preflight on `!j.State.atLeast(StatePreflight)`, so a
// journal that had already passed PREFLIGHT never re-snapshotted. PREFLIGHT,
// COPY and VERIFY are PURE (state.go invariants) — the daemon stays live and
// accepting commits across them — and the host-wide upgrade lock is NOT held
// across the interruption, so the operator has no signal that a cut is
// pending. The rollback then restores the pre-interruption DB.
//
// The tree documented this exact hazard for the SIBLING case and closed it
// there only: cleanupFailedVerifyCopy rewinds a verify failure to INIT and
// clears DBSnapshotPath because "the daemon stays LIVE across a verify failure
// (verify is pure), so an operator may change the config DB before the retry"
// (#1967, deepened to StateInit + SourceGeneration by #1981).
//
// FAIL-ON-REVERT: delete the `else if !j.State.atLeast(StateStopped)` arm from
// Run's preflight gate and TestRun_ResumedCutRetakesDBSnapshot6556 goes RED for
// all three live states — the rollback restores the pre-window content.
package upgrade

import (
	"os"
	"path/filepath"
	"testing"
)

// stageUnhealthy2_0_0 stages a 2.0.0 whose post-flip health check FAILS, so
// the resumed cut reaches the auto-rollback that reads the DB snapshot. That
// rollback is the only observation point: DBSnapshotPath is a path string that
// does not change between the original and the re-taken snapshot, so asserting
// on the journal field would prove nothing. What must be observed is the
// CONTENT the rollback restores.
func stageUnhealthy2_0_0(t *testing.T, fs *fakeSystem, cfg Config) {
	t.Helper()
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthFailVersions["2.0.0"] = true
}

// TestRun_ResumedCutRetakesDBSnapshot6556 is the issue's scenario, run at each
// state in the exposed span.
func TestRun_ResumedCutRetakesDBSnapshot6556(t *testing.T) {
	// PREFLIGHT, COPIED and VERIFIED are exactly the resumable states in which
	// the daemon was still live. Table-driven so a fix that happens to work at
	// one of them is not mistaken for a fix.
	for _, crashAfter := range []State{StatePreflight, StateCopied, StateVerified} {
		t.Run(string(crashAfter), func(t *testing.T) {
			fs := newFakeSystem(t, "1.0.0")
			r, cfg := testEnv(t, fs)
			if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
				t.Fatalf("first cut: %v", err)
			}

			dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
			const preContent = "#xpf-config-envelope v=1 writer=test ast=1 min-reader=1 rollback-fmt=1\n{\"gen\":\"pre-interruption\"}"
			mkfile(t, dbFile, preContent)

			stageUnhealthy2_0_0(t, fs, cfg)

			// The cut runs to crashAfter and is interrupted. Its preflight
			// snapshots preContent.
			seedCrashState(t, r, cfg, fs, crashAfter)

			// THE INTERRUPTION WINDOW. The daemon is still up (nothing before
			// STOPPED touches live state), so the operator commits.
			const windowContent = "#xpf-config-envelope v=1 writer=test ast=1 min-reader=1 rollback-fmt=1\n{\"gen\":\"committed-during-interruption\"}"
			mkfile(t, dbFile, windowContent)

			// Resume. The cut completes, the health check fails, and the
			// auto-rollback restores whatever snapshot the journal names.
			_ = r.Run(Options{})

			got, err := os.ReadFile(dbFile)
			if err != nil {
				t.Fatalf("read config DB after rollback: %v", err)
			}
			if string(got) == preContent {
				t.Fatalf("resumed cut interrupted at %s rolled the config DB back to the "+
					"PRE-INTERRUPTION snapshot, silently discarding the commit made while "+
					"the cut was interrupted.\n got=%q\nwant=%q\n"+
					"The resume reused the snapshot taken at the ORIGINAL preflight (#6556).",
					crashAfter, got, windowContent)
			}
			if string(got) != windowContent {
				t.Fatalf("config DB after rollback is neither snapshot.\n got=%q\nwant=%q",
					got, windowContent)
			}
		})
	}
}

// TestRun_ResumedCutPastStoppedKeepsOriginalSnapshot6556 pins the
// post-STOPPED snapshot rule, and prevents a new rollback-defeating bug.
//
// A STOPPED resume has its own state-aware path: it refreshes the snapshot when
// current still names PreviousVersion, or current names the target while
// either loaded ExecStart or MainPID still identifies previous. A target
// ExecStart with an old MainPID remains an old-process case because
// daemon-reload does not replace the process; on snapshot failure, restore and
// reload the previous ExecStart before restarting it. Unknown paths and
// contradictory combinations refuse. If neither execution signal identifies
// previous, the target may have migrated the DB, so the original snapshot is
// preserved. A later FLIPPED journal state likewise keeps it.
//
// This cell resumes at FLIPPED and requires rollback to restore the original
// content even after the live file changes to an envelope the old binary
// cannot read.
//
// RED-on-revert: re-snapshot unconditionally at FLIPPED and rollback restores
// post-flip content instead of the pre-upgrade DB.
func TestRun_ResumedCutPastStoppedKeepsOriginalSnapshot6556(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	const preContent = "#xpf-config-envelope v=1 writer=test ast=1 min-reader=1 rollback-fmt=1\n{\"gen\":\"pre-upgrade\"}"
	mkfile(t, dbFile, preContent)

	stageUnhealthy2_0_0(t, fs, cfg)
	seedCrashState(t, r, cfg, fs, StateFlipped)

	// Stand in for the N+1 daemon having already written a too-new envelope.
	// This is post-STOP state, NOT an operator commit, and must NOT be
	// captured as the pre-upgrade snapshot.
	const postFlipContent = "#xpf-config-envelope v=1 writer=test ast=1 min-reader=99 rollback-fmt=1\n{}"
	mkfile(t, dbFile, postFlipContent)

	_ = r.Run(Options{})

	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after rollback: %v", err)
	}
	if string(got) == postFlipContent {
		t.Fatalf("a resume at FLIPPED re-snapshotted POST-upgrade DB content and then "+
			"restored it as the rollback target — the old binary would boot against a "+
			"too-new envelope. A resume past STOPPED must retain the original snapshot (#6556).\n"+
			" got=%q\nwant=%q", got, preContent)
	}
	if string(got) != preContent {
		t.Fatalf("config DB after rollback = %q, want the pre-upgrade snapshot %q", got, preContent)
	}
}

// TestResumeReSnapshotClearsStaleSnapshotWhenDBRemoved6556 covers the third
// outcome of the re-classification: the DB was present at the original
// preflight and is GONE by the time the cut resumes.
//
// The pre-#6556 inline snapshot code could not reach this case (it only ran
// once, before anything could remove the DB), so the "absent" branch never had
// to clean up after a previous snapshot. On a re-snapshot it does: leaving the
// old directory in place with AdvancedStateFloor still true would have a later
// rollback restore a config DB over a root the operator deliberately emptied.
func TestResumeReSnapshotClearsStaleSnapshotWhenDBRemoved6556(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)

	j := &Journal{State: StateInit, TargetVersion: "2.0.0"}
	if err := r.snapshotConfigDB(j); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}
	snapDir := filepath.Join(cfg.VersionsDir, ".2.0.0.dbsnap")
	if j.DBSnapshotPath != snapDir || !j.AdvancedStateFloor {
		t.Fatalf("initial snapshot: DBSnapshotPath=%q AdvancedStateFloor=%v, want %q/true",
			j.DBSnapshotPath, j.AdvancedStateFloor, snapDir)
	}
	if _, err := os.Stat(snapDir); err != nil {
		t.Fatalf("initial snapshot dir missing: %v", err)
	}

	// The config DB is removed during the interruption window.
	if err := os.RemoveAll(cfg.ConfigDBDir); err != nil {
		t.Fatal(err)
	}
	if err := r.snapshotConfigDB(j); err != nil {
		t.Fatalf("re-snapshot with the DB absent: %v", err)
	}

	if j.DBSnapshotPath != "" {
		t.Errorf("DBSnapshotPath = %q after the DB was removed, want \"\"", j.DBSnapshotPath)
	}
	if j.AdvancedStateFloor {
		t.Error("AdvancedStateFloor still true after the DB was removed — rollback would " +
			"try to restore a snapshot the journal no longer names")
	}
	if _, err := os.Stat(snapDir); !os.IsNotExist(err) {
		t.Errorf("stale snapshot dir %s survived the re-snapshot (stat err = %v) — a later "+
			"rollback could restore a config DB over a deliberately-emptied root", snapDir, err)
	}
}

// TestResumeReSnapshotSurvivesACrashMidCopy6556 pins the ORDERING change.
//
// The pre-#6556 inline code removed the live snapshot BEFORE copying its
// replacement. Harmless on a first preflight; on a RE-snapshot it means a
// crash mid-copy leaves the journal naming a directory that no longer exists,
// and the rollback fails at restore time rather than falling back on the older
// snapshot. The replacement is now made durable in .partial first.
//
// The probe forces the copy to fail by making the source unreadable, and
// requires the previous snapshot to still be on disk afterwards.
func TestResumeReSnapshotSurvivesACrashMidCopy6556(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0000 directory is still readable, so the copy cannot be made to fail")
	}
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)

	j := &Journal{State: StateInit, TargetVersion: "2.0.0"}
	if err := r.snapshotConfigDB(j); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}
	snapDir := filepath.Join(cfg.VersionsDir, ".2.0.0.dbsnap")
	before, err := os.ReadFile(filepath.Join(snapDir, "active.json"))
	if err != nil {
		t.Fatalf("initial snapshot content: %v", err)
	}

	// Make the config DB stat-able (so the fail-closed stat passes and the
	// snapshot is attempted) but unreadable (so copyTree fails part-way).
	inner := filepath.Join(cfg.ConfigDBDir, "sub")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inner, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(inner, 0755) })

	if err := r.snapshotConfigDB(j); err == nil {
		t.Skip("copyTree tolerated the unreadable subdirectory; cannot force the mid-copy failure here")
	}

	after, err := os.ReadFile(filepath.Join(snapDir, "active.json"))
	if err != nil {
		t.Fatalf("the previous snapshot was destroyed by a FAILED re-snapshot (%v). "+
			"The replacement must be durable in .partial before the old one gives way, "+
			"or a crash mid-copy leaves the journal naming a snapshot that is gone (#6556).", err)
	}
	if string(after) != string(before) {
		t.Errorf("previous snapshot content changed after a failed re-snapshot: got %q, want %q", after, before)
	}
}
