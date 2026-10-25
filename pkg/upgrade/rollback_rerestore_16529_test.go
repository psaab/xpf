package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedPreservedAutoRollback16529 drives the exact #16529 trace through the
// production code: 1.0.0 live -> cut 2.0.0 -> START health fails ->
// rollback() restores the cut-boundary snapshot, flips 1.0.0, STARTs ->
// HelperHealthy(1.0.0) times out -> journal preserved at ROLLINGBACK with
// the old daemon RUNNING. It then lands an operator commit on the running
// daemon and returns with the commit in the live DB.
//
// The journal deliberately carries NO AutoRollbackDBRestored bit and the
// live DB has already diverged from the snapshot, so neither the new bit
// nor the byte-identity signal can heal it — only the surviving-state
// reasoning (here: none; .old was deleted by the completed swap) applies.
// In other words this cell models a LEGACY preserved journal exactly as
// the pre-fix binary wrote it, plus a commit. Pre-fix, the resume STOPs
// the healthy daemon, re-restores the snapshot over the commit, and
// removes .old: the commit is destroyed with no copy.
func seedPreservedAutoRollback16529(t *testing.T, withBit bool) (*Runner, Config, *fakeSystem, string, string) {
	t.Helper()
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	// Cut-boundary snapshot content (what PREFLIGHT/cut-boundary captured).
	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	preContent, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatal(err)
	}

	// Stage 2.0.0 unhealthy; rollback destination 1.0.0 also fails its
	// first health probe (the #14721 preservation), then recovers.
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthFailVersions["2.0.0"] = true
	fs.healthFailVersions["1.0.0"] = true
	if err := r.Run(Options{}); err == nil {
		t.Fatal("unhealthy cut + unhealthy-then-preserved rollback succeeded; want error")
	}
	j, jerr := r.loadJournal()
	if jerr != nil {
		t.Fatalf("journal must be preserved after unhealthy rollback: %v", jerr)
	}
	// The rollback daemon is running (StartUnit succeeded; only health
	// timed out). The operator commits a fix on it.
	if !fs.unitRunning {
		t.Fatal("seed: rolled-back daemon is not running")
	}
	commit := string(preContent) + `{"operator":"post-rollback-fix"}`
	mkfile(t, dbFile, commit)
	// Legacy seeds must not carry the bit on disk either: rewrite the
	// journal exactly as a pre-#16529 binary would have left it. The
	// in-memory journal above was produced by the FIXED binary (which
	// persists the bit before the health gate), so only the on-disk
	// rewrite distinguishes the two seeds.
	if !withBit {
		j.AutoRollbackDBRestored = false
		must(t, r.saveJournal(j))
	} else if !j.AutoRollbackDBRestored {
		t.Fatal("seed: fixed binary did not persist AutoRollbackDBRestored before the health gate")
	}
	fs.healthFailVersions["1.0.0"] = false // helper has recovered by re-run time
	fs.calls = nil
	return r, cfg, fs, commit, string(preContent)
}

// #16529 defect cell (legacy journal): resuming a preserved auto-rollback
// must not destroy the operator commit. Pre-fix this fails: the resume
// STOPs the running daemon, re-restores the snapshot, and the commit is
// gone from both the live DB and .old.
func TestResumePreservedAutoRollbackKeepsCommit16529_Legacy(t *testing.T) {
	r, cfg, fs, commit, _ := seedPreservedAutoRollback16529(t, false)

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("resume: %v; want rolled-back outcome", err)
	}
	assertCommitSurvives16529(t, cfg, commit)
	assertNoStop16529(t, fs)
}

// #16529 defect cell (current journal): same trace, but the preserved
// journal was written by the fixed binary and carries the restored bit.
func TestResumePreservedAutoRollbackKeepsCommit16529_Bitted(t *testing.T) {
	r, cfg, fs, commit, _ := seedPreservedAutoRollback16529(t, true)

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("resume: %v; want rolled-back outcome", err)
	}
	assertCommitSurvives16529(t, cfg, commit)
	assertNoStop16529(t, fs)
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Errorf("journal not cleared after healthy fast-path resume (err=%v)", serr)
	}
}

// Positive control: a rollback that is healthy the first time clears its
// journal, so a later commit + fresh cut is untouched (unchanged behaviour).
func TestControlHealthyRollbackThenCommitUnaffected16529(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	fs.healthFailVersions["2.0.0"] = true
	if err := r.Run(Options{}); err == nil {
		t.Fatal("unhealthy cut succeeded; want rolled-back error")
	}
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Fatalf("healthy rollback must clear its journal (err=%v)", serr)
	}
	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	commit := `{"operator":"after-healthy-rollback"}`
	mkfile(t, dbFile, commit)
	// A re-run stages nothing new (staged is still 2.0.0, now healthy):
	// it must complete the cut without touching the commit pre-FLIP, and
	// the cut-boundary snapshot must carry the commit.
	fs.healthFailVersions["2.0.0"] = false
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("fresh cut after healthy rollback: %v", err)
	}
	snap, err := os.ReadFile(filepath.Join(cfg.VersionsDir, ".2.0.0.dbsnap", "active.json"))
	if err != nil {
		t.Fatalf("cut-boundary snapshot missing: %v", err)
	}
	if !strings.Contains(string(snap), "after-healthy-rollback") {
		t.Errorf("cut-boundary snapshot = %q; operator commit not carried forward", snap)
	}
}

// Direct restore guard: with .old present and the live DB byte-identical
// to the snapshot, restoreDBSnapshot (the auto flavour) must be a no-op
// that keeps .old — previously it deleted .old and rotated anyway.
func TestRestoreDBSnapshotIdentityKeepsOld16529(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	snapDir := filepath.Join(cfg.VersionsDir, ".2.0.0.dbsnap")
	snapContent := "#xpf-config-envelope v=1 writer=test ast=1 min-reader=1 rollback-fmt=1\n{}"
	mkfile(t, filepath.Join(snapDir, "active.json"), snapContent)
	mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"), snapContent)
	mkfile(t, filepath.Join(cfg.ConfigDBDir+".old", "active.json"), "failed-runtime-db")

	if err := r.restoreDBSnapshot(snapDir); err != nil {
		t.Fatalf("restoreDBSnapshot: %v", err)
	}
	old, err := os.ReadFile(filepath.Join(cfg.ConfigDBDir+".old", "active.json"))
	if err != nil {
		t.Fatalf(".old destroyed by an identity restore: %v", err)
	}
	if string(old) != "failed-runtime-db" {
		t.Errorf(".old = %q, want the retained failed-runtime DB", old)
	}
	live, err := os.ReadFile(filepath.Join(cfg.ConfigDBDir, "active.json"))
	if err != nil || string(live) != snapContent {
		t.Errorf("live DB = %q err=%v, want the snapshot content untouched", live, err)
	}
}

// Operator flavour: a resumed RollbackTo whose destination is already
// running and healthy must complete without stopping it, keeping commits.
func TestResumeOperatorRollbackRunningHealthyKeepsCommit16529(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	// Simulate: operator rollback restored the DB (retaining the failed
	// runtime's DB at .old), flipped to 1.0.0, started it, then the
	// health gate preserved the journal. The operator commits on the
	// running 1.0.0 daemon.
	must(t, fx.r.flip("1.0.0"))
	mkfile(t, filepath.Join(fx.cfg.ConfigDBDir+".old", "active.json"), rollbackV1Snap+`{"live":true}`)
	live := rollbackV1Snap + `{"operator":"post-rollback-fix"}`
	mkfile(t, filepath.Join(fx.cfg.ConfigDBDir, "active.json"), live)
	snapDir := filepath.Join(fx.cfg.VersionsDir, ".2.0.0.dbsnap")
	j := &Journal{
		TargetVersion:      "2.0.0",
		PreviousVersion:    "1.0.0",
		State:              StateRollingBack,
		DBSnapshotPath:     snapDir,
		AdvancedStateFloor: true,
		OperatorRollback:   true,
		RollbackDBRestored: true,
	}
	must(t, fx.r.saveJournal(j))
	fx.fs.calls = nil

	if err := fx.r.RollbackTo("1.0.0", RollbackOptions{}); err != nil {
		t.Fatalf("resumed operator rollback: %v", err)
	}
	assertNoStop16529(t, fx.fs)
	got, err := os.ReadFile(filepath.Join(fx.cfg.ConfigDBDir, "active.json"))
	if err != nil || string(got) != live {
		t.Errorf("live DB = %q err=%v; operator commit destroyed by resumed operator rollback", got, err)
	}
	if _, serr := os.Stat(fx.cfg.JournalPath); !os.IsNotExist(serr) {
		t.Errorf("journal not cleared after fast-path operator resume (err=%v)", serr)
	}
}

func assertCommitSurvives16529(t *testing.T, cfg Config, commit string) {
	t.Helper()
	live, err := os.ReadFile(filepath.Join(cfg.ConfigDBDir, "active.json"))
	if err == nil && string(live) == commit {
		return
	}
	if old, oerr := os.ReadFile(filepath.Join(cfg.ConfigDBDir+".old", "active.json")); oerr == nil && string(old) == commit {
		return
	}
	t.Errorf("operator commit destroyed by resume: live=%q (err=%v); want it in the live DB or in .old", live, err)
}

func assertNoStop16529(t *testing.T, fs *fakeSystem) {
	t.Helper()
	for _, c := range fs.calls {
		if c == "stop" {
			t.Errorf("resume STOPPED the already-running rolled-back daemon (calls=%v)", fs.calls)
			return
		}
	}
}
