package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// liveMarker16765 is a distinctive live-DB payload for the 2.0.0 era. If it
// ever appears in .1.0.0.dbsnap the predecessor's rollback snapshot has been
// overwritten with the wrong-era DB (#16765).
const liveMarker16765 = "{\"marker\":\"LIVE-2.0.0-ERA-DB\"}"

const liveEnvelope16765 = "#xpf-config-envelope v=1 writer=test ast=1 min-reader=1 rollback-fmt=1\n"

func plantLiveMarker16765(t *testing.T, cfg Config) {
	t.Helper()
	mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"), liveEnvelope16765+liveMarker16765)
}

// TestPreStopEnvelopeRefusal_PreservesPredecessorSnapshot16765 covers the
// pre-STOP refusal arm: the DB envelope rises between PREFLIGHT and the
// pre-STOP recheck, the recheck refuses, and the committed predecessor's
// .dbsnap must still hold its original (pre-cut) bytes, not the live DB.
func TestPreStopEnvelopeRefusal_PreservesPredecessorSnapshot16765(t *testing.T) {
	r, cfg, fs := setupCommittedPredecessor14720(t)
	before, _ := r.readCommittedStamp("1.0.0")
	origSnap := predecessorDBSnap14720(t, cfg, "1.0.0")
	origStamp := predecessorStampRaw14720(t, r, "1.0.0")
	stagePredecessor14720(t, r, cfg, fs, true)
	// Compatible at PREFLIGHT; rises during VERIFY so the pre-STOP recheck
	// refuses. The installed predecessor reports reader 1, live DB min-reader
	// becomes 3.
	if fs.readerVersionsByDir == nil {
		fs.readerVersionsByDir = make(map[string]int)
	}
	fs.readerVersionsByDir["1.0.0"] = 1
	active := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, active, liveEnvelope16765+"{\"gen\":\"pre\"}")
	const risen = "#xpf-config-envelope v=3 writer=test ast=1 min-reader=3 rollback-fmt=1\n{\"gen\":\"risen\"}"
	fs.verifyHook = func() { mkfile(t, active, risen) }
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("Run error = %v, want pre-STOP envelope refusal", err)
	}
	assertPredecessorSnapshotContent14720(t, cfg, origSnap)
	assertPredecessorSurvives14720(t, r, cfg, before)
	if got := predecessorStampRaw14720(t, r, "1.0.0"); string(got) != string(origStamp) {
		t.Fatalf("predecessor stamp bytes = %q, want %q", got, origStamp)
	}
	assertNoPredbakLeftover14720(t, cfg)
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Fatalf("pre-STOP refusal left journal behind: %v", serr)
	}
}

// TestStartFailure_PredecessorSnapshotNotAdopted16765 covers the START arm:
// the re-staged predecessor fails health, auto-rollback restores the live
// (2.0.0-era) DB, and that rollback must consume this cut's cut-boundary
// snapshot — not the predecessor's stashed original. Observably: the live
// DB after rollback is the cut-boundary (live) content, current is back on
// 2.0.0, and the predecessor stays demoted.
func TestStartFailure_PredecessorSnapshotNotAdopted16765(t *testing.T) {
	r, cfg, fs := setupCommittedPredecessor14720(t)
	stagePredecessor14720(t, r, cfg, fs, true)
	plantLiveMarker16765(t, cfg)
	fs.healthFailVersions["1.0.0"] = true
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "rolled back to 2.0.0") {
		t.Fatalf("Run error = %v, want failed target auto-rollback to 2.0.0", err)
	}
	if got := currentTarget(t, cfg); got != "2.0.0" {
		t.Fatalf("current -> %q after START failure, want 2.0.0", got)
	}
	live, rerr := os.ReadFile(filepath.Join(cfg.ConfigDBDir, "active.json"))
	if rerr != nil {
		t.Fatalf("read live DB after auto-rollback: %v", rerr)
	}
	if !strings.Contains(string(live), "LIVE-2.0.0-ERA-DB") {
		t.Fatalf("live DB after auto-rollback = %q, want the cut-boundary (live) content; "+
			"the predecessor stash must not be adopted as the rollback source", live)
	}
	assertPredecessorDirSurvives14720(t, r, cfg)
	assertNoPredbakLeftover14720(t, cfg)
	stamp, present := r.readCommittedStamp("1.0.0")
	if !present || stamp == nil || stamp.Committed {
		t.Fatalf("start-failed predecessor stamp = (%+v,present=%v), want non-committed", stamp, present)
	}
}

// TestResumeResnapshot_PreservesPredecessorSnapshot16765 covers the #6556
// resume re-snapshot arm: a cut interrupted after PREFLIGHT resumes and
// re-snapshots before COPY. The resume must not overwrite the committed
// predecessor's .dbsnap with the live DB.
func TestResumeResnapshot_PreservesPredecessorSnapshot16765(t *testing.T) {
	r, cfg, fs := setupCommittedPredecessor14720(t)
	before, _ := r.readCommittedStamp("1.0.0")
	origSnap := predecessorDBSnap14720(t, cfg, "1.0.0")
	genid := stagePredecessor14720(t, r, cfg, fs, true)
	plantLiveMarker16765(t, cfg)
	// Seed a PREFLIGHT-state journal for the re-staged predecessor so Run
	// resumes through the #6556 re-snapshot branch.
	j := &Journal{
		State:            StatePreflight,
		TargetVersion:    "1.0.0",
		PreviousVersion:  "2.0.0",
		SourceGeneration: genid,
		DBSnapshotPath:   filepath.Join(cfg.VersionsDir, ".1.0.0.dbsnap"),
	}
	if err := r.saveJournal(j); err != nil {
		t.Fatalf("seed resume journal: %v", err)
	}
	fs.verifyPass = false
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "verify-dataplane") {
		t.Fatalf("Run error = %v, want verify-dataplane failure on resume", err)
	}
	assertPredecessorSnapshotContent14720(t, cfg, origSnap)
	assertPredecessorSurvives14720(t, r, cfg, before)
	assertNoPredbakLeftover14720(t, cfg)
}

// TestSuccessfulCutToPredecessor_KeepsRollbackChain16765 is the success
// control: a completed cut to the committed predecessor must commit, and
// the new live version's stamped predecessor (2.0.0) must be the default
// rollback target with a restorable snapshot.
func TestSuccessfulCutToPredecessor_KeepsRollbackChain16765(t *testing.T) {
	r, cfg, fs := setupCommittedPredecessor14720(t)
	stagePredecessor14720(t, r, cfg, fs, true)
	fs.calls = nil

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("cut to predecessor: %v", err)
	}
	if got := currentTarget(t, cfg); got != "1.0.0" {
		t.Fatalf("current -> %q after successful cut, want 1.0.0", got)
	}
	stamp, present := r.readCommittedStamp("1.0.0")
	if !present || stamp == nil || !stamp.Committed || stamp.Predecessor != "2.0.0" {
		t.Fatalf("new live stamp = (%+v,present=%v), want committed with predecessor 2.0.0", stamp, present)
	}
	if got, err := r.defaultRollbackTarget("1.0.0"); err != nil || got != "2.0.0" {
		t.Fatalf("defaultRollbackTarget(1.0.0) = %q, err=%v; want 2.0.0", got, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.VersionsDir, ".1.0.0.dbsnap", "active.json")); err != nil {
		t.Fatalf("new live .1.0.0.dbsnap missing after commit: %v", err)
	}
	assertNoPredbakLeftover14720(t, cfg)
}
