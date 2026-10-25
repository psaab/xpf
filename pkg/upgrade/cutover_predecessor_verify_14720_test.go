package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupCommittedPredecessor14720 cuts 1.0.0 -> 2.0.0 so that 1.0.0 is the
// committed predecessor of live 2.0.0 and the natural default rollback
// target. It returns the runner, its config, and the fake system.
func setupCommittedPredecessor14720(t *testing.T) (*Runner, Config, *fakeSystem) {
	t.Helper()
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut 1.0.0: %v", err)
	}
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	publishStagedGen(t, r)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("second cut 2.0.0: %v", err)
	}
	if got := currentTarget(t, cfg); got != "2.0.0" {
		t.Fatalf("current -> %q, want 2.0.0", got)
	}
	stamp, present := r.readCommittedStamp("1.0.0")
	if !present || stamp == nil || !stamp.Committed || stamp.Predecessor != "" {
		t.Fatalf("predecessor 1.0.0 stamp = (%+v,present=%v), want committed first cut", stamp, present)
	}
	curStamp, present := r.readCommittedStamp("2.0.0")
	if !present || curStamp == nil || !curStamp.Committed || curStamp.Predecessor != "1.0.0" {
		t.Fatalf("live 2.0.0 stamp = (%+v,present=%v), want committed with predecessor 1.0.0", curStamp, present)
	}
	if got, err := r.defaultRollbackTarget("2.0.0"); err != nil || got != "1.0.0" {
		t.Fatalf("precondition defaultRollbackTarget(2.0.0) = %q, err=%v; want 1.0.0", got, err)
	}
	return r, cfg, fs
}

// stagePredecessor14720 re-stages the committed predecessor tag 1.0.0 under a
// fresh generation. identical selects byte-identical staged binaries (the
// preserved-stamp arm) versus changed bytes (the demoted arm).
func stagePredecessor14720(t *testing.T, r *Runner, cfg Config, fs *fakeSystem, identical bool) string {
	t.Helper()
	fs.stagedVersion = "1.0.0"
	for _, b := range managedBins {
		dst := filepath.Join(cfg.StagedDir, b)
		if identical {
			data, err := os.ReadFile(filepath.Join(r.versionDir("1.0.0"), b))
			if err != nil {
				t.Fatalf("read installed predecessor binary %s: %v", b, err)
			}
			if err := os.WriteFile(dst, data, 0o755); err != nil {
				t.Fatalf("write identical staged binary %s: %v", b, err)
			}
		} else {
			writeFakeBin(t, dst, "binary-"+b+"-1.0.0-rebuild")
		}
	}
	genid := publishStagedGen(t, r)
	if genid == "" {
		t.Fatal("publish staged generation returned empty generation")
	}
	return genid
}

// predecessorDBSnap14720 returns the .<ver>.dbsnap/active.json bytes.
func predecessorDBSnap14720(t *testing.T, cfg Config, ver string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cfg.VersionsDir, "."+ver+".dbsnap", "active.json"))
	if err != nil {
		t.Fatalf("read .%s.dbsnap/active.json: %v", ver, err)
	}
	return b
}

// predecessorStampRaw14720 returns the raw committed-stamp bytes.
func predecessorStampRaw14720(t *testing.T, r *Runner, ver string) []byte {
	t.Helper()
	b, err := os.ReadFile(r.committedStampPath(ver))
	if err != nil {
		t.Fatalf("read committed stamp %s: %v", ver, err)
	}
	return b
}

// assertNoPredbakLeftover14720 proves no .predbak-* backup tree leaks.
func assertNoPredbakLeftover14720(t *testing.T, cfg Config) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(cfg.VersionsDir, ".predbak-*"))
	if err != nil {
		t.Fatalf("glob .predbak-*: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf(".predbak-* left behind: %v", matches)
	}
}

// assertPredecessorDirSurvives14720 checks the physical rollback artifacts
// (version dir, binaries, DB snapshot) and the live version survive. It does
// not check the committed stamp: a changed-byte replacement legitimately
// demotes it (#12177).
func assertPredecessorDirSurvives14720(t *testing.T, r *Runner, cfg Config) {
	t.Helper()
	if _, err := os.Stat(r.versionDir("1.0.0")); err != nil {
		t.Fatalf("committed predecessor version dir destroyed: %v", err)
	}
	for _, b := range managedBins {
		if _, err := os.Stat(filepath.Join(r.versionDir("1.0.0"), b)); err != nil {
			t.Fatalf("committed predecessor binary %s destroyed: %v", b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.VersionsDir, ".1.0.0.dbsnap", "active.json")); err != nil {
		t.Fatalf("predecessor DB snapshot destroyed: %v", err)
	}
	if got := currentTarget(t, cfg); got != "2.0.0" {
		t.Fatalf("current -> %q, want live 2.0.0 untouched", got)
	}
}

// assertPredecessorSnapshotContent14720 requires the predecessor's
// .dbsnap/active.json to be byte-identical to want (#16765: PREFLIGHT
// must not have replaced it with the live DB's content).
func assertPredecessorSnapshotContent14720(t *testing.T, cfg Config, want []byte) {
	t.Helper()
	if got := predecessorDBSnap14720(t, cfg, "1.0.0"); string(got) != string(want) {
		t.Fatalf("predecessor .1.0.0.dbsnap/active.json = %q, want pre-cut content %q", got, want)
	}
}

// assertPredecessorSurvives14720 additionally requires the committed stamp
// and default-rollback candidacy to survive (identical-bytes / same-gen /
// verify-fail arms, where no demotion is legitimate).
func assertPredecessorSurvives14720(t *testing.T, r *Runner, cfg Config, before *committedStamp) {
	t.Helper()
	assertPredecessorDirSurvives14720(t, r, cfg)
	stamp, present := r.readCommittedStamp("1.0.0")
	if !present || stamp == nil || !stamp.Committed {
		t.Fatalf("predecessor stamp = (%+v,present=%v), want committed stamp preserved", stamp, present)
	}
	if before != nil && stamp.CommittedAtUnixNano != before.CommittedAtUnixNano {
		t.Fatalf("predecessor stamp time = %d, want preserved %d", stamp.CommittedAtUnixNano, before.CommittedAtUnixNano)
	}
	if got, err := r.defaultRollbackTarget("2.0.0"); err != nil || got != "1.0.0" {
		t.Fatalf("defaultRollbackTarget(2.0.0) = %q, err=%v; want 1.0.0", got, err)
	}
}

// TestVerifyFailure_PreservesCommittedPredecessor14720 is the #14720
// decisive regression: re-staging the committed predecessor (1.0.0) of the
// live version (2.0.0) under a new generation and then failing VERIFY must
// not delete the rollback target. The journal for such a cut records
// PreviousVersion=2.0.0 (the live version), so the verify-fail cleanup
// guard keyed on PreviousVersion never protected 1.0.0. For identical bytes
// the committed stamp must also survive; for changed bytes the dir/snapshot
// must survive while the stamp stays demoted (#12177).
func TestVerifyFailure_PreservesCommittedPredecessor14720(t *testing.T) {
	for _, tc := range []struct {
		name      string
		identical bool
	}{
		{name: "identical bytes", identical: true},
		{name: "changed bytes", identical: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, cfg, fs := setupCommittedPredecessor14720(t)
			before, _ := r.readCommittedStamp("1.0.0")
			origSnap := predecessorDBSnap14720(t, cfg, "1.0.0")
			origStamp := predecessorStampRaw14720(t, r, "1.0.0")
			stagePredecessor14720(t, r, cfg, fs, tc.identical)
			// Distinctive live-DB marker: PREFLIGHT snapshots the live DB
			// into .1.0.0.dbsnap; without the #16765 fix the marker lands
			// in the predecessor's rollback snapshot.
			const liveMarker = "{\"marker\":\"LIVE-2.0.0-ERA-DB\"}"
			mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"),
				"#xpf-config-envelope v=1 writer=test ast=1 min-reader=1 rollback-fmt=1\n"+liveMarker)
			fs.verifyPass = false
			fs.calls = nil

			err := r.Run(Options{})
			if err == nil || !strings.Contains(err.Error(), "verify-dataplane") {
				t.Fatalf("Run error = %v, want verify-dataplane failure", err)
			}
			assertPredecessorSnapshotContent14720(t, cfg, origSnap)
			assertNoPredbakLeftover14720(t, cfg)
			if tc.identical {
				assertPredecessorSurvives14720(t, r, cfg, before)
				if got := predecessorStampRaw14720(t, r, "1.0.0"); string(got) != string(origStamp) {
					t.Fatalf("predecessor stamp bytes = %q, want %q", got, origStamp)
				}
			} else {
				assertPredecessorDirSurvives14720(t, r, cfg)
				stamp, present := r.readCommittedStamp("1.0.0")
				if !present || stamp == nil || stamp.Committed {
					t.Fatalf("changed-byte predecessor stamp = (%+v,present=%v), want non-committed", stamp, present)
				}
			}
		})
	}
}

// TestVerifyFailure_SameGenerationReusePreservesPredecessor14720 covers the
// worst form: a same-generation reuse skips the copy entirely, yet verify
// failure must still not delete the pre-existing committed predecessor dir.
func TestVerifyFailure_SameGenerationReusePreservesPredecessor14720(t *testing.T) {
	r, cfg, fs := setupCommittedPredecessor14720(t)
	before, _ := r.readCommittedStamp("1.0.0")
	origSnap := predecessorDBSnap14720(t, cfg, "1.0.0")
	genid := stagePredecessor14720(t, r, cfg, fs, true)
	// Falsify the installed .srcgen so COPY takes the same-generation resume
	// path (mirrors stageDowngradeTarget12177).
	mkfile(t, r.srcGenPath("1.0.0"), genid+"\n")
	const liveMarker = "{\"marker\":\"LIVE-2.0.0-ERA-DB\"}"
	mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"),
		"#xpf-config-envelope v=1 writer=test ast=1 min-reader=1 rollback-fmt=1\n"+liveMarker)
	fs.verifyPass = false
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "verify-dataplane") {
		t.Fatalf("Run error = %v, want verify-dataplane failure", err)
	}
	assertPredecessorSurvives14720(t, r, cfg, before)
	assertPredecessorSnapshotContent14720(t, cfg, origSnap)
	assertNoPredbakLeftover14720(t, cfg)
}

// TestStartFailure_PredecessorDirSurvives14720 covers the FLIP/START arm:
// when the re-staged predecessor fails to come up, auto-rollback returns to
// live 2.0.0 and the predecessor dir/snapshot survive. Its stamp stays
// demoted — it was demoted at the pre-STOP gate after VERIFY passed, and
// #12177 requires a just-failed target to stay excluded from default
// rollback selection. The #14720 verify-fail identity confusion (the
// dir/snapshot deletion) does not apply past VERIFY.
func TestStartFailure_PredecessorDirSurvives14720(t *testing.T) {
	r, cfg, fs := setupCommittedPredecessor14720(t)
	stagePredecessor14720(t, r, cfg, fs, true)
	fs.healthFailVersions["1.0.0"] = true
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "rolled back to 2.0.0") {
		t.Fatalf("Run error = %v, want failed target auto-rollback to 2.0.0", err)
	}
	assertPredecessorDirSurvives14720(t, r, cfg)
	// #16765: the cut-boundary snapshot this cut took for the re-staged
	// predecessor (live-DB content) is what the auto-rollback restored;
	// the predecessor's own .1.0.0.dbsnap was stashed pre-COPY and must
	// not be adopted as the rollback source. Assert it still survives as
	// a file; content equality is NOT required here (the auto-rollback
	// consumed the cut's snapshot) — content is asserted on the pre-STOP
	// and verify arms where no rollback runs.
	assertNoPredbakLeftover14720(t, cfg)
	stamp, present := r.readCommittedStamp("1.0.0")
	if !present || stamp == nil || stamp.Committed {
		t.Fatalf("start-failed predecessor stamp = (%+v,present=%v), want non-committed", stamp, present)
	}
	if got, err := r.defaultRollbackTarget("2.0.0"); err == nil && got == "1.0.0" {
		t.Fatalf("start-failed target 1.0.0 remains default rollback candidate")
	}
}

// TestStartFailure_ChangedPredecessorStaysDemoted14720 is the Case-C
// control (#12177): a changed-byte replacement that fails START must stay
// non-committed after auto-rollback — the old committed history does not
// describe the replacement bytes, so it must not be resurrected.
func TestStartFailure_ChangedPredecessorStaysDemoted14720(t *testing.T) {
	r, cfg, fs := setupCommittedPredecessor14720(t)
	stagePredecessor14720(t, r, cfg, fs, false)
	fs.healthFailVersions["1.0.0"] = true
	fs.calls = nil

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "rolled back to 2.0.0") {
		t.Fatalf("Run error = %v, want failed target auto-rollback to 2.0.0", err)
	}
	if got := currentTarget(t, cfg); got != "2.0.0" {
		t.Fatalf("current -> %q after failed replacement, want 2.0.0", got)
	}
	stamp, present := r.readCommittedStamp("1.0.0")
	if !present || stamp == nil || stamp.Committed {
		t.Fatalf("changed-byte predecessor stamp = (%+v,present=%v), want non-committed", stamp, present)
	}
	if got, err := r.defaultRollbackTarget("2.0.0"); err == nil && got == "1.0.0" {
		t.Fatalf("changed-byte failed target 1.0.0 remains default rollback candidate")
	}
}
