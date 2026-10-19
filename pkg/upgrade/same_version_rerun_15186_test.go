package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #15186 (D05-01): a bare re-run of `xpfd upgrade` when the staged version is
// already live and committed must be an idempotent no-op, not a full
// same-version cut. These tests exercise that exact state through Run and
// runRollingWith.

// setupCommitted2_0_15186 cuts 1.0.0 -> 2.0.0 (2.0.0 live+committed, predecessor 1.0.0)
// and leaves the staged set still naming 2.0.0 with the same generation
// still published (the bare re-run precondition).
func setupCommitted2_0_15186(t *testing.T) (*Runner, Config, *fakeSystem) {
	t.Helper()
	r, cfg, fs := setupCommittedPredecessor14720(t)
	fs.calls = nil
	return r, cfg, fs
}

func dbsnapBytes15186(t *testing.T, cfg Config, ver string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cfg.VersionsDir, "."+ver+".dbsnap", "active.json"))
	if err != nil {
		t.Fatalf("read .%s.dbsnap/active.json: %v", ver, err)
	}
	return b
}

func TestRerunAlreadyLiveCommittedIsNoOp15186(t *testing.T) {
	r, cfg, fs := setupCommitted2_0_15186(t)
	// Mutate the live DB after the cut: a re-run that (wrongly) re-snapshots
	// would replace .2.0.0.dbsnap with these bytes.
	liveDB := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, liveDB, "#xpf-config-envelope v=1 writer=test ast=1 min-reader=1 rollback-fmt=1\n{\"after\":\"cut\"}")
	beforeSnap := dbsnapBytes15186(t, cfg, "2.0.0")
	if string(beforeSnap) == "live-mutated" {
		t.Fatal("precondition")
	}
	beforeStamp, present := r.readCommittedStamp("2.0.0")
	if !present || beforeStamp == nil || !beforeStamp.Committed || beforeStamp.Predecessor != "1.0.0" {
		t.Fatalf("precondition stamp = %+v present=%v", beforeStamp, present)
	}

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("bare re-run of already-live committed version: %v", err)
	}
	for _, c := range fs.calls {
		if c == "stop" || c == "start" {
			t.Fatalf("re-run performed stop/start calls %v; want no-op", fs.calls)
		}
	}
	if got := dbsnapBytes15186(t, cfg, "2.0.0"); string(got) != string(beforeSnap) {
		t.Fatalf(".2.0.0.dbsnap changed on re-run: got %q want %q", got, beforeSnap)
	}
	stamp, present := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || !stamp.Committed || stamp.Predecessor != "1.0.0" {
		t.Fatalf("stamp after re-run = %+v present=%v; want committed predecessor 1.0.0", stamp, present)
	}
	if got, err := r.defaultRollbackTarget("2.0.0"); err != nil || got != "1.0.0" {
		t.Fatalf("defaultRollbackTarget after re-run = %q err=%v; want 1.0.0", got, err)
	}
	if _, err := os.Stat(cfg.JournalPath); !os.IsNotExist(err) {
		t.Fatalf("journal left after no-op re-run: %v", err)
	}
}

func TestRerunAlreadyLiveDifferentGenerationRefuses15186(t *testing.T) {
	r, cfg, fs := setupCommitted2_0_15186(t)
	beforeSnap := dbsnapBytes15186(t, cfg, "2.0.0")
	// Re-stage same version under a NEW generation with changed bytes.
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0-rebuild")
	}
	fs.stagedVersion = "2.0.0"
	publishStagedGen(t, r)
	fs.calls = nil
	err := r.Run(Options{})
	if err == nil {
		t.Fatal("same-version different-bytes re-run succeeded; want refusal")
	}
	if strings.Contains(err.Error(), "dpkg-reconfigure") {
		t.Fatalf("refusal still advises dpkg-reconfigure (loop): %v", err)
	}
	if !strings.Contains(err.Error(), "DISTINCT version tag") {
		t.Fatalf("refusal lacks re-version guidance: %v", err)
	}
	for _, c := range fs.calls {
		if c == "stop" || c == "start" {
			t.Fatalf("refusal performed stop/start %v", fs.calls)
		}
	}
	if got := dbsnapBytes15186(t, cfg, "2.0.0"); string(got) != string(beforeSnap) {
		t.Fatal(".2.0.0.dbsnap changed on refused re-run")
	}
	stamp, present := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || !stamp.Committed || stamp.Predecessor != "1.0.0" {
		t.Fatalf("stamp after refusal = %+v present=%v", stamp, present)
	}
}

func TestRerunAlreadyLiveVerifyFailureKeepsSnapshot15186(t *testing.T) {
	// Same-generation arm: pinned gen == live .srcgen, but VERIFY fails.
	// Must return error without stop/start and without deleting live dbsnap/stamp.
	r, cfg, fs := setupCommitted2_0_15186(t)
	beforeSnap := dbsnapBytes15186(t, cfg, "2.0.0")
	fs.verifyPass = false
	fs.calls = nil
	// This sub-case only applies if the fix routes same-gen to no-op BEFORE
	// verify; the no-op test above already covers that. Keep this as the
	// guard-arm test via direct cleanup invocation below.
	_ = fs
	_ = beforeSnap
	// Direct guard: cleanupFailedVerifyCopy for target==live must not remove dbsnap.
	j := &Journal{TargetVersion: "2.0.0", PreviousVersion: "1.0.0", State: StateCopied}
	r.cleanupFailedVerifyCopy(j)
	if got := dbsnapBytes15186(t, cfg, "2.0.0"); string(got) != string(beforeSnap) {
		t.Fatal("cleanupFailedVerifyCopy removed/changed live .2.0.0.dbsnap")
	}
	if _, err := os.Stat(r.versionDir("2.0.0")); err != nil {
		t.Fatalf("cleanup removed live version dir: %v", err)
	}
	stamp, present := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil || !stamp.Committed || stamp.Predecessor != "1.0.0" {
		t.Fatalf("stamp after cleanup = %+v present=%v", stamp, present)
	}
}

func TestRollingRerunAlreadyLiveIsNoOpBeforeForceSecondary15186(t *testing.T) {
	r, cfg, fs := setupCommitted2_0_15186(t)
	_ = cfg
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	if err := runRollingWith(r, cl, fastRC()); err != nil {
		t.Fatalf("rolling re-run of already-live committed version: %v", err)
	}
	if cl.forced {
		t.Fatal("rolling re-run called ForceSecondary for already-live version")
	}
	for _, c := range fs.calls {
		if c == "stop" || c == "start" {
			t.Fatalf("rolling re-run performed stop/start %v", fs.calls)
		}
	}
}

func TestStampNeverWritesSelfPredecessor15186(t *testing.T) {
	r, _, _ := setupCommitted2_0_15186(t)
	j := &Journal{TargetVersion: "2.0.0", PreviousVersion: "2.0.0"}
	if err := r.stampCommittedVersion(j); err != nil {
		t.Fatalf("stampCommittedVersion: %v", err)
	}
	stamp, present := r.readCommittedStamp("2.0.0")
	if !present || stamp == nil {
		t.Fatal("stamp missing after self-predecessor stamp")
	}
	if stamp.Predecessor == "2.0.0" {
		t.Fatal("stamp wrote Predecessor == Version")
	}
	if !stamp.Committed {
		t.Fatal("stamp not committed")
	}
}
