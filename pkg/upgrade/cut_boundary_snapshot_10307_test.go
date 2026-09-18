package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stageSecondCut prepares a failed target after a known-good first cut and
// publishes its staged generation so Run takes the normal uninterrupted path.
func stageSecondCut(t *testing.T, r *Runner, cfg Config, fs *fakeSystem) {
	t.Helper()
	fs.stagedVersion = "2.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-2.0.0")
	}
	if publishStagedGen(t, r) == "" {
		t.Fatal("publish staged generation returned empty generation")
	}
}

func TestRun_CutBoundarySnapshotPreservesCopyCommit10307(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	const committedDuringCopy = "#xpf-config-envelope v=1\n{\"gen\":\"committed-during-copy\"}"
	mkfile(t, dbFile, "#xpf-config-envelope v=1\n{\"gen\":\"pre-upgrade\"}")
	stageSecondCut(t, r, cfg, fs)

	// The existing copyTree durability seam lets this cell commit immediately
	// after the target version's COPY has landed, before VERIFY/STOP.
	previousSync := copyTreeSyncDir
	t.Cleanup(func() { copyTreeSyncDir = previousSync })
	copyTreeSyncDir = func(dir string) error {
		err := previousSync(dir)
		if err == nil && strings.HasSuffix(dir, ".2.0.0.partial") {
			mkfile(t, dbFile, committedDuringCopy)
		}
		return err
	}
	fs.startFailOnce = true
	if err := r.Run(Options{}); err == nil {
		t.Fatal("second cut must fail at START and auto-roll back")
	}

	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after rollback: %v", err)
	}
	if string(got) != committedDuringCopy {
		t.Fatalf("rollback restored stale PREFLIGHT snapshot: got %q, want commit made during COPY %q", got, committedDuringCopy)
	}
}

func TestRun_CutBoundarySnapshotPreservesVerifyCommit10307(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	const committedDuringVerify = "#xpf-config-envelope v=1\n{\"gen\":\"committed-during-verify\"}"
	mkfile(t, dbFile, "#xpf-config-envelope v=1\n{\"gen\":\"pre-upgrade\"}")
	stageSecondCut(t, r, cfg, fs)

	// Verify is pure and the old daemon remains live here. Model a commit that
	// lands after PREFLIGHT's snapshot but before the STOP cut boundary.
	fs.verifyHook = func() { mkfile(t, dbFile, committedDuringVerify) }
	fs.startFailOnce = true
	if err := r.Run(Options{}); err == nil {
		t.Fatal("second cut must fail at START and auto-roll back")
	}

	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after rollback: %v", err)
	}
	if string(got) != committedDuringVerify {
		t.Fatalf("rollback restored stale PREFLIGHT snapshot: got %q, want commit made during VERIFY %q", got, committedDuringVerify)
	}
}

func TestRun_CutBoundarySnapshotDoesNotResurrectConfirmedState10307(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	confirmPath := filepath.Join(cfg.ConfigDBDir, "confirm.json")
	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, dbFile, "#xpf-config-envelope v=1\n{\"gen\":\"pre-upgrade\"}")
	mkfile(t, confirmPath, `{"pending":"before-stop"}`)
	stageSecondCut(t, r, cfg, fs)
	if _, err := os.Stat(confirmPath); err != nil {
		t.Fatalf("confirm state disappeared before the cut started: %v", err)
	}

	// StopUnit entry is the last instant at which the old daemon can commit.
	// A snapshot taken before StopUnit loses both this commit and the durable
	// confirmation deletion; the snapshot must be taken after StopUnit returns.
	const committedAtStop = "#xpf-config-envelope v=1\n{\"gen\":\"committed-at-stop-boundary\"}"
	fs.stopHook = func() {
		mkfile(t, dbFile, committedAtStop)
		if err := os.Remove(confirmPath); err != nil {
			t.Fatalf("confirm at STOP boundary: %v", err)
		}
	}
	fs.startFailOnce = true
	if err := r.Run(Options{}); err == nil {
		t.Fatal("second cut must fail at START and auto-roll back")
	}

	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after rollback: %v", err)
	}
	if string(got) != committedAtStop {
		t.Errorf("rollback lost commit at STOP boundary: got %q, want %q", got, committedAtStop)
	}
	if _, err := os.Stat(confirmPath); !os.IsNotExist(err) {
		t.Fatalf("confirm.json was resurrected by rollback: stat err=%v", err)
	}

}

func TestRun_CutBoundarySnapshotFailureRestartsOldDaemon10307(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	stageSecondCut(t, r, cfg, fs)

	originalStat := statConfigDBDir
	statCalls := 0
	statConfigDBDir = func(path string) (os.FileInfo, error) {
		statCalls++
		if statCalls == 3 {
			return nil, errors.New("injected cut-boundary stat EIO")
		}
		return originalStat(path)
	}
	t.Cleanup(func() { statConfigDBDir = originalStat })

	err := r.Run(Options{})
	if err == nil || !strings.Contains(err.Error(), "cut-boundary snapshot config DB") {
		t.Fatalf("Run error = %v, want cut-boundary snapshot failure", err)
	}
	if statCalls != 3 {
		t.Fatalf("config DB stat calls = %d, want PREFLIGHT size + snapshot + cut-boundary calls", statCalls)
	}
	if !fs.unitRunning {
		t.Fatal("old daemon remained stopped after cut-boundary snapshot failure")
	}
	current, err := r.readCurrentVersion()
	if err != nil {
		t.Fatalf("read current after cut-boundary failure: %v", err)
	}
	if current != "1.0.0" {
		t.Fatalf("current version after cut-boundary failure = %q, want old 1.0.0", current)
	}

	lastStop, lastStart := -1, -1
	for i, call := range fs.calls {
		switch call {
		case "stop":
			lastStop = i
		case "start":
			lastStart = i
		}
	}
	if lastStop < 0 || lastStart < 0 || lastStop >= lastStart {
		t.Fatalf("stop must precede recovery start, calls=%v", fs.calls)
	}

	j, err := r.loadJournal()
	if err != nil {
		t.Fatalf("load journal after cut-boundary failure: %v", err)
	}
	if j.State != StateVerified {
		t.Fatalf("journal state after cut-boundary failure = %s, want VERIFIED (pre-STOP)", j.State)
	}
}
