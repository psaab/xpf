package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Follow-up to #10307 (promoted from the Rev10393 delta-review advisory
// probes, which lived only under /tmp). These cells lock in the two
// directions the committed #10307 cells do not cover: pending-confirm
// preservation across rollback, and byte-level DB content on the
// cut-boundary stat-failure path.

// TestRun_CutBoundarySnapshotPreservesPendingConfirm10395 is the reverse
// direction of TestRun_CutBoundarySnapshotDoesNotResurrectConfirmedState10307.
// A VERIFY-armed confirm.json (pending state, not yet confirmed) plus its
// commit must BOTH survive START-failure auto-rollback. The pre-fix code
// restores the stale PREFLIGHT snapshot, losing both.
func TestRun_CutBoundarySnapshotPreservesPendingConfirm10395(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	confirmPath := filepath.Join(cfg.ConfigDBDir, "confirm.json")
	const committedDuringVerify = "#xpf-config-envelope v=1\n{\"gen\":\"committed-during-verify\"}"
	const pendingConfirm = `{"pending":"mid-verify","rollbackTarget":"pre-upgrade"}`
	mkfile(t, dbFile, "#xpf-config-envelope v=1\n{\"gen\":\"pre-upgrade\"}")
	_ = os.Remove(confirmPath)
	stageSecondCut(t, r, cfg, fs)
	if _, err := os.Stat(confirmPath); !os.IsNotExist(err) {
		t.Fatalf("confirm.json must be absent before arming: stat err=%v", err)
	}

	fired := false
	fs.verifyHook = func() {
		fired = true
		mkfile(t, dbFile, committedDuringVerify)
		mkfile(t, confirmPath, pendingConfirm)
	}
	fs.startFailOnce = true
	if err := r.Run(Options{}); err == nil {
		t.Fatal("second cut must fail at START and auto-roll back")
	}
	if !fired {
		t.Fatal("verifyHook never fired; harness is vacuous")
	}

	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after rollback: %v", err)
	}
	if string(got) != committedDuringVerify {
		t.Errorf("rollback lost VERIFY commit: got %q, want %q", got, committedDuringVerify)
	}
	raw, err := os.ReadFile(confirmPath)
	if err != nil {
		t.Errorf("pending confirm.json missing after rollback: %v", err)
	} else if string(raw) != pendingConfirm {
		t.Errorf("pending confirm.json altered by rollback: got %q, want %q", raw, pendingConfirm)
	}
}

// TestRun_CutBoundarySnapshotFailurePreservesLiveDB10395 extends the
// committed stat-failure cell (which checks daemon/current/journal only)
// with byte-level content assertions: on cut-boundary stat failure the live
// active.json + confirm.json are byte-identical, the PREFLIGHT .2.0.0.dbsnap
// is preserved, no .partial is left behind, the daemon is running, current
// stays 1.0.0, and the journal stays VERIFIED.
func TestRun_CutBoundarySnapshotFailurePreservesLiveDB10395(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	confirmPath := filepath.Join(cfg.ConfigDBDir, "confirm.json")
	const liveActive = "#xpf-config-envelope v=1\n{\"gen\":\"live-before-cut\"}"
	const liveConfirm = `{"pending":"live-before-cut"}`
	mkfile(t, dbFile, liveActive)
	mkfile(t, confirmPath, liveConfirm)
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
		t.Fatalf("config DB stat calls = %d, want 3", statCalls)
	}

	// Live bytes unchanged: no lost DB, no confirm resurrection/loss.
	gotActive, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read live active.json after failure: %v", err)
	}
	if string(gotActive) != liveActive {
		t.Errorf("live active.json altered by failed cut: got %q, want %q", gotActive, liveActive)
	}
	gotConfirm, err := os.ReadFile(confirmPath)
	if err != nil {
		t.Errorf("live confirm.json missing after failed cut: %v", err)
	} else if string(gotConfirm) != liveConfirm {
		t.Errorf("live confirm.json altered by failed cut: got %q, want %q", gotConfirm, liveConfirm)
	}

	// On-disk PREFLIGHT snapshot preserved (failed re-snapshot touched nothing).
	snapshotDir := filepath.Join(cfg.VersionsDir, ".2.0.0.dbsnap")
	snapActive, err := os.ReadFile(filepath.Join(snapshotDir, "active.json"))
	if err != nil {
		t.Errorf("PREFLIGHT snapshot active.json missing after failed re-snapshot: %v", err)
	} else if string(snapActive) != liveActive {
		t.Errorf("PREFLIGHT snapshot active.json altered by failed re-snapshot: got %q, want %q", snapActive, liveActive)
	}
	snapConfirm, err := os.ReadFile(filepath.Join(snapshotDir, "confirm.json"))
	if err != nil {
		t.Errorf("PREFLIGHT snapshot confirm.json missing after failed re-snapshot: %v", err)
	} else if string(snapConfirm) != liveConfirm {
		t.Errorf("PREFLIGHT snapshot confirm.json altered by failed re-snapshot: got %q, want %q", snapConfirm, liveConfirm)
	}
	if _, err := os.Stat(filepath.Join(cfg.VersionsDir, ".2.0.0.dbsnap.partial")); !os.IsNotExist(err) {
		t.Errorf("snapshot .partial left behind: stat err=%v", err)
	}

	// Committed asserts still hold.
	if !fs.unitRunning {
		t.Errorf("old daemon remained stopped after cut-boundary snapshot failure")
	}
	current, err := r.readCurrentVersion()
	if err != nil {
		t.Fatalf("read current after cut-boundary failure: %v", err)
	}
	if current != "1.0.0" {
		t.Errorf("current version after cut-boundary failure = %q, want old 1.0.0", current)
	}
	j, err := r.loadJournal()
	if err != nil {
		t.Fatalf("load journal after cut-boundary failure: %v", err)
	}
	if j.State != StateVerified {
		t.Errorf("journal state after cut-boundary failure = %s, want VERIFIED (pre-STOP)", j.State)
	}
}
