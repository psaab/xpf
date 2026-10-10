package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writePendingVersionStatus12143(t *testing.T, path, staged, running string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf("format=1\nstaged_version=%s\nrunning_version=%s\nreason=cut-failed\nrecovery=xpfd upgrade\nrecorded_at=2026-10-08T12:00:00Z\n", staged, running)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertStatusRetained12143(t *testing.T, r *Runner, path, staged, current string) {
	t.Helper()
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, r.LastCommittedCut())
	if err != nil {
		t.Fatalf("ClearBinaryUpgradeStatusIfCurrent: %v", err)
	}
	if cleared {
		t.Fatalf("status for staged %s was cleared while current is %s", staged, current)
	}
	status := ReadBinaryUpgradeStatus(path)
	if status.ReadErr != nil || !status.Recorded || status.StagedVersion != staged {
		t.Fatalf("status after mismatched clear = %+v, want staged %s retained", status, staged)
	}
}

func TestBareRerunAfterFailedPublishRetainsStatus12143(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	for _, bin := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, bin), "binary-"+bin+"-3.0.0")
	}
	fs.stagedVersion = "2.0.0" // failed publish leaves current-gen on 2.0.0
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("bare re-run of prior generation: %v", err)
	}
	current, err := r.readCurrentVersion()
	if err != nil || current != "2.0.0" {
		t.Fatalf("current = %q, err=%v; want previous 2.0.0", current, err)
	}
	assertStatusRetained12143(t, r, path, "3.0.0", current)
}

func TestRollingAfterFailedPublishRetainsStatus12143(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	cluster := func() *fakeCluster {
		return &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	}
	if err := runRollingWith(r, cluster(), fastRC()); err != nil {
		t.Fatalf("initial rolling cut: %v", err)
	}
	for _, bin := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, bin), "binary-"+bin+"-3.0.0")
	}
	fs.stagedVersion = "2.0.0"
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	if err := runRollingWith(r, cluster(), fastRC()); err != nil {
		t.Fatalf("rolling re-run of prior generation: %v", err)
	}
	current, err := r.readCurrentVersion()
	if err != nil || current != "2.0.0" {
		t.Fatalf("current = %q, err=%v; want previous 2.0.0", current, err)
	}
	assertStatusRetained12143(t, r, path, "3.0.0", current)
}

func TestResumeRollbackAfterPublishRetainsStatus12143(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}
	fs.stagedVersion = "2.0.0"
	for _, bin := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, bin), "binary-"+bin+"-2.0.0")
	}
	journal := &Journal{State: StateRollingBack, TargetVersion: "2.0.0", PreviousVersion: "1.0.0"}
	must(t, r.copyStaged(journal))
	must(t, r.flip("2.0.0"))
	must(t, r.saveJournal(journal))

	fs.stagedVersion = "3.0.0"
	for _, bin := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, bin), "binary-"+bin+"-3.0.0")
	}
	publishStagedGen(t, r)
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("resume rollback: %v", err)
	}
	current, err := r.readCurrentVersion()
	if err != nil || current != "1.0.0" {
		t.Fatalf("current = %q, err=%v; want resumed rollback 1.0.0", current, err)
	}
	assertStatusRetained12143(t, r, path, "3.0.0", current)
}

func TestSupersededStatusClearsAfterNewerRollingCut12143(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	cluster := func() *fakeCluster {
		return &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	}
	if err := runRollingWith(r, cluster(), fastRC()); err != nil {
		t.Fatalf("initial rolling cut: %v", err)
	}

	fs.stagedVersion = "4.0.0"
	for _, bin := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, bin), "binary-"+bin+"-4.0.0")
	}
	publishStagedGen(t, r)

	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	if err := runRollingWith(r, cluster(), fastRC()); err != nil {
		t.Fatalf("rolling cut to superseding version: %v", err)
	}
	current, err := r.readCurrentVersion()
	if err != nil || current != "4.0.0" {
		t.Fatalf("current = %q, err=%v; want newer committed 4.0.0", current, err)
	}
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, r.LastCommittedCut())
	if err != nil || !cleared {
		t.Fatalf("superseded clear = %v, err=%v; want record cleared", cleared, err)
	}
	status := ReadBinaryUpgradeStatus(path)
	if status.ReadErr != nil || status.Recorded {
		t.Fatalf("status after superseded clear = %+v, want absent", status)
	}
}

func TestMatchingCommittedVersionClearsStatus12143(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("cut to staged version: %v", err)
	}
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "2.0.0", "1.0.0")
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, r.LastCommittedCut())
	if err != nil || !cleared {
		t.Fatalf("matching clear = %v, err=%v; want cleared", cleared, err)
	}
	status := ReadBinaryUpgradeStatus(path)
	if status.ReadErr != nil || status.Recorded {
		t.Fatalf("status after matching committed version clear = %+v, want absent", status)
	}
}
