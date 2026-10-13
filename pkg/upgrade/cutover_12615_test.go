// #12615: a STOPPED cut interrupted after FLIP 6a has current -> its
// UNVERIFIED target while the journal still says STOPPED. A newer staged
// version then supersedes it — the stale STOPPED recovery must restore the
// journaled known-good PreviousVersion before starting the fresh cut.
//
// FAIL-ON-REVERT: removing the current-version check/rollback in Run's stale
// STOPPED recovery makes this test RED: 3.0.0's failed health rolls back to
// unverified 2.0.0 instead of the known-good 1.0.0.
package upgrade

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

func TestCut_SupersededStoppedAfter6a_RollsBackToKnownGood_12615(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs) // publishes gen of fs.stagedVersion (2.0.0)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	// Model FLIP 6a completing before the interruption: current now names
	// 2.0.0, but the journal is still STOPPED and systemd still has old 1.0.0
	// ExecStart loaded. The unverified target has NOT passed health.
	if err := os.Remove(filepath.Join(cfg.VersionsDir, currentLink)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("2.0.0", filepath.Join(cfg.VersionsDir, currentLink)); err != nil {
		t.Fatal(err)
	}
	fs.baseExecStart = filepath.Join(r.versionDir("1.0.0"), "xpfd")
	fs.loadedExecStart = fakeSystemdExecStart(fs.baseExecStart)
	fs.runningUnitExe = fs.baseExecStart
	fs.dropinContent = ""

	sg := r.stagedGenConfig()
	gOld, err := sg.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	verDir := filepath.Join(cfg.VersionsDir, "2.0.0")
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-2.0.0")
	}
	if err := os.WriteFile(filepath.Join(verDir, stagedgen.SrcGenFile), []byte(gOld+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	jStale := &Journal{TargetVersion: "2.0.0", PreviousVersion: "1.0.0",
		State: StateStopped, SourceGeneration: gOld}
	if err := r.saveJournal(jStale); err != nil {
		t.Fatal(err)
	}

	// A newer apt install stages + publishes 3.0.0, superseding the stale cut.
	fs.stagedVersion = "3.0.0"
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, b), "binary-"+b+"-3.0.0")
	}
	if _, err := sg.Publish(); err != nil {
		t.Fatal(err)
	}
	newGen, err := sg.ResolveCurrent()
	if err != nil || newGen == gOld {
		t.Fatalf("published generation = %q (err %v), old generation %q", newGen, err, gOld)
	}
	stagedVersion, err := fs.BinaryVersion(filepath.Join(sg.GenDir(newGen), "xpfd"))
	if err != nil || stagedVersion != "3.0.0" {
		t.Fatalf("published staged version = %q (err %v); want 3.0.0", stagedVersion, err)
	}
	fs.healthFailVersions["3.0.0"] = true

	loaded, err := r.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	_, source, err := r.resolveSource(loaded)
	if err != nil {
		t.Fatal(err)
	}
	version, err := fs.BinaryVersion(filepath.Join(source, "xpfd"))
	if err != nil || loaded.TargetVersion == version {
		t.Fatalf("supersede fixture target=%q source=%q version=%q err=%v", loaded.TargetVersion, source, version, err)
	}
	err = r.Run(Options{})
	if err == nil {
		t.Fatal("expected 3.0.0 health failure to be surfaced")
	}
	if cur, rerr := r.readCurrentVersion(); rerr != nil || cur != "1.0.0" {
		t.Fatalf("current after failed 3.0.0 cut = %q (err %v); want known-good 1.0.0, not unverified 2.0.0: %v", cur, rerr, err)
	}
	for _, c := range fs.calls {
		if c == "health:2.0.0" {
			t.Fatalf("unverified 2.0.0 was treated as a health-confirmed recovery: calls=%v", fs.calls)
		}
	}
}
