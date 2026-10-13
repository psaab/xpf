// #12615: a STOPPED cut interrupted after FLIP 6a has current -> its
// UNVERIFIED target while the journal still says STOPPED. A newer staged
// version then supersedes it — recovery must restore the journaled known-good
// PreviousVersion before starting the fresh cut.
//
// FAIL-ON-REVERT: removing the STOPPED/current recovery makes the first test
// roll back to unverified 2.0.0. Failing to retry unit restoration when
// current already names PreviousVersion makes the second test start with the
// stale target ExecStart after a crash during the restoration flip.
package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

func seedSupersededStoppedAfter6a12615(t *testing.T, fs *fakeSystem, loadedVersion string) (*Runner, Config) {
	t.Helper()
	r, cfg := testEnv(t, fs) // publishes gen of fs.stagedVersion (2.0.0)
	seedInitialCurrent(t, r, cfg, "1.0.0")

	// Model FLIP 6a completing before interruption: current names 2.0.0 while
	// the durable journal is still STOPPED. systemd may still have either the
	// previous or target ExecStart loaded, depending on how far flip got.
	if err := os.Remove(filepath.Join(cfg.VersionsDir, currentLink)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("2.0.0", filepath.Join(cfg.VersionsDir, currentLink)); err != nil {
		t.Fatal(err)
	}
	fs.baseExecStart = filepath.Join(r.versionDir(loadedVersion), "xpfd")
	fs.loadedExecStart = fakeSystemdExecStart(fs.baseExecStart)
	fs.runningUnitExe = ""
	fs.unitRunning = false
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

	// Publish a newer 3.0.0 package to supersede the stale cut.
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
	return r, cfg
}

func TestCut_SupersededStoppedAfter6a_RollsBackToKnownGood_12615(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := seedSupersededStoppedAfter6a12615(t, fs, "1.0.0")
	fs.healthFailVersions["3.0.0"] = true

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected 3.0.0 health failure to be surfaced")
	}
	if cur, rerr := r.readCurrentVersion(); rerr != nil || cur != "1.0.0" {
		t.Fatalf("current after failed 3.0.0 cut = %q (err %v); want known-good 1.0.0, not unverified 2.0.0: %v", cur, rerr, err)
	}
	for _, c := range fs.calls {
		if c == "health:2.0.0" {
			t.Fatalf("unverified 2.0.0 was treated as health-confirmed recovery: calls=%v", fs.calls)
		}
	}
}

func TestCut_SupersededStoppedRestoreFlipRetryRestoresExecStart_12615(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := seedSupersededStoppedAfter6a12615(t, fs, "2.0.0")
	fs.daemonReloadFailOnce = true

	// First recovery repoints current to 1.0.0, but daemon-reload fails and
	// the STOPPED journal must remain for retry. systemd still has target 2.0.0
	// loaded even though current is already back at the known-good version.
	if err := r.Run(Options{}); err == nil || !strings.Contains(err.Error(), "daemon-reload") {
		t.Fatalf("first recovery error = %v; want daemon-reload failure", err)
	}
	if cur, err := r.readCurrentVersion(); err != nil || cur != "1.0.0" {
		t.Fatalf("current after failed restore flip = %q (%v), want 1.0.0", cur, err)
	}
	j, err := r.loadJournal()
	if err != nil || j.State != StateStopped || j.TargetVersion != "2.0.0" {
		t.Fatalf("journal after failed restore flip = %+v (%v); want STOPPED target 2.0.0", j, err)
	}
	if got := fakeSystemdExecPath(fs.loadedExecStart); got != filepath.Join(r.versionDir("2.0.0"), "xpfd") {
		t.Fatalf("loaded ExecStart after failed restore flip = %q; want unverified target executable", got)
	}

	// On retry, current already names PreviousVersion, so recovery must still
	// notice the stale target ExecStart, reload 1.0.0, then start the unit.
	fs.healthFailVersions["3.0.0"] = true
	retryOffset := len(fs.calls)
	runErr := r.Run(Options{})
	if runErr == nil {
		t.Fatal("expected the superseding 3.0.0 health failure")
	}
	calls := fs.calls[retryOffset:]
	firstReload, firstStart := -1, -1
	for i, call := range calls {
		if call == "daemon-reload" && firstReload == -1 {
			firstReload = i
		}
		if call == "start" && firstStart == -1 {
			firstStart = i
		}
	}
	if firstReload == -1 || firstStart == -1 || firstReload >= firstStart {
		t.Fatalf("retry must reload known-good ExecStart before first unit start: reload=%d start=%d calls=%v",
			firstReload, firstStart, calls)
	}
	if cur, err := r.readCurrentVersion(); err != nil || cur != "1.0.0" {
		t.Fatalf("current after retry = %q (%v), want known-good 1.0.0", cur, err)
	}
	if got := fakeSystemdExecPath(fs.loadedExecStart); got != filepath.Join(r.versionDir("1.0.0"), "xpfd") {
		t.Fatalf("loaded ExecStart after retry = %q; want known-good executable", got)
	}
	if fs.unitRunning && fs.runningUnitExe != filepath.Join(r.versionDir("1.0.0"), "xpfd") {
		t.Fatalf("running unit executable = %q; want known-good executable", fs.runningUnitExe)
	}
	if _, err := os.Stat(cfg.JournalPath); err == nil {
		t.Fatal("journal remains after failed fresh cut rollback")
	}
}
