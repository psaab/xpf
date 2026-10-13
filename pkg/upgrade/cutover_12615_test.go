// #12615: a STOPPED cut interrupted after FLIP 6a has current -> its
// UNVERIFIED target while the journal still says STOPPED. A newer staged
// version then supersedes it — recovery must restore the journaled known-good
// PreviousVersion before starting the fresh cut, without restoring the stale
// cut-boundary DB snapshot and without restarting PreviousVersion on a live DB
// it cannot read.
//
// FAIL-ON-REVERT: removing the STOPPED/current recovery makes the first test
// roll back to unverified 2.0.0. Failing to retry unit restoration when
// current already names PreviousVersion makes the retry test start with the
// stale target ExecStart after a crash during the restoration flip. Dropping
// the PreviousVersion envelope-reader gate before the stop, after the stop, or
// before a plain restart restarts 1.0.0 on a DB only 2.0.0 can read.
package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

const (
	// readerV1DB12615 is an envelope the known-good 1.0.0 (reader 1) wrote.
	readerV1DB12615 = "#xpf-config-envelope v=1 writer=1.0.0 ast=1 min-reader=1 rollback-fmt=1\n"
	// readerV2DB12615 is an envelope the unverified 2.0.0 wrote; 1.0.0 cannot
	// read it.
	readerV2DB12615 = "#xpf-config-envelope v=2 writer=2.0.0 ast=1 min-reader=2 rollback-fmt=1 committed=1\n"
)

// stoppedUnit12615 is the state recovery observes for the superseded STOPPED
// 2.0.0 cut: the version versions/current names, the version whose ExecStart
// systemd has loaded, and the version the unit's MainPID executes ("" means
// the unit is inactive).
type stoppedUnit12615 struct {
	current, loaded, running string
}

// seedSupersededStopped12615 seeds known-good 1.0.0, a STOPPED journal for the
// unverified 2.0.0 cut that recorded a cut-boundary snapshot of DB "A", the
// unit state u, a stale partial, and a newer published 3.0.0 that supersedes
// the stale cut. It returns the runner, its config, and the partial's path.
func seedSupersededStopped12615(t *testing.T, fs *fakeSystem, u stoppedUnit12615) (*Runner, Config, string) {
	t.Helper()
	r, cfg := testEnv(t, fs) // publishes gen of fs.stagedVersion (2.0.0)
	seedInitialCurrent(t, r, cfg, "1.0.0")

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

	// FLIP 6a may have repointed current to 2.0.0 before the interruption, and
	// an earlier recovery may have repointed it back to 1.0.0; systemd may have
	// either version's ExecStart loaded and either version running.
	cur := filepath.Join(cfg.VersionsDir, currentLink)
	if err := os.Remove(cur); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(u.current, cur); err != nil {
		t.Fatal(err)
	}
	fs.baseExecStart = filepath.Join(r.versionDir(u.loaded), "xpfd")
	fs.loadedExecStart = fakeSystemdExecStart(fs.baseExecStart)
	fs.dropinContent = ""
	fs.unitRunning = u.running != ""
	fs.runningUnitExe = ""
	if u.running != "" {
		fs.runningUnitExe = filepath.Join(r.versionDir(u.running), "xpfd")
	}

	snap := filepath.Join(cfg.VersionsDir, ".2.0.0.dbsnap")
	mkfile(t, filepath.Join(snap, "active.json"), readerV1DB12615+`{"gen":"A-stale-cut-boundary"}`)
	jStale := &Journal{TargetVersion: "2.0.0", PreviousVersion: "1.0.0", State: StateStopped,
		SourceGeneration: gOld, DBSnapshotPath: snap, AdvancedStateFloor: true}
	if err := r.saveJournal(jStale); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(cfg.VersionsDir, partialPrefix+"stale-cut"+partialSuffix)
	if err := os.MkdirAll(partial, 0o755); err != nil {
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
	return r, cfg, partial
}

func liveDB12615(t *testing.T, cfg Config) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cfg.ConfigDBDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// assertStaleStoppedPreserved12615 checks a fail-closed recovery: the stale
// STOPPED 2.0.0 journal and partial survive, current still names wantCurrent,
// and none of the forbidden calls ran.
func assertStaleStoppedPreserved12615(t *testing.T, r *Runner, partial, wantCurrent string, calls []string, forbidden ...string) {
	t.Helper()
	if j, err := r.loadJournal(); err != nil || j.State != StateStopped || j.TargetVersion != "2.0.0" {
		t.Errorf("stale journal not preserved: %+v (%v)", j, err)
	}
	if _, err := os.Stat(partial); err != nil {
		t.Errorf("stale partial swept on a fail-closed recovery: %v", err)
	}
	if cur, err := r.readCurrentVersion(); err != nil || cur != wantCurrent {
		t.Errorf("current = %q (%v), want %q", cur, err, wantCurrent)
	}
	for _, c := range calls {
		for _, f := range forbidden {
			if c == f {
				t.Errorf("call %q on a fail-closed recovery: calls=%v", c, calls)
			}
		}
	}
}

func TestCut_SupersededStoppedAfter6a_RollsBackToKnownGood_12615(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _, _ := seedSupersededStopped12615(t, fs, stoppedUnit12615{current: "2.0.0", loaded: "1.0.0"})
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
	r, cfg, _ := seedSupersededStopped12615(t, fs, stoppedUnit12615{current: "2.0.0", loaded: "2.0.0"})
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

// The unverified 2.0.0 ran after FLIP 6a, or after a restore flip failed
// before daemon-reload and the postinst safety net started the still-loaded
// target, and rewrote the live DB in an envelope 1.0.0 cannot read. Recovery
// must refuse before it stops, flips, reloads or starts anything, whichever
// unit state it finds (including a reboot that loaded the restored drop-in).
func TestCut_SupersededStoppedRefusesPreviousOnUnreadableDB_12615(t *testing.T) {
	for _, tc := range []struct {
		name string
		unit stoppedUnit12615
	}{
		{"current-target/target-running", stoppedUnit12615{current: "2.0.0", loaded: "2.0.0", running: "2.0.0"}},
		{"current-target/unit-down", stoppedUnit12615{current: "2.0.0", loaded: "2.0.0"}},
		{"current-previous/target-running", stoppedUnit12615{current: "1.0.0", loaded: "2.0.0", running: "2.0.0"}},
		{"current-previous/target-loaded", stoppedUnit12615{current: "1.0.0", loaded: "2.0.0"}},
		{"current-previous/previous-loaded-after-reboot", stoppedUnit12615{current: "1.0.0", loaded: "1.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			r, cfg, partial := seedSupersededStopped12615(t, fs, tc.unit)
			fs.readerVersionsByDir = map[string]int{"1.0.0": 1}
			db := readerV2DB12615 + `{"gen":"written-by-unverified-2.0.0"}`
			mkfile(t, filepath.Join(cfg.ConfigDBDir, "active.json"), db)
			wasRunning, wasExe := fs.unitRunning, fs.runningUnitExe

			err := r.Run(Options{})
			if err == nil || !strings.Contains(err.Error(), "cannot be proven to read the live config DB") ||
				!strings.Contains(err.Error(), "exceeds target 1.0.0 reader v=1") {
				t.Fatalf("Run error = %v; want the 1.0.0 envelope-reader refusal (calls=%v)", err, fs.calls)
			}
			assertStaleStoppedPreserved12615(t, r, partial, tc.unit.current, fs.calls,
				"stop", "dropin", "daemon-reload", "start")
			if fs.unitRunning != wasRunning || fs.runningUnitExe != wasExe {
				t.Errorf("unit changed on refusal: running=%v exe=%q, want running=%v exe=%q",
					fs.unitRunning, fs.runningUnitExe, wasRunning, wasExe)
			}
			if got := liveDB12615(t, cfg); got != db {
				t.Errorf("live DB rewritten on refusal: %q", got)
			}
		})
	}
}

// A running unverified target can commit an envelope 1.0.0 cannot read while
// it is being stopped, after the pre-stop check passed. Recovery must check
// again once the stop has quiesced it, and refuse before the restore flip.
func TestCut_SupersededStoppedRechecksDBAfterStop_12615(t *testing.T) {
	for _, tc := range []struct {
		name string
		unit stoppedUnit12615
	}{
		{"current-target", stoppedUnit12615{current: "2.0.0", loaded: "2.0.0", running: "2.0.0"}},
		{"current-previous", stoppedUnit12615{current: "1.0.0", loaded: "2.0.0", running: "2.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			r, cfg, partial := seedSupersededStopped12615(t, fs, tc.unit)
			fs.readerVersionsByDir = map[string]int{"1.0.0": 1}
			dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
			mkfile(t, dbFile, readerV1DB12615+`{"gen":"readable-at-pre-stop-check"}`)
			fs.stopHook = func() {
				mkfile(t, dbFile, readerV2DB12615+`{"gen":"final-commit-by-unverified-2.0.0"}`)
			}

			err := r.Run(Options{})
			if err == nil || !strings.Contains(err.Error(), "cannot be proven to read the live config DB") ||
				!strings.Contains(err.Error(), "the unit was stopped and is left down") {
				t.Fatalf("Run error = %v; want the post-stop envelope-reader refusal (calls=%v)", err, fs.calls)
			}
			stops := 0
			for _, c := range fs.calls {
				if c == "stop" {
					stops++
				}
			}
			if stops != 1 {
				t.Errorf("stop calls = %d, want exactly the restore stop: calls=%v", stops, fs.calls)
			}
			assertStaleStoppedPreserved12615(t, r, partial, tc.unit.current, fs.calls,
				"dropin", "daemon-reload", "start")
			if fs.unitRunning {
				t.Errorf("unit restarted after the post-stop refusal: exe=%q", fs.runningUnitExe)
			}
		})
	}
}
