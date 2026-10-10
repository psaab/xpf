// #12174: a same-version resume from STOPPED FLIPs under a LIVE old daemon
// and the auto-rollback then deletes commits made after it restarted.
//
// The preflight resume gate re-snapshots only below STOPPED, on the rationale
// "From STOPPED onward the daemon is DOWN" (cutover.go:562-603). That is
// unenforced: at >= STOPPED both the STOP and the cut-boundary snapshot are
// skipped (cutover.go:725-754), while nothing verifies the daemon actually
// stayed down across the interruption. If the cut is interrupted after the
// durable STOPPED journal write but before FLIP, and the enabled old unit
// starts again (reboot / postinst restart of an inactive unit after a failed
// cut / operator action), the operator can commit against the live old
// daemon — and does not know a cut is pending, since the upgrade lock is NOT
// held across the interruption. On resume:
//
//   - FLIP runs under the live old daemon (the STOP-before-FLIP structural
//     race closure is bypassed),
//   - START is a no-op because the old daemon is already running
//     (systemctl start on an active unit returns success), so the running
//     binary is still the OLD version,
//   - the production version-bound health gate (HelperHealthProbe wired via
//     NewSystemWithHelperHealth) FAILS because the armed helper executes the
//     old version dir, not the target's, and
//   - the standalone auto-rollback restores the cut-boundary DB snapshot taken
//     at the ORIGINAL stop — silently reverting every commit made after the
//     old daemon restarted.
//
// The resume must either STOP the live old unit plus take a fresh snapshot
// before FLIP, or refuse safely while preserving the post-restart commits.
//
// FAIL-ON-REVERT: omit the STOPPED-resume re-stop or fresh snapshot and
// TestRun_StoppedResumeLiveOldUnitPreservesCommits12174 goes RED — the
// auto-rollback restores the pre-restart snapshot. The two controls stay
// green either way, proving the main cell discriminates the live-unit state.
package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedStoppedSameVersionCut drives a cut to 2.0.0 up to and including STOPPED
// through the Runner's own phase methods (authentic journal + on-disk state),
// with the cut-boundary snapshot taken over boundaryContent. It returns the
// runner/cfg and the config DB file path. The caller models the interruption
// window (old-unit restart + distinguishable commit) before re-running.
func seedStoppedSameVersionCut(t *testing.T, fs *fakeSystem, boundaryContent string) (*Runner, Config, string) {
	t.Helper()
	r, cfg := testEnv(t, fs)
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("first cut: %v", err)
	}

	dbFile := filepath.Join(cfg.ConfigDBDir, "active.json")
	mkfile(t, dbFile, boundaryContent)
	stageSecondCut(t, r, cfg, fs)

	// Drive the second cut to durable STOPPED exactly as Run would: preflight
	// through VERIFY, then STOP + the cut-boundary snapshot + STOPPED journal.
	// (seedCrashState's STOPPED arm skips the cut-boundary snapshot, so the
	// phases are driven explicitly here.)
	prev, err := r.readCurrentVersion()
	if err != nil {
		t.Fatalf("read previous version for stopped journal: %v", err)
	}
	sourceGeneration, err := r.stagedGenConfig().ResolveCurrent()
	if err != nil {
		t.Fatalf("resolve staged generation for stopped journal: %v", err)
	}
	j := &Journal{
		State: StateInit, TargetVersion: fs.stagedVersion,
		PreviousVersion: prev, StartedAtUnixNano: fs.Now().UnixNano(),
		SourceGeneration: sourceGeneration,
	}
	must(t, r.transition(j, StateStaged))
	must(t, r.preflight(j))
	must(t, r.transition(j, StatePreflight))
	must(t, r.copyStaged(j))
	must(t, r.transition(j, StateCopied))
	must(t, r.verify(j))
	must(t, r.transition(j, StateVerified))
	must(t, fs.StopUnit(cfg.Unit))
	must(t, r.snapshotConfigDB(j))
	must(t, r.saveJournal(j))
	must(t, r.transition(j, StateStopped))
	return r, cfg, dbFile
}

// TestRun_StoppedResumeLiveOldUnitPreservesCommits12174 is the issue's
// scenario: interrupted-STOPPED + old-unit-started + distinguishable-commit,
// resumed to the same version.
func TestRun_StoppedResumeLiveOldUnitPreservesCommits12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundaryContent = "#xpf-config-envelope v=1\n{\"gen\":\"cut-boundary-before-restart\"}"
	r, cfg, dbFile := seedStoppedSameVersionCut(t, fs, boundaryContent)

	// THE INTERRUPTION WINDOW. The cut stopped the unit and journaled STOPPED
	// but died before FLIP. The enabled old unit then started again (reboot /
	// postinst restart of an inactive unit / operator action) and the operator
	// committed a distinguishable config against the live old daemon.
	must(t, fs.StartUnit(cfg.Unit))
	const windowContent = "#xpf-config-envelope v=1\n{\"gen\":\"committed-after-old-unit-restart\"}"
	mkfile(t, dbFile, windowContent)

	// StartUnit returns success with unitRunning already true, matching
	// systemd's start-on-active behavior. The version-bound health probe
	// therefore sees the OLD binary unless this resume stops the old unit.
	// After the fix re-stops it, deliberately fail target health anyway so the
	// test observes auto-rollback restoring the FRESH snapshot (not merely a
	// successful cut leaving the live DB untouched).
	resumeStopped := false
	const committedAtStop = "#xpf-config-envelope v=1\n{\"gen\":\"committed-at-resume-stop-boundary\"}"
	fs.stopHook = func() {
		resumeStopped = true
		mkfile(t, dbFile, committedAtStop)
	}
	resumeCallOffset := len(fs.calls)
	fs.healthProbe = func(ver string, _ time.Duration) error {
		if ver == "2.0.0" && !resumeStopped {
			return errors.New("armed helper still executes old unit version")
		}
		if ver == "2.0.0" {
			return errors.New("synthetic target health failure")
		}
		return nil
	}

	// Resume: same staged version, journaled target unchanged.
	runErr := r.Run(Options{})

	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after resume: %v", err)
	}
	if string(got) == boundaryContent {
		t.Fatalf("resumed STOPPED cut with a LIVE old unit rolled the config DB back "+
			"to the PRE-RESTART cut-boundary snapshot, silently discarding commits "+
			"made after the old daemon restarted.\n got=%q\nwant=%q\n"+
			"The resume skipped STOP + fresh snapshot at >= STOPPED (#12174).",
			got, committedAtStop)
	}
	if string(got) != committedAtStop {
		t.Fatalf("auto-rollback did not restore the snapshot taken after STOP.\n got=%q\nwant=%q",
			got, committedAtStop)
	}
	if runErr == nil || !strings.Contains(runErr.Error(), "rolled back") {
		t.Fatalf("resume must reach target health failure and auto-rollback; Run error = %v", runErr)
	}
	current, err := r.readCurrentVersion()
	if err != nil {
		t.Fatalf("read current version after rollback: %v", err)
	}
	if current != "1.0.0" {
		t.Fatalf("auto-rollback current version = %q, want previous 1.0.0", current)
	}
	resumeCalls := fs.calls[resumeCallOffset:]
	resumeStop, resumeFlip := -1, -1
	for i, call := range resumeCalls {
		if call == "stop" && resumeStop < 0 {
			resumeStop = i
		}
		if call == "dropin" && resumeFlip < 0 {
			resumeFlip = i
		}
	}
	if resumeStop < 0 || resumeFlip < 0 || resumeStop >= resumeFlip {
		t.Fatalf("STOP must happen before FLIP on the STOPPED resume; calls=%v", resumeCalls)
	}
}

// TestRun_StoppedResumeUnitStillDownProceeds12174 is the stopped-unit control:
// the same interrupted-STOPPED same-version resume with the unit still down
// must complete the cut exactly as before (the fix must not refuse or disturb
// the already-correct path).
func TestRun_StoppedResumeUnitStillDownProceeds12174(t *testing.T) {
	fs := newFakeSystem(t, "1.0.0")
	const boundaryContent = "#xpf-config-envelope v=1\n{\"gen\":\"cut-boundary-unit-down\"}"
	r, cfg, dbFile := seedStoppedSameVersionCut(t, fs, boundaryContent)

	// Control: the unit stays stopped across the interruption. No commit can
	// land while the daemon is down.
	if fs.unitRunning {
		t.Fatal("seed left the unit running; the stopped-unit control requires it down")
	}

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("resumed STOPPED cut with the unit still down must complete: %v", err)
	}
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "2.0.0" {
		t.Fatalf("current = %q after the stopped-unit resume, want 2.0.0", cur)
	}
	got, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatalf("read config DB after resume: %v", err)
	}
	if string(got) != boundaryContent {
		t.Fatalf("stopped-unit resume changed the config DB: got %q want %q", got, boundaryContent)
	}
}

// TestRun_StoppedResumeDifferentStagedVersionRecovers12174 is the
// different-staged-version control: a superseding version still takes the
// stale-STOPPED recovery branch (restart known-good + fresh cut), unchanged
// by the same-version resume fix.
func TestRun_StoppedResumeDifferentStagedVersionRecovers12174(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg, _ := seedStaleStoppedSupersede(t, fs)

	// The enabled old unit stopped with the stale cut, then restarted during
	// the interruption; recovery's StartUnit must be a harmless active no-op.
	must(t, fs.StopUnit(cfg.Unit))
	must(t, fs.StartUnit(cfg.Unit))

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("stale-STOPPED recovery with a superseding version must proceed: %v", err)
	}
	cur, _ := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if filepath.Base(cur) != "3.0.0" {
		t.Fatalf("current = %q after stale-STOPPED recovery, want 3.0.0 (fresh cut proceeded)", cur)
	}
}
