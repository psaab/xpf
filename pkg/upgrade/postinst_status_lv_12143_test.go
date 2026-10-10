package upgrade

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	upgradelock "github.com/psaab/xpf/pkg/upgrade/lock"
)

func TestOlderEvidenceCannotClearFailureAfterAutoRollback12143(t *testing.T) {
	for _, sameRunner := range []bool{false, true} {
		t.Run(map[bool]string{false: "cross-runner", true: "saved-same-runner"}[sameRunner], func(t *testing.T) {
			r, cfg, s := statusProcessEnv12143(t, "2.0.0")
			seedInitialCurrent(t, r, cfg, "1.0.0")
			if err := r.Run(Options{}); err != nil {
				t.Fatalf("initial cut: %v", err)
			}

			stageStatusVersion12143(t, cfg, "4.0.0")
			s.stagedVersion = "4.0.0"
			publishStagedGen(t, r)
			if err := r.Run(Options{}); err != nil {
				t.Fatalf("healthy 4.0.0 cut: %v", err)
			}
			proof := r.LastCommittedCut()

			failedRunner := r
			if !sameRunner {
				var err error
				failedRunner, err = NewRunner(r.cfg)
				if err != nil {
					t.Fatal(err)
				}
				s.runner = failedRunner
			}
			stageStatusVersion12143(t, cfg, "3.0.0")
			s.stagedVersion = "3.0.0"
			publishStagedGen(t, failedRunner)
			s.healthFailVersions["3.0.0"] = true
			if err := failedRunner.Run(Options{}); err == nil {
				t.Fatal("unhealthy 3.0.0 cut succeeded")
			}
			current, currentErr := failedRunner.readCurrentVersion()
			journal, journalErr := failedRunner.loadJournal()
			if currentErr != nil || journalErr != nil || current != "4.0.0" || s.running != "4.0.0" || journal.State != StateInit {
				t.Fatalf("rollback fixture current=%q process=%q journal=%+v errors=%v/%v", current, s.running, journal, currentErr, journalErr)
			}

			path := filepath.Join(t.TempDir(), "upgrade-deferred")
			writePendingVersionStatus12143(t, path, "3.0.0", "4.0.0")
			backdated := time.Unix(1, 0)
			if err := os.Chtimes(path, backdated, backdated); err != nil {
				t.Fatalf("backdate post-failure status: %v", err)
			}
			before := ReadBinaryUpgradeStatus(path)
			cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, proof)
			after := ReadBinaryUpgradeStatus(path)
			if err != nil || cleared || before.ReadErr != nil || !before.Recorded || after != before {
				t.Fatalf("stale evidence cleared a newer post-rollback failure: clear=%t err=%v before=%+v after=%+v", cleared, err, before, after)
			}
		})
	}
}

func TestClearRetainsRealPostinstReplacementWhileLocked12143(t *testing.T) {
	r, cfg, s := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, statusPath, "3.0.0", "2.0.0")
	stageStatusVersion12143(t, cfg, "4.0.0")
	s.stagedVersion = "4.0.0"
	publishStagedGen(t, r)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy 4.0.0 cut: %v", err)
	}
	proof := r.LastCommittedCut()

	if err := syscall.Mkfifo(cfg.JournalPath, 0o600); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(t.TempDir(), "upgrade.lock")
	previousAcquire := acquireUpgradeLock
	acquireUpgradeLock = func(command, target string) (lockHandle, error) {
		return upgradelock.AcquireAt(lockPath, command, target)
	}
	t.Cleanup(func() { acquireUpgradeLock = previousAcquire })

	type clearResult struct {
		cleared bool
		err     error
	}
	done := make(chan clearResult, 1)
	go func() {
		cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(statusPath, proof)
		done <- clearResult{cleared: cleared, err: err}
	}()

	type opened struct {
		file *os.File
		err  error
	}
	writerReady := make(chan opened, 1)
	go func() {
		f, err := os.OpenFile(cfg.JournalPath, os.O_WRONLY, 0)
		writerReady <- opened{file: f, err: err}
	}()
	var writer *os.File
	select {
	case result := <-writerReady:
		if result.err != nil {
			t.Fatal(result.err)
		}
		writer = result.file
	case result := <-done:
		t.Fatalf("clear returned before the journal barrier: %+v", result)
	case <-time.After(10 * time.Second):
		t.Fatal("clear did not reach the journal barrier")
	}
	defer writer.Close()

	competitor, lockErr := upgradelock.AcquireAt(lockPath, "postinst publish", "5.0.0")
	if competitor != nil {
		_ = competitor.Release()
	}
	if !upgradelock.IsBusy(lockErr) {
		t.Fatalf("clear does not hold the real upgrade lock: %v", lockErr)
	}

	script, err := os.ReadFile("../../debian/xpf.postinst")
	if err != nil {
		t.Fatal(err)
	}
	_, functionAndRest, found := strings.Cut(string(script), "record_upgrade_failure() {")
	if !found {
		t.Fatal("missing postinst record_upgrade_failure function")
	}
	functionBody, _, found := strings.Cut(functionAndRest, "write_upgrade_status_unreadable_marker() {")
	if !found {
		t.Fatal("missing postinst status-writer boundary")
	}
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "xpfd"), []byte("#!/bin/sh\nprintf 'xpfd 5.0.0\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "systemctl"), []byte("#!/bin/sh\nprintf '0\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", "-c", "set -eu\nrecord_upgrade_failure() {"+functionBody+"\nrecord_upgrade_failure publish-deferred 'xpfd publish-generation && xpfd upgrade'\n")
	command.Env = append(os.Environ(),
		"STAGED="+tools,
		"XPF_UPGRADE_STATUS="+statusPath,
		"XPF_UPGRADE_STATUS_UNREADABLE="+filepath.Join(tools, "unreadable"),
		"XPF_PROC_DIR="+filepath.Join(tools, "proc"),
		"XPF_VERSIONS_DIR="+cfg.VersionsDir,
		"PATH="+tools+":"+os.Getenv("PATH"),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual postinst writer: %v: %s", err, output)
	}
	installed := ReadBinaryUpgradeStatus(statusPath)
	if !installed.Recorded || installed.StagedVersion != "5.0.0" || installed.Reason != "publish-deferred" {
		t.Fatalf("actual postinst writer did not install the new failure: %+v", installed)
	}

	if _, err := writer.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		after := ReadBinaryUpgradeStatus(statusPath)
		if result.err != nil || result.cleared || after != installed {
			t.Fatalf("clear removed an un-compared postinst record: cleared=%t err=%v installed=%+v after=%+v", result.cleared, result.err, installed, after)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("clear failed to finish after releasing the journal barrier")
	}
}

func TestStatusGenerationReadErrorRetainsDeferredStatus12143(t *testing.T) {
	r, cfg, _ := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy cut: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, statusPath, "1.5.0", "1.0.0")
	before := ReadBinaryUpgradeStatus(statusPath)

	generationPath := r.statusGenerationPath()
	if err := os.Remove(generationPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(generationPath, 0o700); err != nil {
		t.Fatal(err)
	}
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(statusPath, r.LastCommittedCut())
	after := ReadBinaryUpgradeStatus(statusPath)
	if err == nil || cleared || before.ReadErr != nil || after != before {
		t.Fatalf("generation read failure did not retain status: clear=%t err=%v before=%+v after=%+v", cleared, err, before, after)
	}
}

func TestGenerationInvalidEvidenceRetainsDeferredStatus12143(t *testing.T) {
	r, cfg, _ := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy cut: %v", err)
	}
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "1.5.0", "1.0.0")
	// Corrupt the counter: with generation 0 on disk, the pre-fold legacy
	// gate (and a dropped-validity-check mutant) would CLEAR here. The
	// require-validity gate must retain (Opus F2).
	if err := os.WriteFile(r.statusGenerationPath(), []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := ReadBinaryUpgradeStatus(path)
	// Generation-invalid evidence cannot occur in production (the only
	// constructor always carries begin state); the gate must retain
	// rather than honor a legacy zero path (Opus MINOR-3).
	invalidEvidence := CommittedCut{version: "2.0.0", healthConfirmed: true}
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, invalidEvidence)
	after := ReadBinaryUpgradeStatus(path)
	if err != nil || cleared || after != before {
		t.Fatalf("generation-invalid evidence clear=%t err=%v before=%+v after=%+v; want retain",
			cleared, err, before, after)
	}
}

func TestStatusGenerationReadFailureDoesNotFailRun12143(t *testing.T) {
	r, cfg, _ := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := os.Mkdir(r.statusGenerationPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("status-generation bookkeeping failure aborted the cut: %v", err)
	}
	if proof := r.LastCommittedCut(); !proof.healthConfirmed || proof.generationValid {
		t.Fatalf("cut evidence after generation write failure = %+v; want unusable supersession generation", proof)
	}
}

// TestPreflipFailedRunInvalidatesEarlierEvidence12143 pins the Run begin
// advance (cutover.go): a later verify-rejected Run (pure pre-STOP failure,
// no rollback) must invalidate earlier healthy evidence. What this test
// actually kills is the begin-after-verify POSITION mutant (M1b): a full
// begin-removal mutant is masked here by the require-validity gate (all
// evidence invalid → retain) and caught by the digit-order/superseded/read-error
// tests instead.
func TestPreflipFailedRunInvalidatesEarlierEvidence12143(t *testing.T) {
	a, cfg, s := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, a, cfg, "1.0.0")
	if err := a.Run(Options{}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	stageStatusVersion12143(t, cfg, "4.0.0")
	s.stagedVersion = "4.0.0"
	publishStagedGen(t, a)
	if err := a.Run(Options{}); err != nil {
		t.Fatalf("healthy 4.0.0 cut: %v", err)
	}
	proof := a.LastCommittedCut()
	// A later VERIFY-REJECTED Run through a second runner: verify is pure
	// (pre-STOP, no rollback), so only the Run begin advances the fence.
	b, err := NewRunner(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.runner = b
	s.verifyPass = false
	runErr := b.Run(Options{})
	s.verifyPass = true
	if runErr == nil {
		t.Fatal("verify-rejected cut unexpectedly succeeded")
	}
	current, err := b.readCurrentVersion()
	if err != nil || current != "4.0.0" {
		t.Fatalf("current=%q err=%v; want 4.0.0", current, err)
	}
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "4.0.0")
	clearStatus12143(t, a, path, proof, false)
}

// TestRollbackBeginInvalidatesEarlierEvidence12143 pins the RollbackTo begin
// advance (rollback.go): a rollback round-trip away and back must invalidate
// earlier healthy evidence (removing the begin clears here while the rest of
// the suite stays green — verified firsthand).
func TestRollbackBeginInvalidatesEarlierEvidence12143(t *testing.T) {
	r, cfg, s := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	stageStatusVersion12143(t, cfg, "4.0.0")
	s.stagedVersion = "4.0.0"
	publishStagedGen(t, r)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy 4.0.0 cut: %v", err)
	}
	proof := r.LastCommittedCut()
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	// Round-trip away and back to the evidence version: both rollbacks
	// advance the generation, so the earlier proof must not clear.
	if err := r.RollbackTo("2.0.0", RollbackOptions{ClusterCoordinated: true}); err != nil {
		t.Fatalf("rollback away: %v", err)
	}
	if err := r.RollbackTo("4.0.0", RollbackOptions{ClusterCoordinated: true}); err != nil {
		t.Fatalf("rollback back: %v", err)
	}
	current, err := r.readCurrentVersion()
	if err != nil || current != "4.0.0" {
		t.Fatalf("current=%q err=%v; want 4.0.0", current, err)
	}
	clearStatus12143(t, r, path, proof, false)
}

// TestClearQuarantineRaceRetainsNewerRecord12143 is the deterministic
// pin for the quarantine-rename clear: a writer rename landing between the
// quarantine move and the identity decision must NOT be deleted. The hook
// fires at exactly that point (statConfigDBDir pattern), so no timing luck
// is involved. Kills the check-then-unlink shape (T1/T2 mutants).
func TestClearQuarantineRaceRetainsNewerRecord12143(t *testing.T) {
	r, cfg, s := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	stageStatusVersion12143(t, cfg, "4.0.0")
	s.stagedVersion = "4.0.0"
	publishStagedGen(t, r)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy 4.0.0 cut: %v", err)
	}
	proof := r.LastCommittedCut()
	dir := t.TempDir()
	path := filepath.Join(dir, "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	expected := ReadBinaryUpgradeStatus(path)
	if expected.ReadErr != nil || !expected.Recorded {
		t.Fatalf("pending status before clear = %+v", expected)
	}
	// The hook simulates the lockless writer winning the race at the worst
	// instant: after the quarantine move, before the identity decision. A
	// check-then-unlink implementation deletes this 5.0.0 record.
	hooked := false
	previousHook := clearStatusQuarantineHook
	clearStatusQuarantineHook = func() {
		hooked = true
		// Atomic rename like the production postinst writer (temp + rename),
		// not an in-place write: the live name is vacant at this point
		// (quarantined away), so this installs a genuinely newer record.
		tmp, err := os.CreateTemp(dir, "upgrade-deferred.hook.*")
		if err != nil {
			panic(err)
		}
		data := "format=1\nstaged_version=5.0.0\nrunning_version=unknown\nreason=cut-failed\nrecovery=xpfd upgrade\nrecorded_at=2026-10-08T12:00:00Z\n"
		if _, err := tmp.WriteString(data); err != nil {
			panic(err)
		}
		if err := tmp.Close(); err != nil {
			panic(err)
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			panic(err)
		}
	}
	t.Cleanup(func() { clearStatusQuarantineHook = previousHook })
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, proof)
	if err != nil {
		t.Fatalf("clear err: %v", err)
	}
	if !hooked {
		t.Fatal("quarantine hook never fired; test proves nothing")
	}
	after := ReadBinaryUpgradeStatus(path)
	if after.ReadErr != nil || !after.Recorded || after.StagedVersion != "5.0.0" {
		t.Fatalf("quarantine race: after=%+v cleared=%t; want the 5.0.0 record retained",
			after, cleared)
	}
	if cleared {
		t.Fatalf("quarantine race: cleared=true while a newer record landed; want retain")
	}
}

// TestClearPreQuarantineRaceRestoresNewerRecord12143 pins the fstat-match +
// restore window (writer rename between the pinned re-read and the quarantine
// move). The pre-quarantine hook installs a 5.0.0 record at exactly that
// point; the clear must retain it with cleared=false. Kills F0 (match
// removed) and R0 (restore turned into drop), which both ship the suite
// green without this test (Opus MINOR-A).
func TestClearPreQuarantineRaceRestoresNewerRecord12143(t *testing.T) {
	r, cfg, s := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	stageStatusVersion12143(t, cfg, "4.0.0")
	s.stagedVersion = "4.0.0"
	publishStagedGen(t, r)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy 4.0.0 cut: %v", err)
	}
	proof := r.LastCommittedCut()
	dir := t.TempDir()
	path := filepath.Join(dir, "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	expected := ReadBinaryUpgradeStatus(path)
	if expected.ReadErr != nil || !expected.Recorded {
		t.Fatalf("pending status before clear = %+v", expected)
	}
	hooked := false
	previousHook := clearStatusPreQuarantineHook
	clearStatusPreQuarantineHook = func() {
		hooked = true
		tmp, err := os.CreateTemp(dir, "upgrade-deferred.prehook.*")
		if err != nil {
			panic(err)
		}
		data := "format=1\nstaged_version=5.0.0\nrunning_version=unknown\nreason=cut-failed\nrecovery=xpfd upgrade\nrecorded_at=2026-10-08T12:00:00Z\n"
		if _, err := tmp.WriteString(data); err != nil {
			panic(err)
		}
		if err := tmp.Close(); err != nil {
			panic(err)
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			panic(err)
		}
	}
	t.Cleanup(func() { clearStatusPreQuarantineHook = previousHook })
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, proof)
	if err != nil {
		t.Fatalf("clear err: %v", err)
	}
	if !hooked {
		t.Fatal("pre-quarantine hook never fired; test proves nothing")
	}
	after := ReadBinaryUpgradeStatus(path)
	if after.ReadErr != nil || !after.Recorded || after.StagedVersion != "5.0.0" {
		t.Fatalf("pre-quarantine race: after=%+v cleared=%t; want the 5.0.0 record retained",
			after, cleared)
	}
	if cleared {
		t.Fatalf("pre-quarantine race: cleared=true while a newer record landed; want retain")
	}
}

// TestClearRechecksUnreadableMarkerBeforeQuarantine12143 pins the MINOR-B
// re-check: a marker installed between the gate read and the locked re-read
// must fail the clear with the marker error and retain the record. Kills the
// MB0 mutant (re-check deleted). The pre-quarantine hook installs the marker
// at exactly the re-check point, deterministically.
func TestClearRechecksUnreadableMarkerBeforeQuarantine12143(t *testing.T) {
	r, cfg, s := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	stageStatusVersion12143(t, cfg, "4.0.0")
	s.stagedVersion = "4.0.0"
	publishStagedGen(t, r)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy 4.0.0 cut: %v", err)
	}
	proof := r.LastCommittedCut()
	dir := t.TempDir()
	path := filepath.Join(dir, "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	expected := ReadBinaryUpgradeStatus(path)
	if expected.ReadErr != nil || !expected.Recorded {
		t.Fatalf("pending status before clear = %+v", expected)
	}
	marker := filepath.Join(dir, "upgrade-deferred-unreadable")
	previousPath := binaryUpgradeStatusUnreadablePath
	binaryUpgradeStatusUnreadablePath = marker
	t.Cleanup(func() { binaryUpgradeStatusUnreadablePath = previousPath })
	// Install the marker AFTER the expected-read (simulating a writer
	// failure between the gate read and the locked re-read) but BEFORE the
	// clear runs: the re-check inside the clear must observe it.
	if err := os.WriteFile(marker, []byte("unpersisted 5.0.0"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, proof)
	if err == nil || cleared {
		t.Fatalf("marker re-check: cleared=%t err=%v; want (false, marker error)", cleared, err)
	}
	after := ReadBinaryUpgradeStatus(path)
	if after.ReadErr != nil || !after.Recorded || after.StagedVersion != "3.0.0" {
		t.Fatalf("marker re-check: after=%+v; want the 3.0.0 record retained", after)
	}
}
