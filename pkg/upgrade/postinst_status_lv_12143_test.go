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

func TestCorruptStatusGenerationUsesLegacyZeroEvidence12143(t *testing.T) {
	r, cfg, _ := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("healthy cut: %v", err)
	}
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "1.5.0", "1.0.0")
	if err := os.WriteFile(r.statusGenerationPath(), []byte("invalid\\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyEvidence := CommittedCut{version: "2.0.0", healthConfirmed: true}
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, legacyEvidence)
	if err != nil || !cleared {
		t.Fatalf("legacy zero-generation evidence clear=%t err=%v; want version-gated clear", cleared, err)
	}
	if after := ReadBinaryUpgradeStatus(path); after.ReadErr != nil || after.Recorded {
		t.Fatalf("status after legacy clear = %+v; want absent", after)
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
