package upgrade

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// statusProcess12143 tracks the actual started version separately from the
// current symlink. A symlink flip cannot prove that the new process started.
type statusProcess12143 struct {
	*fakeSystem
	runner   *Runner
	running  string
	starts   []string
	failStop bool
}

func (s *statusProcess12143) StartUnit(unit string) error {
	if err := s.fakeSystem.StartUnit(unit); err != nil {
		return err
	}
	version, err := s.runner.readCurrentVersion()
	if err != nil {
		return err
	}
	s.running = version
	s.starts = append(s.starts, version)
	return nil
}

func (s *statusProcess12143) StopUnit(unit string) error {
	if s.failStop {
		s.failStop = false
		return fmt.Errorf("injected rollback stop failure; %s still running", s.running)
	}
	if err := s.fakeSystem.StopUnit(unit); err != nil {
		return err
	}
	s.running = ""
	return nil
}

func statusProcessEnv12143(t *testing.T, version string) (*Runner, Config, *statusProcess12143) {
	t.Helper()
	r, cfg := testEnv(t, newFakeSystem(t, version))
	s := &statusProcess12143{fakeSystem: r.cfg.Sys.(*fakeSystem), runner: r}
	r.cfg.Sys = s
	r.cfg.Logf = func(string, ...any) {}
	return r, cfg, s
}

func stageStatusVersion12143(t *testing.T, cfg Config, version string) {
	t.Helper()
	for _, bin := range managedBins {
		writeFakeBin(t, filepath.Join(cfg.StagedDir, bin), "binary-"+bin+"-"+version)
	}
}

func cutStatusVersion12143(r *Runner, rolling bool) error {
	if rolling {
		cluster := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
		return runRollingWith(r, cluster, fastRC())
	}
	return r.Run(Options{})
}

func clearStatus12143(t *testing.T, r *Runner, path string, evidence CommittedCut, wantClear bool) {
	t.Helper()
	before := ReadBinaryUpgradeStatus(path)
	if before.ReadErr != nil || !before.Recorded {
		t.Fatalf("pending status before clear = %+v", before)
	}
	cleared, err := r.ClearBinaryUpgradeStatusIfCurrent(path, evidence)
	if err != nil || cleared != wantClear {
		t.Fatalf("clear = %t, err=%v; want clear=%t", cleared, err, wantClear)
	}
	after := ReadBinaryUpgradeStatus(path)
	if after.ReadErr != nil || after.Recorded == wantClear {
		t.Fatalf("status after clear = %+v; want recorded=%t", after, !wantClear)
	}
	if !wantClear && after != before {
		t.Fatalf("retained status changed: before=%+v after=%+v", before, after)
	}
}

func TestUnknownRunningVersionRecutRetainsDeferredStatus12143(t *testing.T) {
	for _, rolling := range []bool{false, true} {
		t.Run(fmt.Sprintf("rolling=%t", rolling), func(t *testing.T) {
			r, cfg, s := statusProcessEnv12143(t, "2.0.0")
			seedInitialCurrent(t, r, cfg, "1.0.0")
			if err := cutStatusVersion12143(r, rolling); err != nil {
				t.Fatalf("initial cut: %v", err)
			}
			stageStatusVersion12143(t, cfg, "3.0.0")
			s.stagedVersion = "2.0.0" // the failed publish left generation 2 current
			path := filepath.Join(t.TempDir(), "upgrade-deferred")
			writePendingVersionStatus12143(t, path, "3.0.0", "unknown")
			if err := cutStatusVersion12143(r, rolling); err != nil {
				t.Fatalf("re-cut current generation: %v", err)
			}
			current, err := r.readCurrentVersion()
			if err != nil || current != "2.0.0" || s.running != "2.0.0" {
				t.Fatalf("current=%q process=%q err=%v; want both to remain 2.0.0", current, s.running, err)
			}
			clearStatus12143(t, r, path, r.LastCommittedCut(), false)
		})
	}
}

func TestFailedHealthRollbackDoesNotSupersedeDeferredStatus12143(t *testing.T) {
	r, cfg, s := statusProcessEnv12143(t, "1.0.0")
	if err := r.Run(Options{AllowNoRollbackFirstCut: true}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	stageStatusVersion12143(t, cfg, "2.0.0")
	s.stagedVersion = "2.0.0"
	publishStagedGen(t, r)
	s.healthFailVersions["2.0.0"] = true
	s.healthHook = func() { s.failStop = true }
	if err := r.Run(Options{}); err == nil {
		t.Fatal("unhealthy cut with failed rollback stop unexpectedly succeeded")
	}
	s.healthHook = nil
	journal, err := r.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if journal.State != StateRollingBack || s.running != "2.0.0" {
		t.Fatalf("journal=%+v process=%q; want failed-health rollback before stop", journal, s.running)
	}

	stageStatusVersion12143(t, cfg, "3.0.0")
	s.stagedVersion = "3.0.0"
	publishStagedGen(t, r)
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("resume rollback: %v", err)
	}
	if s.running != "1.0.0" || slices.Contains(s.starts, "3.0.0") {
		t.Fatalf("rollback process=%q starts=%v; want restore 1.0.0 without starting 3.0.0", s.running, s.starts)
	}
	clearStatus12143(t, r, path, r.LastCommittedCut(), false)
}

func TestFailedHealthOvertakeCannotUseStaleInvocationEvidence12143(t *testing.T) {
	r, cfg, s := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := cutStatusVersion12143(r, true); err != nil {
		t.Fatalf("initial rolling cut: %v", err)
	}
	stageStatusVersion12143(t, cfg, "3.0.0")
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
	if err := cutStatusVersion12143(r, true); err != nil {
		t.Fatalf("invocation A re-cut: %v", err)
	}
	evidenceA := r.LastCommittedCut()

	stageStatusVersion12143(t, cfg, "4.0.0")
	s.stagedVersion = "4.0.0"
	publishStagedGen(t, r)
	b, err := NewRunner(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.runner = b
	s.healthFailVersions["4.0.0"] = true
	if err := cutStatusVersion12143(b, true); err == nil {
		t.Fatal("unhealthy overtaking rolling cut unexpectedly succeeded")
	}
	journal, err := b.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if journal.State != StateFlipped || journal.TargetVersion != "4.0.0" {
		t.Fatalf("unhealthy overtake journal=%+v; want unconfirmed FLIPPED 4.0.0", journal)
	}
	clearStatus12143(t, r, path, evidenceA, false)

	matchingPath := filepath.Join(t.TempDir(), "upgrade-deferred-matching")
	writePendingVersionStatus12143(t, matchingPath, "4.0.0", "2.0.0")
	clearStatus12143(t, r, matchingPath, CommittedCut{}, false)
}

func TestPendingJournalBlocksOlderHealthyClearEvidence12143(t *testing.T) {
	r, cfg, s := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("initial cut: %v", err)
	}
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")

	stageStatusVersion12143(t, cfg, "4.0.0")
	s.stagedVersion = "4.0.0"
	publishStagedGen(t, r)
	if err := r.Run(Options{}); err != nil {
		t.Fatalf("invocation A healthy cut: %v", err)
	}
	evidenceA := r.LastCommittedCut()

	stageStatusVersion12143(t, cfg, "5.0.0")
	s.stagedVersion = "5.0.0"
	publishStagedGen(t, r)
	b, err := NewRunner(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.runner = b
	s.healthFailVersions["5.0.0"] = true
	if err := cutStatusVersion12143(b, true); err == nil {
		t.Fatal("unhealthy overtaking cut unexpectedly succeeded")
	}
	journal, err := b.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if journal.State != StateFlipped || journal.TargetVersion != "5.0.0" {
		t.Fatalf("unhealthy overtake journal=%+v; want unconfirmed FLIPPED 5.0.0", journal)
	}
	if evidenceA.version != "4.0.0" || !evidenceA.healthConfirmed {
		t.Fatalf("invocation A evidence=%+v; want health-confirmed 4.0.0", evidenceA)
	}
	clearStatus12143(t, r, path, evidenceA, false)
}

func TestSupersessionEvidenceRejectsUnknownAndNonNewerVersions12143(t *testing.T) {
	tests := []struct {
		name      string
		staged    string
		version   string
		confirmed bool
	}{
		{name: "unknown staged version", staged: "unknown", version: "5.0.0", confirmed: true},
		{name: "unknown commit version", staged: "3.0.0", version: "unknown", confirmed: true},
		{name: "unconfirmed commit", staged: "3.0.0", version: "5.0.0", confirmed: false},
		{name: "not strictly newer", staged: "3.0.0", version: "3.0.0", confirmed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cfg, _ := statusProcessEnv12143(t, "2.0.0")
			seedInitialCurrent(t, r, cfg, "1.0.0")
			path := filepath.Join(t.TempDir(), "upgrade-deferred")
			writePendingVersionStatus12143(t, path, tt.staged, "unknown")
			evidence := CommittedCut{version: tt.version, healthConfirmed: tt.confirmed}
			clearStatus12143(t, r, path, evidence, false)
		})
	}
}

func TestFailedRollingResultDoesNotExposeCutEvidence12143(t *testing.T) {
	r, cfg, _ := statusProcessEnv12143(t, "2.0.0")
	seedInitialCurrent(t, r, cfg, "1.0.0")
	cluster := &fakeCluster{
		peerAlive:  true,
		synced:     true,
		compatible: true,
		peerReady:  true,
		drainAfter: 1,
		rejoinErr:  fmt.Errorf("injected post-cut rejoin failure"),
	}
	if err := runRollingWith(r, cluster, fastRC()); err == nil {
		t.Fatal("rolling result unexpectedly succeeded without a confirmed rejoin")
	}
	if evidence := r.LastCommittedCut(); evidence.healthConfirmed || evidence.version != "" {
		t.Fatalf("failed rolling result exposed commit evidence %+v", evidence)
	}
}

func TestCompletedRollbackRejectsSavedSupersessionEvidence12143(t *testing.T) {
	for _, sameRunner := range []bool{false, true} {
		for _, statusAfterRollback := range []bool{false, true} {
			t.Run(fmt.Sprintf("same_runner=%t/record_after_rollback=%t", sameRunner, statusAfterRollback), func(t *testing.T) {
				r, cfg, s := statusProcessEnv12143(t, "2.0.0")
				seedInitialCurrent(t, r, cfg, "1.0.0")
				if err := r.Run(Options{}); err != nil {
					t.Fatalf("initial cut: %v", err)
				}
				path := filepath.Join(t.TempDir(), "upgrade-deferred")
				if !statusAfterRollback {
					writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
				}

				stageStatusVersion12143(t, cfg, "4.0.0")
				s.stagedVersion = "4.0.0"
				publishStagedGen(t, r)
				if err := r.Run(Options{}); err != nil {
					t.Fatalf("healthy superseding cut: %v", err)
				}
				evidence := r.LastCommittedCut()
				if !evidence.healthConfirmed || evidence.version != "4.0.0" {
					t.Fatalf("saved evidence = %+v; want health-confirmed 4.0.0", evidence)
				}

				rollbackRunner := r
				if !sameRunner {
					var err error
					rollbackRunner, err = NewRunner(r.cfg)
					if err != nil {
						t.Fatal(err)
					}
					s.runner = rollbackRunner
				}
				if err := rollbackRunner.RollbackTo("2.0.0", RollbackOptions{}); err != nil {
					t.Fatalf("completed rollback: %v", err)
				}
				current, err := r.readCurrentVersion()
				if err != nil || current != "2.0.0" || s.running != "2.0.0" {
					t.Fatalf("after rollback current=%q process=%q err=%v; want 2.0.0", current, s.running, err)
				}
				journal, err := r.loadJournal()
				if err != nil || journal.State != StateInit {
					t.Fatalf("after rollback journal=%+v err=%v; want cleared journal", journal, err)
				}
				if statusAfterRollback {
					writePendingVersionStatus12143(t, path, "3.0.0", "2.0.0")
				}

				// Keep the pre-rollback copy even when the same Runner reset its
				// LastCommittedCut during rollback.
				clearStatus12143(t, r, path, evidence, false)
			})
		}
	}
}

func TestDebianDigitOrderClearDirections12143(t *testing.T) {
	pairs := []struct {
		name  string
		lower string
		upper string
	}{
		{name: "upstream dotted", lower: "1.0.1", upper: "1.0.a"},
		{name: "revision mixed", lower: "1.0-1ubuntu1", upper: "1.0-1ubuntuA"},
		{name: "upstream mixed suffix", lower: "1.0a1", upper: "1.0a.a"},
	}
	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			if output, err := exec.Command("dpkg", "--compare-versions", pair.lower, "lt", pair.upper).CombinedOutput(); err != nil {
				t.Fatalf("dpkg oracle %s < %s: %s %v", pair.lower, pair.upper, output, err)
			}
			for _, newerCut := range []bool{false, true} {
				t.Run(map[bool]string{false: "older-cut-retains", true: "newer-cut-clears"}[newerCut], func(t *testing.T) {
					r, cfg, s := statusProcessEnv12143(t, "0.9")
					seedInitialCurrent(t, r, cfg, "0.8")
					if err := r.Run(Options{}); err != nil {
						t.Fatalf("initial cut: %v", err)
					}
					statusVersion, cutVersion, wantClear := pair.upper, pair.lower, false
					if newerCut {
						statusVersion, cutVersion, wantClear = pair.lower, pair.upper, true
					}
					path := filepath.Join(t.TempDir(), "upgrade-deferred")
					writePendingVersionStatus12143(t, path, statusVersion, "0.9")
					stageStatusVersion12143(t, cfg, cutVersion)
					s.stagedVersion = cutVersion
					publishStagedGen(t, r)
					if err := r.Run(Options{}); err != nil {
						t.Fatalf("real cut to %s: %v", cutVersion, err)
					}
					clearStatus12143(t, r, path, r.LastCommittedCut(), wantClear)
				})
			}
		})
	}
}
