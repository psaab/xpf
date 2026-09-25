package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

func crashCommitConfirmedAtStage(t *testing.T, s *Store, stage commitConfirmedCrashStage) {
	t.Helper()
	previous := commitConfirmedCrashHook
	commitConfirmedCrashHook = func(current commitConfirmedCrashStage) {
		if current == stage {
			panic(stage)
		}
	}
	defer func() { commitConfirmedCrashHook = previous }()
	crashed := false
	func() {
		defer func() {
			if value := recover(); value != nil {
				if value != stage {
					t.Fatalf("unexpected panic at stage %q: %v", stage, value)
				}
				crashed = true
			}
		}()
		_, _ = s.CommitConfirmed(10)
	}()
	if !crashed {
		t.Fatalf("CommitConfirmed did not reach injected crash stage %q", stage)
	}
}

func TestCommitConfirmedCrashBoundariesRecoverSafely_10696(t *testing.T) {
	stages := []commitConfirmedCrashStage{
		commitConfirmedStageRecord,
		commitConfirmedStageActive,
		commitConfirmedStagePromote,
		commitConfirmedStageJournal,
		commitConfirmedStageHistory,
		commitConfirmedStageArm,
		commitConfirmedStageBind,
	}
	for _, stage := range stages {
		t.Run(string(stage), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			s := newTestStoreAt(t, path)
			commitBaseline(t, s)
			if err := s.SetFromInput("system host-name Base"); err != nil {
				t.Fatalf("SetFromInput baseline: %v", err)
			}
			if _, err := s.Commit(); err != nil {
				t.Fatalf("Commit baseline: %v", err)
			}
			if err := s.SetFromInput("system host-name Candidate"); err != nil {
				t.Fatalf("SetFromInput candidate: %v", err)
			}
			crashCommitConfirmedAtStage(t, s, stage)
			if s.confirmTimer != nil {
				s.confirmTimer.Stop()
			}

			restarted := newTestStoreAt(t, path)
			if err := restarted.Load(); err != nil {
				t.Fatalf("Load after simulated crash: %v", err)
			}
			got := restarted.ActiveConfig()
			if got == nil {
				t.Fatal("recovered active config is nil")
			}
			if stage == commitConfirmedStageRecord {
				if got.System.HostName != "Base" {
					t.Fatalf("record-only crash activated %q; want Base", got.System.HostName)
				}
				if restarted.IsConfirmPending() {
					t.Fatal("a record written before active.json incorrectly armed a window for Base")
				}
				return
			}
			if got.System.HostName != "Candidate" {
				t.Fatalf("active candidate was not recovered after %q boundary: got %q", stage, got.System.HostName)
			}
			if !restarted.IsConfirmPending() {
				t.Fatalf("candidate at %q boundary recovered without a rollback window", stage)
			}
			if restarted.confirmTimer != nil {
				restarted.confirmTimer.Stop()
			}
		})
	}
}

func TestNestedCommitConfirmedCrashBoundariesPreserveRollback_10696(t *testing.T) {
	for _, stage := range []commitConfirmedCrashStage{
		commitConfirmedStageRecord,
		commitConfirmedStageActive,
		commitConfirmedStageBind,
	} {
		t.Run(string(stage), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			s := newTestStoreAt(t, path)
			commitBaseline(t, s)
			if err := s.SetFromInput("system host-name Base"); err != nil {
				t.Fatalf("SetFromInput baseline: %v", err)
			}
			if _, err := s.Commit(); err != nil {
				t.Fatalf("Commit baseline: %v", err)
			}
			if err := s.SetFromInput("system host-name Pending"); err != nil {
				t.Fatalf("SetFromInput pending: %v", err)
			}
			if _, err := s.CommitConfirmed(10); err != nil {
				t.Fatalf("CommitConfirmed first window: %v", err)
			}
			if stage == commitConfirmedStageRecord {
				previous, err := s.db.ReadConfirm()
				if err != nil || previous == nil {
					t.Fatalf("ReadConfirm before expiry setup: rec=%v err=%v", previous, err)
				}
				previous.Deadline = time.Now().Add(-time.Second)
				if err := s.db.WriteConfirm(previous); err != nil {
					t.Fatalf("expire previous record: %v", err)
				}
				s.confirmDeadline = previous.Deadline
			}
			if err := s.SetFromInput("system host-name Nested"); err != nil {
				t.Fatalf("SetFromInput nested: %v", err)
			}
			crashCommitConfirmedAtStage(t, s, stage)
			if s.confirmTimer != nil {
				s.confirmTimer.Stop()
			}

			restarted := newTestStoreAt(t, path)
			if err := restarted.Load(); err != nil {
				t.Fatalf("Load after nested crash: %v", err)
			}
			got := restarted.ActiveConfig()
			if got == nil {
				t.Fatal("recovered active config is nil")
			}
			if stage == commitConfirmedStageRecord {
				if got.System.HostName != "Base" {
					t.Fatalf("expired prior window did not roll back after record-boundary crash: got %q", got.System.HostName)
				}
				if restarted.IsConfirmPending() {
					t.Fatal("expired prior window remained pending after rollback")
				}
				return
			}
			if got.System.HostName != "Nested" {
				t.Fatalf("nested candidate was not active after %q boundary: got %q", stage, got.System.HostName)
			}
			if !restarted.IsConfirmPending() {
				t.Fatalf("nested candidate at %q boundary lost the rollback window", stage)
			}
			if restarted.confirmPrevTree == nil || !strings.Contains(restarted.confirmPrevTree.FormatSet(), "host-name Base") {
				t.Fatalf("nested crash at %q changed the original rollback target", stage)
			}
			if restarted.confirmTimer != nil {
				restarted.confirmTimer.Stop()
			}
		})
	}
}

func TestNestedConfirmBindingFailureRetriesWithoutLosingWindow_10696(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatalf("SetFromInput baseline: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit baseline: %v", err)
	}
	if err := s.SetFromInput("system host-name Pending"); err != nil {
		t.Fatalf("SetFromInput pending: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed first window: %v", err)
	}

	restoreRollbackSeams(t)
	var writes atomic.Int32
	inner := rbWriteFileDurable
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Base(path) == "confirm.json" {
			if writes.Add(1) == 2 {
				return errInjectedConfirmArm
			}
		}
		return inner(path, data, perm, opts...)
	}
	s.SetPersistRetryBackoffForTesting(5*time.Millisecond, 20*time.Millisecond)
	if err := s.SetFromInput("system host-name Nested"); err != nil {
		t.Fatalf("SetFromInput nested: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed nested: %v", err)
	}
	if !s.IsConfirmPending() || !s.ConfigPersistDegraded() {
		t.Fatal("failed binding rewrite must keep the nested window recoverable and degraded until retry")
	}
	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm after binding failure: rec=%v err=%v", rec, err)
	}
	if rec.GuardedHash != guardedConfigHash(s.active) || rec.PreviousHash == "" {
		t.Fatalf("binding failure lost either candidate guard or old-hash alias: %+v", rec)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.ConfigPersistDegraded() {
		time.Sleep(5 * time.Millisecond)
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("binding rewrite retry did not converge")
	}
	rec, err = s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm after binding retry: rec=%v err=%v", rec, err)
	}
	if rec.GuardedHash != guardedConfigHash(s.active) || rec.PreviousHash != "" || !rec.PreviousDeadline.IsZero() {
		t.Fatalf("finalized record retained a temporary previous-generation binding: %+v", rec)
	}
}

func prepareLegacyConfirmRollbackDebt10696(t *testing.T, path string) *Store {
	t.Helper()
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatalf("SetFromInput baseline: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit baseline: %v", err)
	}
	if err := s.SetFromInput("system host-name Pending"); err != nil {
		t.Fatalf("SetFromInput pending: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	legacy, err := s.db.ReadConfirm()
	if err != nil || legacy == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", legacy, err)
	}
	legacy.GuardedHash = ""
	legacy.Deadline = time.Now().Add(-time.Second)
	if err := s.db.WriteConfirm(legacy); err != nil {
		t.Fatalf("write legacy record: %v", err)
	}

	recovering := newTestStoreAt(t, path)
	recovering.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	recovering.SetWriteActiveForTesting(failingWriteActive)
	if err := recovering.Load(); err != nil {
		t.Fatalf("Load with rollback persistence fault: %v", err)
	}
	recovering.mu.Lock()
	rollbackStillOwed := recovering.confirmResolvePendingPersist
	recovering.mu.Unlock()
	if !rollbackStillOwed {
		t.Fatal("expired legacy record did not retain its failed rollback write")
	}
	if got := recovering.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("in-memory rollback target = %q, want Base", got)
	}
	return recovering
}

func TestPendingRollbackLegacyRecordTransitionSurvivesCrash_10696(t *testing.T) {
	for _, stage := range []commitConfirmedCrashStage{
		commitConfirmedStageRecord,
		commitConfirmedStageActive,
	} {
		t.Run(string(stage), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			recovering := prepareLegacyConfirmRollbackDebt10696(t, path)
			recovering.SetWriteActiveForTesting(nil)
			diskActive, err := recovering.db.ReadActive()
			if err != nil || diskActive == nil {
				t.Fatalf("ReadActive before new arm: tree=%v err=%v", diskActive, err)
			}
			if err := recovering.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := recovering.SetFromInput("system host-name Later"); err != nil {
				t.Fatalf("SetFromInput later candidate: %v", err)
			}
			crashCommitConfirmedAtStage(t, recovering, stage)
			record, err := recovering.db.ReadConfirm()
			if err != nil || record == nil {
				t.Fatalf("ReadConfirm after crash: rec=%v err=%v", record, err)
			}
			if record.GuardedHash != guardedConfigHash(recovering.candidate) ||
				record.PreviousHash != guardedConfigHash(diskActive) ||
				!record.Deadline.After(time.Now()) ||
				record.PreviousDeadline.IsZero() || !record.PreviousDeadline.Before(time.Now()) {
				t.Fatalf("legacy rollback was not bound to the old generation with separate deadlines: %+v", record)
			}

			restarted := newTestStoreAt(t, path)
			if err := restarted.Load(); err != nil {
				t.Fatalf("Load after %q crash: %v", stage, err)
			}
			want := "Base"
			if stage == commitConfirmedStageActive {
				want = "Later"
			}
			if got := restarted.ActiveConfig().System.HostName; got != want {
				t.Fatalf("active after %q crash = %q, want %q", stage, got, want)
			}
			if stage == commitConfirmedStageActive {
				if !restarted.IsConfirmPending() {
					t.Fatal("new active candidate lost its fresh rollback window")
				}
				if restarted.confirmPrevTree == nil ||
					!strings.Contains(restarted.confirmPrevTree.FormatSet(), "host-name Base") {
					t.Fatal("recovery changed the new candidate's rollback target")
				}
				if restarted.confirmTimer != nil {
					restarted.confirmTimer.Stop()
				}
			} else if restarted.IsConfirmPending() {
				t.Fatal("expired prior window was extended at the record boundary")
			}
		})
	}
}


func TestPendingRollbackAliasPreservesPriorRecovery_10696(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatalf("SetFromInput baseline: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit baseline: %v", err)
	}
	if err := s.SetFromInput("system host-name Pending"); err != nil {
		t.Fatalf("SetFromInput pending: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed first window: %v", err)
	}
	gen := s.ConfirmGenForTesting()

	if err := s.SetFromInput("system host-name Rejected"); err != nil {
		t.Fatalf("SetFromInput rejected nested candidate: %v", err)
	}
	s.SetWriteActiveForTesting(failingWriteActive)
	if _, err := s.CommitConfirmed(10); err == nil {
		t.Fatal("nested candidate must be rejected when active persistence fails")
	}
	record, err := s.db.ReadConfirm()
	if err != nil || record == nil {
		t.Fatalf("ReadConfirm after rejected nested candidate: rec=%v err=%v", record, err)
	}
	if record.GuardedHash != guardedConfigHash(s.candidate) ||
		record.PreviousHash != guardedConfigHash(s.active) {
		t.Fatalf("rejected nested prewrite did not preserve the candidate and active hashes: %+v", record)
	}

	oldDeadline := time.Now().Add(-time.Second)
	record.PreviousDeadline = oldDeadline
	if err := s.db.WriteConfirm(record); err != nil {
		t.Fatalf("expire previous rollback window: %v", err)
	}
	s.mu.Lock()
	s.confirmDeadline = oldDeadline
	if s.confirmTimer != nil {
		s.confirmTimer.Stop()
	}
	s.mu.Unlock()
	s.InvokeRollbackTimerForTesting(gen)
	if got := s.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("failed rollback target = %q, want Base", got)
	}
	s.mu.Lock()
	rollbackStillOwed := s.confirmResolvePendingPersist
	s.mu.Unlock()
	if !rollbackStillOwed {
		t.Fatal("failed timeout rollback did not retain its persistence debt")
	}
	diskActive, err := s.db.ReadActive()
	if err != nil || diskActive == nil {
		t.Fatalf("ReadActive after failed timeout rollback: tree=%v err=%v", diskActive, err)
	}
	if !strings.Contains(diskActive.FormatSet(), "host-name Pending") {
		t.Fatalf("failed timeout rollback changed on-disk active unexpectedly: %s", diskActive.FormatSet())
	}

	s.SetWriteActiveForTesting(nil)
	if err := s.SetFromInput("system host-name Later"); err != nil {
		t.Fatalf("SetFromInput later candidate: %v", err)
	}
	crashCommitConfirmedAtStage(t, s, commitConfirmedStageRecord)
	record, err = s.db.ReadConfirm()
	if err != nil || record == nil {
		t.Fatalf("ReadConfirm after new provisional record: rec=%v err=%v", record, err)
	}
	if record.GuardedHash != guardedConfigHash(s.candidate) ||
		record.PreviousHash != guardedConfigHash(diskActive) ||
		!record.Deadline.After(time.Now()) ||
		!record.PreviousDeadline.Equal(oldDeadline) {
		t.Fatalf("new arm failed to preserve separate old and candidate deadlines: %+v, old=%v", record, oldDeadline)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load after later pre-active crash: %v", err)
	}
	if got := restarted.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("recovery did not honor the expired old rollback window: got %q, want Base", got)
	}
	if restarted.IsConfirmPending() {
		t.Fatal("recovery extended the expired prior rollback window")
	}
	if restarted.confirmTimer != nil {
		restarted.confirmTimer.Stop()
	}
}

func TestNestedFinalizationFailureRecoversAgainstCandidateDeadline_10696(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatalf("SetFromInput baseline: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit baseline: %v", err)
	}
	if err := s.SetFromInput("system host-name Pending"); err != nil {
		t.Fatalf("SetFromInput pending: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed first window: %v", err)
	}

	oldRecord, err := s.db.ReadConfirm()
	if err != nil || oldRecord == nil {
		t.Fatalf("ReadConfirm before expiry setup: rec=%v err=%v", oldRecord, err)
	}
	oldDeadline := time.Now().Add(-time.Second)
	oldRecord.Deadline = oldDeadline
	if err := s.db.WriteConfirm(oldRecord); err != nil {
		t.Fatalf("expire prior window: %v", err)
	}
	s.mu.Lock()
	s.confirmDeadline = oldDeadline
	if s.confirmTimer != nil {
		s.confirmTimer.Stop()
	}
	s.mu.Unlock()

	restoreRollbackSeams(t)
	var writes atomic.Int32
	inner := rbWriteFileDurable
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Base(path) == "confirm.json" && writes.Add(1) >= 2 {
			return errInjectedConfirmArm
		}
		return inner(path, data, perm, opts...)
	}
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	if err := s.SetFromInput("system host-name Nested"); err != nil {
		t.Fatalf("SetFromInput nested: %v", err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed nested: %v", err)
	}
	if writes.Load() < 2 {
		t.Fatal("final confirm-record write was not faulted")
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("failed finalization did not report degraded persistence")
	}
	if s.confirmTimer != nil {
		s.confirmTimer.Stop()
	}
	record, err := s.db.ReadConfirm()
	if err != nil || record == nil {
		t.Fatalf("ReadConfirm after finalization failure: rec=%v err=%v", record, err)
	}
	if record.GuardedHash != guardedConfigHash(s.active) ||
		record.PreviousHash == "" ||
		!record.Deadline.After(time.Now()) ||
		!record.PreviousDeadline.Equal(oldDeadline) {
		t.Fatalf("provisional record did not bind both generations to their deadlines: %+v", record)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load after finalization failure: %v", err)
	}
	if got := restarted.ActiveConfig().System.HostName; got != "Nested" {
		t.Fatalf("recovery used the expired prior deadline for the active candidate: got %q, want Nested", got)
	}
	if !restarted.IsConfirmPending() {
		t.Fatal("recovery lost the nested candidate's fresh rollback window")
	}
	if restarted.confirmPrevTree == nil ||
		!strings.Contains(restarted.confirmPrevTree.FormatSet(), "host-name Base") {
		t.Fatal("recovery changed the nested candidate's rollback target")
	}
	if restarted.confirmTimer != nil {
		restarted.confirmTimer.Stop()
	}
}
