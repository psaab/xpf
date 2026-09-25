package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

var errInjectedConfirmArm = errors.New("injected confirm.json arm-write failure")

// failConfirmArm fails only confirm.json writes, keeping active-config and
// rollback persistence available so these cells exercise the record boundary.
func failConfirmArm(t *testing.T, fail *atomic.Bool) {
	t.Helper()
	restoreRollbackSeams(t)
	prev := rbWriteFileDurable
	rbWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if fail.Load() && filepath.Base(path) == "confirm.json" {
			return errInjectedConfirmArm
		}
		return prev(path, data, perm, opts...)
	}
}

func TestArmWriteFailureRejectsBeforeActive9014(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	activeBefore := s.ShowActiveSet()
	var activeWrites int
	s.SetWriteActiveForTesting(func(tree *config.ConfigTree) error {
		activeWrites++
		return s.db.WriteActive(tree)
	})

	var fail atomic.Bool
	failConfirmArm(t, &fail)
	fail.Store(true)
	if err := s.SetFromInput("system host-name armfail"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if !s.IsDirty() {
		t.Fatal("fixture did not stage a candidate")
	}
	if _, err := s.CommitConfirmed(5); err == nil {
		t.Fatal("CommitConfirmed succeeded although its pre-promotion recovery record could not be written")
	}
	if activeWrites != 0 {
		t.Fatalf("active config was written %d times after the record write failed; want no active write", activeWrites)
	}
	if got := s.ShowActiveSet(); got != activeBefore {
		t.Fatalf("failed arm changed active config:\nwant %s\ngot %s", activeBefore, got)
	}
	if !s.IsDirty() || !strings.Contains(s.ShowCandidateSet(), "armfail") {
		t.Fatal("rejected commit must leave the candidate staged")
	}
	if s.IsConfirmPending() {
		t.Fatal("rejected commit unexpectedly armed a rollback timer")
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("a rejected initial record write must not leave degraded retry debt")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("failed initial record write left confirm.json: rec=%v err=%v", rec, err)
	}
}

func TestArmCanBeRetriedAfterWriteFaultClears9014(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	var fail atomic.Bool
	failConfirmArm(t, &fail)
	fail.Store(true)
	if err := s.SetFromInput("system host-name armretry"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(5); err == nil {
		t.Fatal("first CommitConfirmed succeeded while the initial record write was failing")
	}
	if !s.IsDirty() || !strings.Contains(s.ShowCandidateSet(), "armretry") {
		t.Fatal("failed first attempt did not preserve its candidate")
	}

	fail.Store(false)
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed after clearing write fault: %v", err)
	}
	if s.IsDirty() || !s.IsConfirmPending() {
		t.Fatal("successful retry did not promote the candidate and arm its window")
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("successful record finalization left persistence degraded")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("successful retry did not persist confirm.json: rec=%v err=%v", rec, err)
	}
}

func TestHealthyArmLeavesNoDebt9014(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	if err := s.SetFromInput("system host-name armclean"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if s.ConfigPersistDegraded() {
		t.Fatal("healthy arm incorrectly reports degraded persistence")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("healthy arm did not write its recovery record: rec=%v err=%v", rec, err)
	}
}
